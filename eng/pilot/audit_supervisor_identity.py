"""Read-only parent/self process objects. No scalar-PID selection, signal or cleanup API."""
import ctypes
import os
from pathlib import Path
import select
from types import SimpleNamespace

import audit_process_fence as process
import audit_cleanup_protocol as protocol

packet=process.packet


class _LinuxPeer:
    def __init__(self,pid,pinned):
        import audit_process_posix as platform
        self.pid,self.pinned,self.platform,self.fd=pid,pinned,platform,None
        before=platform.process_fields(pid);self.birth=before['birth']
        self.fd=os.pidfd_open(pid,0)
        try:
            os.set_inheritable(self.fd,False)
            self.live_identity()
        except BaseException:self.close();raise

    def exited(self):
        packet.require(self.fd is not None and not os.get_inheritable(self.fd))
        watcher=select.poll();watcher.register(self.fd,select.POLLIN)
        return bool(watcher.poll(0))

    def live_identity(self):
        packet.require(not self.exited())
        info=self.platform.process_fields(self.pid)
        packet.require(info['birth']==self.birth and info['state'] not in ('Z','X'))
        actual=(Path('/proc')/str(self.pid)/'exe').stat();expected=os.fstat(self.pinned.fd)
        packet.require((actual.st_dev,actual.st_ino)==(expected.st_dev,expected.st_ino))
        self.pinned.check();packet.require(not self.exited())
        return dict(pid=self.pid,birthKind='linux-proc-start-ticks',birthToken=self.birth,executableSha256=self.pinned.digest)

    def close(self):
        if self.fd is not None:os.close(self.fd);self.fd=None


class _WindowsPeer:
    def __init__(self,pid,pinned):
        import audit_process_windows as platform
        self.api,self.pid,self.pinned=platform,pid,pinned
        self.kernel=ctypes.WinDLL('kernel32',use_last_error=True);self.handle=None
        opened=self.kernel.OpenProcess;opened.argtypes,opened.restype=[platform.U32,platform.BOOL,platform.U32],platform.HANDLE
        self.handle=opened(0x1000|0x100000,False,pid) # Query limited information + synchronize; no termination/write rights.
        packet.require(self.handle)
        try:
            flags=platform.U32();get=self.kernel.GetHandleInformation
            get.argtypes,get.restype=[platform.HANDLE,ctypes.POINTER(platform.U32)],platform.BOOL
            packet.require(get(self.handle,ctypes.byref(flags)) and not flags.value&1)
            self.live_identity()
        except BaseException:self.close();raise

    def exited(self):
        packet.require(self.handle is not None)
        wait=self.kernel.WaitForSingleObject;wait.argtypes,wait.restype=[self.api.HANDLE,self.api.U32],self.api.U32
        value=wait(self.handle,0);packet.require(value in (0,258));return value==0

    def live_identity(self):
        facade=SimpleNamespace(pid=self.pid,_handle=self.handle,poll=lambda:0 if self.exited() else None)
        value=self.api.JobFence.identity(SimpleNamespace(_kernel=self.kernel),facade,self.pinned)
        return dict(pid=value['pid'],birthKind=value['birthKind'],birthToken=value['birthToken'],executableSha256=value['imageSha256'])

    def close(self):
        if self.handle is not None:
            handle,self.handle=self.handle,None;close=self.kernel.CloseHandle
            close.argtypes,close.restype=[self.api.HANDLE],self.api.BOOL;packet.require(close(handle))


class HeldLocalPeer:
    """A retained OS process object for the current process or its actual parent only."""
    def __init__(self,role,pinned,expected):
        packet.require(role in ('self','parent') and type(pinned) is process.PinnedFile)
        protocol._identity(expected)
        self.role,self.pinned,self._peer,self._closed=role,pinned,None,False
        self._caller=os.getpid();self._expected=dict(expected)
        pid=os.getpid() if role=='self' else os.getppid()
        packet.require(expected['pid']==pid and expected['executableSha256']==pinned.digest)
        try:
            self._peer=(_WindowsPeer if os.name=='nt' else _LinuxPeer)(pid,pinned)
            packet.require(self._peer.live_identity()==self._expected)
            self.snapshot()
        except BaseException:self.close();raise

    def snapshot(self):
        packet.require(not self._closed and os.getpid()==self._caller)
        self.pinned.check()
        exited=self._peer.exited()
        if not exited:
            packet.require(self._peer.live_identity()==self._expected)
            if self.role=='parent':packet.require(os.getppid()==self._expected['pid'])
        return dict(schema='fleetory.actual-local-peer-observation.v1',role=self.role,identity=dict(self._expected),
            state='exited' if exited else 'live',heldOsProcessObject=True,nonInheritable=True,
            actualEntryImageAndBirthMatched=True,readOnlyObservation=True,processSignalAuthorized=False,
            cleanupAuthorized=False,supervisorIndependenceVerified=False,controllerDeathCleanupVerified=False)

    def close(self):
        self._closed=True
        if self._peer is not None:self._peer.close()

    def __enter__(self):return self
    def __exit__(self,*_):self.close()


def current_identity(pinned):
    packet.require(type(pinned) is process.PinnedFile)
    peer=(_WindowsPeer if os.name=='nt' else _LinuxPeer)(os.getpid(),pinned)
    try:return peer.live_identity()
    finally:peer.close()


if __name__=='__main__':raise SystemExit('Read-only local peer library; no PID wire input, signal, Docker or cleanup CLI.')
