"""Fixture-only read-only observation of pinned dotnet members of an already owned OS fence."""
import ctypes
import os
from pathlib import Path
import select

import audit_process_fence as process

packet=process.packet
MAX_MEMBERS=256


def pid_list(values):
    packet.require(type(values) is list and 0<len(values)<=MAX_MEMBERS)
    packet.require(all(type(v) is int and 0<v<=0xffffffff for v in values) and len(set(values))==len(values))
    return values


class LinuxChild:
    def __init__(self,pid,pump):
        import audit_process_posix as platform
        self.pid,self.owner,self.pinned=pid,pump.process.pid,pump.command.dotnet
        self.fd=None;self.platform=platform
        info=platform.process_fields(pid)
        self.birth=info['birth'];self.fd=os.pidfd_open(pid,0);os.set_inheritable(self.fd,False)
        try:self.check_alive()
        except BaseException:self.close();raise

    def check_alive(self):
        info=self.platform.process_fields(self.pid)
        packet.require(info['birth']==self.birth and info['group']==info['session']==self.owner and info['state'] not in ('Z','X'))
        actual=(Path('/proc')/str(self.pid)/'exe').stat();expected=os.fstat(self.pinned.fd)
        packet.require((actual.st_dev,actual.st_ino)==(expected.st_dev,expected.st_ino))
        self.pinned.check()
        watcher=select.poll();watcher.register(self.fd,select.POLLIN);packet.require(not watcher.poll(0))

    def exited(self):
        watcher=select.poll();watcher.register(self.fd,select.POLLIN)
        return bool(watcher.poll(0))

    def report(self):
        self.check_alive()
        return dict(pid=self.pid,ownerPid=self.owner,birthKind='linux-proc-start-ticks',birthToken=self.birth,
            imageSha256=self.pinned.digest,ownedPidfd=True,ownedFenceMembershipVerified=True,livePinnedDotnetObserved=True)

    def close(self):
        if self.fd is not None:os.close(self.fd);self.fd=None


def linux_candidates(pump):
    import audit_process_posix as platform
    result=[]
    for index,entry in enumerate(Path('/proc').iterdir()):
        packet.require(index<16384)
        if not entry.name.isascii() or not entry.name.isdecimal():continue
        pid=int(entry.name)
        try:info=platform.process_fields(pid)
        except (FileNotFoundError,ProcessLookupError):continue
        if pid!=pump.process.pid and info['group']==info['session']==pump.process.pid and info['state'] not in ('Z','X'):
            result.append(pid)
    return pid_list(result) if result else []


class WindowsChild:
    def __init__(self,pid,pump):
        import audit_process_windows as platform
        self.api=platform;self.kernel=pump.fence._kernel;self.pid=pid;self.owner=pump.process.pid
        self.pinned=pump.command.dotnet;self.job=pump.fence.handle;self.handle=None
        opened=self.kernel.OpenProcess
        opened.argtypes,opened.restype=[platform.U32,platform.BOOL,platform.U32],platform.HANDLE
        self.handle=opened(0x1000|0x100000,False,pid)
        if not self.handle:raise ProcessLookupError('Owned candidate already exited.')
        try:
            self.birth=self._birth();self.check_alive()
        except BaseException:self.close();raise

    def _birth(self):
        api=self.api;values=(api.U64(),api.U64(),api.U64(),api.U64())
        get=self.kernel.GetProcessTimes;get.argtypes,get.restype=[api.HANDLE]+[ctypes.POINTER(api.U64)]*4,api.BOOL
        packet.require(get(self.handle,*(ctypes.byref(v) for v in values)) and values[0].value>0)
        return str(values[0].value)

    def exited(self):
        wait=self.kernel.WaitForSingleObject;wait.argtypes,wait.restype=[self.api.HANDLE,self.api.U32],self.api.U32
        value=wait(self.handle,0);packet.require(value in (0,258))
        return value==0

    def check_alive(self):
        api=self.api;packet.require(not self.exited() and self._birth()==self.birth)
        member=api.BOOL();test=self.kernel.IsProcessInJob
        test.argtypes,test.restype=[api.HANDLE,api.HANDLE,ctypes.POINTER(api.BOOL)],api.BOOL
        packet.require(test(self.handle,self.job,ctypes.byref(member)) and member.value)
        name=ctypes.create_unicode_buffer(32768);length=api.U32(len(name))
        image=self.kernel.QueryFullProcessImageNameW
        image.argtypes,image.restype=[api.HANDLE,api.U32,ctypes.c_wchar_p,ctypes.POINTER(api.U32)],api.BOOL
        packet.require(image(self.handle,0,name,ctypes.byref(length)) and 0<length.value<len(name))
        packet.require(Path(name.value).resolve(strict=True)==self.pinned.path)
        self.pinned.check()

    def report(self):
        self.check_alive()
        return dict(pid=self.pid,ownerPid=self.owner,birthKind='windows-filetime',birthToken=self.birth,
            imageSha256=self.pinned.digest,ownedProcessHandle=True,ownedFenceMembershipVerified=True,livePinnedDotnetObserved=True)

    def close(self):
        if self.handle is not None:
            close=self.kernel.CloseHandle;close.argtypes,close.restype=[self.api.HANDLE],self.api.BOOL
            handle,self.handle=self.handle,None;packet.require(close(handle))


def windows_candidates(pump):
    import audit_process_windows as api
    class Members(ctypes.Structure):
        _fields_=[('assigned',api.U32),('count',api.U32),('pids',api.SIZE*MAX_MEMBERS)]
    value=Members();query=pump.fence._kernel.QueryInformationJobObject
    query.argtypes,query.restype=[api.HANDLE,ctypes.c_int,ctypes.c_void_p,api.U32,ctypes.c_void_p],api.BOOL
    packet.require(query(pump.fence.handle,3,ctypes.byref(value),ctypes.sizeof(value),None) and
        0<value.count<=value.assigned<=MAX_MEMBERS)
    return [pid for pid in pid_list([int(v) for v in value.pids[:value.count]]) if pid!=pump.process.pid]


def find_dotnet(pump):
    pump.fence.identity(pump.process,pump.command.executable);pump.command.dotnet.check()
    candidates=windows_candidates(pump) if os.name=='nt' else linux_candidates(pump)
    factory=WindowsChild if os.name=='nt' else LinuxChild
    for pid in candidates:
        try:return factory(pid,pump)
        except (ValueError,FileNotFoundError,ProcessLookupError):continue
    return None
