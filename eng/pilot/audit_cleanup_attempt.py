"""Persistent consumed public-sleep attempt. No callback, Docker, signal or deletion API."""
from contextlib import contextmanager
import ctypes
import os
from pathlib import Path
import stat
import time

import audit_cleanup_protocol as protocol
import audit_control_identity as control
from audit_use_transaction import create_ledger

packet,files,C=protocol.packet,control.files,protocol.C
MAX_RECORD=8192


def ledger_name(nonce):
    return 'public-sleep-cleanup-'+packet.identity(nonce)+'.json'


@contextmanager
def _stable_namespace(directory):
    if os.name!='nt':
        yield
        return
    kernel=files.windows_file_api()
    # Hold the existing ordinary directory without write/delete sharing before
    # creating the ledger. No ACL or filesystem permission is changed.
    handle=kernel.CreateFileW(str(directory.path),0x80,1,None,3,0x02200000,None)
    packet.require(handle!=ctypes.c_void_p(-1).value)
    try:
        directory.check()
        yield
    finally:packet.require(kernel.CloseHandle(handle))


class ConsumedAttempt:
    """A checked, retained record, deliberately incapable of dispatching an action."""
    def __init__(self,directory,stream,name,record):
        self._directory,self._stream,self._name=directory,stream,name
        self._pid,self._bytes,self._sealed=os.getpid(),C(record)+b'\n',False
        self._identity=self._file_identity()
        packet.require(0<len(self._bytes)<=MAX_RECORD)

    def _file_identity(self):
        packet.require(self._stream is not None and os.getpid()==self._pid)
        self._directory.check()
        held=os.fstat(self._stream.fileno());current=(self._directory.path/self._name).lstat()
        packet.require(files.regular_single_file(held) and files.regular_single_file(current) and
            (held.st_dev,held.st_ino)==(current.st_dev,current.st_ino) and not os.get_inheritable(self._stream.fileno()))
        if os.name=='posix':
            packet.require(held.st_uid==os.geteuid() and stat.S_IMODE(held.st_mode)==0o600)
        return held.st_dev,held.st_ino

    def _seal(self):
        packet.require(not self._sealed and self._file_identity()==self._identity)
        packet.require(self._stream.write(self._bytes)==len(self._bytes))
        os.fsync(self._stream.fileno())
        if os.name=='posix':os.fsync(self._directory.fd)
        self._sealed=True
        self.check()

    def check(self):
        packet.require(self._sealed and self._file_identity()==self._identity)
        self._stream.seek(0)
        packet.require(self._stream.read(MAX_RECORD+1)==self._bytes)

    def report(self):
        self.check()
        return dict(packet.strict_json(self._bytes,MAX_RECORD),localConsumedRecordFlushed=True)

    def close(self):
        self._stream=None


@contextmanager
def claim(trusted_operator_root,ticket,expected_ticket,create_receipt,resource):
    # Freeze all caller-owned buffers before validating or hashing any of them.
    ticket,create_receipt,resource=(protocol._freeze(v) for v in (ticket,create_receipt,resource))
    value=protocol._ticket(ticket,expected_ticket)
    protocol._receipt(create_receipt,value);protocol._resource(resource,value)
    packet.require(value['createdNs']<=time.time_ns()<value['cleanupExpiresNs'])
    name=ledger_name(value['nonce'])
    record=dict(schema='fleetory.public-sleep-cleanup-attempt.v1',purpose=protocol.PURPOSE,
        nonce=value['nonce'],supervisorNonce=value['supervisorNonce'],status='ATTEMPT_CONSUMED',
        ticketSha256=packet.digest(ticket),createReceiptSha256=packet.digest(create_receipt),resourceAssertionSha256=packet.digest(resource),
        controller=value['controller'],supervisor=value['supervisor'],containerId=value['containerId'],imageId=value['imageId'],
        reservationSha256=value['reservationSha256'],runtimeIntentSha256=value['runtimeIntentSha256'],
        restartReplayRefusedWhileRecordRetained=True,
        externalRollbackResistanceVerified=False,windowsDirectoryAclAuthenticated=False,
        actualProcessIdentityVerified=False,createReceiptOriginAuthenticated=False,cleanupAuthorized=False,
        actualCleanupExecuted=False,independentExpiryEnforcementVerified=False,controllerDeathCleanupVerified=False,
        supervisorDeathCleanupVerified=False,operationalLeaseAuthorized=False,originalInputsRead=False,
        originalPrivatePkiUsed=False,sourceVpsAccessed=False,fullSystemRecoveryVerified=False,phase7Complete=False)
    with control.DirectoryLease(Path(trusted_operator_root)) as directory,_stable_namespace(directory):
        if os.name=='posix':
            info=directory.path.stat(follow_symlinks=False)
            packet.require(info.st_uid==os.geteuid() and stat.S_IMODE(info.st_mode)==0o700)
        fd=create_ledger(directory.path,directory.fd,name)
        attempt=None
        try:
            os.set_inheritable(fd,False)
            with os.fdopen(fd,'r+b',buffering=0) as stream:
                fd=None
                attempt=ConsumedAttempt(directory,stream,name,record)
                attempt._seal()
                yield attempt
                attempt.check()
        finally:
            if attempt is not None:attempt.close()
            if fd is not None:os.close(fd)


if __name__=='__main__':raise SystemExit('Consumed public attempt library only; no root CLI, reset, dispatch or cleanup operation.')
