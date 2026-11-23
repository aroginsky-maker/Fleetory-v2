"""Consumed purpose ledger and one audit-only capture/dispatch slot. No native process API."""
from contextlib import contextmanager
from dataclasses import dataclass
import json
import os
from pathlib import Path
import stat

import audit_archive_input as archive
import audit_use_admission as admission
import fresh_server_pair as packet
import recovery_files as files

MAX_LEDGER = 16384
MAX_RESULT = 262144


def ledger_name(nonce):
    return 'historical-audit-use-' + packet.identity(nonce) + '.json'


def root_identity(directory, root_fd):
    files.ordinary_directory(directory)
    packet.require(directory.resolve(strict=True) == directory)
    if os.name == 'posix':
        held, current = os.fstat(root_fd), directory.stat(follow_symlinks=False)
        packet.require((held.st_dev, held.st_ino) == (current.st_dev, current.st_ino))


def create_ledger(directory, root_fd, name):
    root_identity(directory, root_fd)
    packet.require(files.relative_parts(name) == [name])
    if os.name == 'nt':
        return files.windows_create_new(directory / name)
    packet.require(os.name == 'posix')
    return os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=root_fd)


@dataclass(frozen=True)
class CapturedUse:
    data: bytes
    nonce: str
    archive_sha256: str


class UseSession:
    def __init__(self, directory, root_fd, fd, accepted):
        self._directory, self._root_fd, self._fd, self._accepted = directory, root_fd, fd, accepted
        self._captured = None
        self._record = dict(schema='fleetory.audit-use-ledger.v1', purpose=admission.PURPOSE, nonce=accepted.nonce,
            revision=accepted.revision, planSha256=accepted.plan_sha256, nativePlanSha256=accepted.native_sha256,
            selectionSha256=accepted.selection_sha256, ciEvidenceSha256=accepted.ci_sha256, localEvidenceSha256=accepted.local_sha256,
            status='CLAIMED_CONSUMED', archiveCaptureAttempts=0, dispatchAttempts=0, captureCompleted=False,
            gateOriginAuthenticated=False, existingDataConsentAuthenticated=False, nativeResultAuthenticated=False,
            processSupervisionVerified=False, ownerCleanupVerified=False, rollbackResistanceVerified=False,
            nativeLaunchAuthorized=False, writerAdmissionVerified=False, executionAuthorized=False,
            fullSystemRecoveryVerified=False, phase7Complete=False)
        self._save()
        if os.name == 'posix':
            os.fsync(root_fd)

    def _identity(self):
        packet.require(self._fd is not None)
        root_identity(self._directory, self._root_fd)
        held = os.fstat(self._fd)
        current = (self._directory / ledger_name(self._accepted.nonce)).lstat()
        packet.require(files.regular_single_file(held) and files.regular_single_file(current))
        packet.require((held.st_dev, held.st_ino) == (current.st_dev, current.st_ino))
        if os.name == 'posix':
            packet.require(held.st_uid == os.geteuid() and stat.S_IMODE(held.st_mode) == 0o600)

    def _save(self):
        self._identity()
        data = json.dumps(self._record, sort_keys=True, separators=(',', ':')).encode('utf-8') + b'\n'
        packet.require(0 < len(data) <= MAX_LEDGER)
        os.lseek(self._fd, 0, os.SEEK_SET)
        view = memoryview(data)
        while view:
            count = os.write(self._fd, view)
            packet.require(count > 0)
            view = view[count:]
        os.ftruncate(self._fd, len(data))
        os.fsync(self._fd)
        self._identity()

    def capture(self, trusted_archive_root):
        self._identity()
        packet.require(self._record['archiveCaptureAttempts'] == self._record['dispatchAttempts'] == 0)
        self._record.update(status='CAPTURE_ATTEMPT_CONSUMED', archiveCaptureAttempts=1)
        self._save()  # Durable consumed claim precedes the first archive-open attempt.
        value = archive.capture(trusted_archive_root, self._accepted.selection_bytes, self._accepted.selection_sha256)
        packet.require(value.artifact_sha256 == self._accepted.archive_sha256 and len(value.data) == self._accepted.archive_bytes)
        self._captured = CapturedUse(bytes(value.data), self._accepted.nonce, value.artifact_sha256)
        self._record.update(status='CAPTURED_PRIVATE_NOT_DISPATCHED', captureCompleted=True)
        self._save()
        return self._captured

    def dispatch(self, trusted_callback):
        self._identity()
        packet.require(self._captured is not None and self._record['captureCompleted'] is True and self._record['dispatchAttempts'] == 0)
        packet.require(callable(trusted_callback))
        self._record.update(status='DISPATCH_ATTEMPT_CONSUMED', dispatchAttempts=1)
        self._save()  # Never retry a launch merely because the response was lost.
        result = trusted_callback(self._captured)
        packet.require(type(result) in (bytes, bytearray) and 0 < len(result) <= MAX_RESULT)
        frozen = bytes(result)
        self._record.update(status='DISPATCH_RETURNED_UNVERIFIED', resultSha256=packet.digest(frozen), resultBytes=len(frozen))
        self._save()
        return frozen

    def report(self):
        return dict(self._record)

    def close(self, failed):
        if self._fd is None:
            return
        try:
            if failed:
                self._record['status'] = 'FAILED_CONSUMED'
                self._save()
        finally:
            os.close(self._fd)
            self._fd = None
            self._captured = None


@contextmanager
def transaction(trusted_operator_root, accepted):
    packet.require(type(accepted) is admission.AdmittedUse)
    reference, pin = archive.audit_reference(accepted.selection_bytes, accepted.selection_sha256)
    packet.require((reference.path, reference.bytes, reference.sha256) ==
                   (accepted.archive_path, accepted.archive_bytes, accepted.archive_sha256))
    packet.require(pin == accepted.selection_sha256)
    with files.rooted(Path(trusted_operator_root)) as (directory, root_fd):
        fd = create_ledger(directory, root_fd, ledger_name(accepted.nonce))
        session = None
        try:
            os.set_inheritable(fd, False)
            session = UseSession(directory, root_fd, fd, accepted)
            yield session
        except BaseException:
            if session is None:
                os.close(fd)
            else:
                session.close(True)
            raise
        else:
            session.close(False)


if __name__ == '__main__':
    raise SystemExit('Audit-use transaction is a library; no CLI or native launcher is provided.')
