"""Held control-directory identity and consumed immutable metadata, not a launcher."""
from contextlib import ExitStack, contextmanager
import ctypes
import json
import os
from pathlib import Path
import re
import stat
import time
import uuid

import fresh_server_pair as packet
import recovery_files as files

SCHEMA = 'fleetory.audit-control-plan.v1'
PURPOSE = 'historical-audit-control-identity.v1'
MAX_RECORD = 8192


def admit(data, expected):
    packet.hex_value(expected)
    packet.require(type(data) in (bytes, bytearray) and 0 < len(data) <= MAX_RECORD)
    frozen = bytes(data)
    packet.require(packet.digest(frozen) == expected)
    value = packet.strict_json(frozen, MAX_RECORD)
    packet.keys(value, 'schema purpose nonce revision nativePlanSha256 codeSha256 probeSha256 runtimes')
    packet.require(value['schema'] == SCHEMA and value['purpose'] == PURPOSE)
    packet.identity(value['nonce'])
    packet.require(type(value['revision']) is str and re.fullmatch('[a-f0-9]{40}', value['revision']))
    for name in ('nativePlanSha256', 'codeSha256', 'probeSha256'):
        packet.hex_value(value[name])
    packet.keys(value['runtimes'], 'python powershell')
    for pin in value['runtimes'].values():
        packet.hex_value(pin)
    return value, frozen


class WindowsDirectory:
    """Non-inheritable directory handle; identities use volume plus FILE_ID_128."""
    def __init__(self, path):
        from ctypes import wintypes
        self._kernel = files.windows_file_api()
        create = self._kernel.CreateFileW
        self._close = self._kernel.CloseHandle
        # READ_ATTRIBUTES; read/write/delete sharing permits identity-change tests.
        # BACKUP_SEMANTICS opens directories; OPEN_REPARSE_POINT prevents leaf traversal.
        self._handle = create(str(path), 0x80, 7, None, 3, 0x02200000, None)
        if self._handle == ctypes.c_void_p(-1).value:
            self._handle = None
            raise OSError('Control directory cannot be held.')
        try:
            info = self._kernel.GetFileInformationByHandleEx
            info.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
            info.restype = wintypes.BOOL
            self._info = info
            attributes = (ctypes.c_uint32 * 2)()
            packet.require(info(self._handle, 9, attributes, ctypes.sizeof(attributes)))
            packet.require(attributes[0] & 0x10 and not attributes[0] & 0x400)
            self.identity = self.identity_now()
            final = self._kernel.GetFinalPathNameByHandleW
            name = ctypes.create_unicode_buffer(32768)
            length = final(self._handle, name, len(name), 0)
            packet.require(0 < length < len(name) and name.value.startswith('\\\\?\\'))
            packet.require(os.path.normcase(name.value[4:]) == os.path.normcase(str(path)))
        except BaseException:
            self.close()
            raise

    def identity_now(self):
        from ctypes import wintypes
        packet.require(self._handle is not None)
        identifier = ctypes.create_string_buffer(24)
        packet.require(self._info(self._handle, 18, identifier, 24))
        inherited = wintypes.DWORD()
        get_flags = self._kernel.GetHandleInformation
        get_flags.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        get_flags.restype = wintypes.BOOL
        packet.require(get_flags(self._handle, ctypes.byref(inherited)) and not inherited.value & 1)
        return bytes(identifier)

    def close(self):
        if self._handle is not None:
            handle, self._handle = self._handle, None
            self._close(handle)


class DirectoryLease:
    def __init__(self, path):
        self.path = Path(path).absolute()
        self.fd, self.windows = None, None
        try:
            for ancestor in reversed([self.path, *self.path.parents]):
                files.ordinary_directory(ancestor)
            if os.name == 'nt':
                self.path = files.windows_long_root(self.path)
                self._ordinary()
                self.windows = WindowsDirectory(self.path)
                self.identity = self.windows.identity
            else:
                packet.require(os.name == 'posix')
                self._ordinary()
                self.fd = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                os.set_inheritable(self.fd, False)
                held = os.fstat(self.fd)
                self.identity = held.st_dev, held.st_ino
            self.check()
        except BaseException:
            self.close()
            raise

    def _ordinary(self):
        for ancestor in reversed([self.path, *self.path.parents]):
            files.ordinary_directory(ancestor)
        packet.require(self.path.resolve(strict=True) == self.path)

    def check(self):
        self._ordinary()
        if os.name == 'nt':
            packet.require(self.windows is not None and self.windows._handle is not None)
            packet.require(self.windows.identity_now() == self.identity)
            current = WindowsDirectory(self.path)
            try:
                packet.require(current.identity == self.identity)
            finally:
                current.close()
        else:
            packet.require(self.fd is not None)
            held, current = os.fstat(self.fd), self.path.stat(follow_symlinks=False)
            packet.require(stat.S_ISDIR(held.st_mode) and not os.get_inheritable(self.fd))
            packet.require((held.st_dev, held.st_ino) == self.identity == (current.st_dev, current.st_ino))

    def close(self):
        if self.windows is not None:
            self.windows.close()
            self.windows = None
        if self.fd is not None:
            fd, self.fd = self.fd, None
            os.close(fd)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def namespace_name(nonce):
    packet.identity(nonce)
    return 'audit-control-' + str(uuid.UUID(nonce))


class ControlIdentity:
    def __init__(self, parent, directory, plan, plan_bytes):
        self._parent, self._directory = parent, directory
        self._plan, self._plan_bytes = plan, plan_bytes
        self._records = {}
        self._binding_attempted = False
        self._launch_attempted = False
        self._metadata_attempts = set()
        self._closed = False
        self._created = time.time_ns()

    def _reserve(self):
        plan = self._plan
        self._write_once('reservation.json', dict(schema='fleetory.audit-control-reservation.v1',
            purpose=PURPOSE, nonce=plan['nonce'], revision=plan['revision'], planSha256=packet.digest(self._plan_bytes),
            nativePlanSha256=plan['nativePlanSha256'], codeSha256=plan['codeSha256'], probeSha256=plan['probeSha256'],
            runtimes=plan['runtimes'], supervisorPid=os.getpid(), createdNs=self._created))

    def _directories(self):
        packet.require(not self._closed)
        self._parent.check()
        self._directory.check()
        packet.require(self._directory.path.parent == self._parent.path and
                       self._directory.path.name == namespace_name(self._plan['nonce']))

    def check(self):
        self._directories()
        for name, (fd, expected) in self._records.items():
            current = (self._directory.path / name).lstat()
            held = os.fstat(fd)
            packet.require(files.regular_single_file(held) and files.regular_single_file(current))
            packet.require((held.st_dev, held.st_ino) == (current.st_dev, current.st_ino))
            packet.require(not os.get_inheritable(fd) and held.st_size == len(expected))
            if os.name == 'posix':
                packet.require(held.st_uid == os.geteuid() and stat.S_IMODE(held.st_mode) == 0o600)
            os.lseek(fd, 0, os.SEEK_SET)
            packet.require(os.read(fd, MAX_RECORD + 1) == expected)

    def _write_once(self, name, value):
        self.check()
        packet.require(name in ('reservation.json', 'binding.json', 'launch-attempt.json',
            'payload-binding.json', 'payload-release.json', 'backend-attempt.json', 'backend-intent.json',
            'backend-binding-attempt.json', 'backend-binding.json', 'image-attempt.json', 'image-intent.json',
            'image-binding-attempt.json', 'image-binding.json', 'native-ready.json', 'native-close.json',
            'native-payload-intent.json', 'native-resource-intent.json', 'native-resource-ack.json') and name not in self._records)
        data = json.dumps(value, sort_keys=True, separators=(',', ':')).encode() + b'\n'
        packet.require(0 < len(data) <= MAX_RECORD)
        if os.name == 'nt':
            fd = files.windows_create_new(self._directory.path / name)
        else:
            fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=self._directory.fd)
        self._records[name] = (fd, data)  # A failed write remains consumed and cannot be retried.
        os.set_inheritable(fd, False)
        self._directories()
        view = memoryview(data)
        while view:
            count = os.write(fd, view)
            packet.require(0 < count <= len(view))
            view = view[count:]
        os.fsync(fd)
        if os.name == 'posix':
            os.fsync(self._directory.fd)
        self.check()

    def consume_launch_attempt(self):
        self.check()
        packet.require(not self._launch_attempted and not self._binding_attempted)
        self._launch_attempted = True
        self._write_once('launch-attempt.json', dict(schema='fleetory.audit-control-launch-attempt.v1',
            nonce=self._plan['nonce'], reservationSha256=packet.digest(self._records['reservation.json'][1]),
            status='ATTEMPT_CONSUMED', launchAuthorized=False))
        return self.report()

    def consume_backend_attempt(self):
        self._consume_metadata_attempt('backend')

    def consume_image_attempt(self):
        self._consume_metadata_attempt('image')

    def _consume_metadata_attempt(self, kind):
        self.check()
        packet.require(kind in ('backend', 'image') and kind not in self._metadata_attempts)
        self._metadata_attempts.add(kind)
        self._write_once(kind + '-attempt.json', dict(schema='fleetory.audit-' + kind + '-attempt.v1',
            nonce=self._plan['nonce'], reservationSha256=packet.digest(self._records['reservation.json'][1]),
            status='ATTEMPT_CONSUMED', backendCreationAuthorized=False, cleanupAuthorized=False))

    def bind_assertion(self, pid, started_ns, runtime_pin):
        self.check()
        packet.require(not self._binding_attempted)
        self._binding_attempted = True
        packet.require(type(pid) is int and 1 < pid < 2**31 and type(started_ns) is int)
        packet.require(self._created <= started_ns <= time.time_ns() + 5_000_000_000)
        packet.hex_value(runtime_pin)
        packet.require(runtime_pin == self._plan['runtimes']['powershell'])
        self._write_once('binding.json', dict(schema='fleetory.audit-control-binding.v1',
            nonce=self._plan['nonce'], reservationSha256=packet.digest(self._records['reservation.json'][1]),
            assertedChildPid=pid, assertedStartNs=started_ns, runtimeSha256=runtime_pin,
            processIdentityAuthenticated=False, launchAuthorized=False, cleanupAuthorized=False))
        return self.report()

    def report(self):
        self.check()
        return dict(schema='fleetory.audit-control-identity.v1', nonce=self._plan['nonce'],
            reservationSha256=packet.digest(self._records['reservation.json'][1]),
            bindingSha256=packet.digest(self._records['binding.json'][1]) if 'binding.json' in self._records else None,
            launchAttemptConsumed=self._launch_attempted,
            directoryHandlesHeld=True, recordHandlesHeld=True, nonceConsumed=True,
            processIdentityAuthenticated=False, runtimeContinuityVerified=False, launchAuthorized=False,
            backendNamespaceBound=False, processSupervisionVerified=False, cleanupAuthorized=False,
            originalInputsRead=False, originalPrivatePkiUsed=False, fullSystemRecoveryVerified=False, phase7Complete=False)

    def close(self):
        self._closed = True
        records = tuple(self._records.values())
        self._records.clear()
        with ExitStack() as closing:
            closing.callback(self._parent.close)
            closing.callback(self._directory.close)
            for fd, _ in records:
                closing.callback(os.close, fd)


@contextmanager
def claim(trusted_control_root, plan_bytes, expected_pin):
    plan, frozen = admit(plan_bytes, expected_pin)
    parent = DirectoryLease(trusted_control_root)
    directory = None
    try:
        name = namespace_name(plan['nonce'])
        parent.check()
        if os.name == 'nt':
            os.mkdir(parent.path / name, mode=0o700)
        else:
            os.mkdir(name, mode=0o700, dir_fd=parent.fd)
            os.fsync(parent.fd)
        parent.check()
        directory = DirectoryLease(parent.path / name)
        session = ControlIdentity(parent, directory, plan, frozen)
        try:
            session._reserve()
            yield session
        finally:
            session.close()
    finally:
        if directory is not None:
            directory.close()
        parent.close()


if __name__ == '__main__':
    raise SystemExit('Control identity is a library; no launcher, backend, cleanup or original-file CLI is provided.')
