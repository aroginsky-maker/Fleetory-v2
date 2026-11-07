"""Held payload/marker identities tied to a control session; no backend cleanup API."""
from contextlib import ExitStack
import ctypes
import os
from pathlib import Path

import audit_control_identity as control
import audit_launch_bundle as bundle
import audit_process_fence as process
import fresh_server_pair as packet
import recovery_files as files

MARKER = 'controller-owner.json'
MAX_FRAME = 4096


def directory_hash(lease):
    lease.check()
    value = lease.windows.identity if os.name == 'nt' else (str(lease.identity[0]) + ':' + str(lease.identity[1])).encode('ascii')
    return packet.digest(value)


def payload_name(nonce):
    packet.identity(nonce)
    return 'native-audit-controller-' + nonce


def header(data, expected):
    packet.require(type(data) is bytes and 0 < len(data) <= MAX_FRAME and packet.digest(data) == expected)
    value = packet.strict_json(data, MAX_FRAME)
    packet.keys(value, 'schema nonce controlSha256 controlDirectorySha256 bundleSha256')
    packet.require(value['schema'] == 'fleetory.audit-payload-reservation.v1')
    packet.identity(value['nonce'])
    for name in ('controlSha256', 'controlDirectorySha256', 'bundleSha256'):
        packet.hex_value(value[name])
    return value


def read_frame(stream):
    data = stream.readline(MAX_FRAME + 1)
    packet.require(0 < len(data) <= MAX_FRAME and data.endswith(b'\n'))
    return data[:-1]


def marker(value, pid, directory):
    return dict(schema='fleetory.audit-payload-owner.v1', nonce=value['nonce'], controlSha256=value['controlSha256'],
        controlDirectorySha256=value['controlDirectorySha256'], bundleSha256=value['bundleSha256'],
        ownerPid=pid, payloadDirectorySha256=directory)


def _create_record(directory, data):
    fd = files.windows_create_new(directory.path / MARKER) if os.name == 'nt' else os.open(
        MARKER, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory.fd)
    try:
        view = memoryview(data)
        while view:
            count = os.write(fd, view)
            packet.require(0 < count <= len(view))
            view = view[count:]
        os.fsync(fd)
    finally:
        os.close(fd)
    if os.name == 'posix':
        os.fsync(directory.fd)


class OwnedPayload:
    """Child claims its own fresh directory. Failures preserve the unknown outcome."""
    def __init__(self, repository, value):
        self.value, self._held = value, ExitStack()
        self.parent, self.directory, self.pin = None, None, None
        try:
            self.parent = self._held.enter_context(control.DirectoryLease(Path(repository) / 'artifacts'))
            self.path = self.parent.path / payload_name(value['nonce'])
            if os.name == 'nt':
                os.mkdir(self.path, mode=0o700)
            else:
                os.mkdir(self.path.name, mode=0o700, dir_fd=self.parent.fd)
                os.fsync(self.parent.fd)
            self.parent.check()
            self.directory = self._held.enter_context(control.DirectoryLease(self.path))
            self.directory_sha = directory_hash(self.directory)
            self.record = bundle.canonical(marker(value, os.getpid(), self.directory_sha))
            self.record_sha = packet.digest(self.record)
            _create_record(self.directory, self.record)
            self.pin = self._held.enter_context(process.PinnedFile(self.path / MARKER, self.record_sha))
        except BaseException:
            self.close()
            raise

    def check(self):
        self.parent.check()
        self.directory.check()
        self.pin.check()

    def remove(self):
        self.check()
        packet.require(set(os.listdir(self.path)) == {MARKER})
        self.pin.close()
        if os.name == 'nt':
            os.unlink(self.path / MARKER)
            self.directory.check()
            os.rmdir(self.path)
        else:
            os.unlink(MARKER, dir_fd=self.directory.fd)
            self.directory.check()
            os.rmdir(self.path.name, dir_fd=self.parent.fd)
            os.fsync(self.parent.fd)

    def close(self):
        self._held.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


class BoundPayload:
    def __init__(self, command, session, process_handle, fence, ready, value):
        self.command, self.session, self.process, self.fence = command, session, process_handle, fence
        self._held, self.pin, self.directory = ExitStack(), None, None
        self.released = False
        try:
            observed = self.owner_identity()
            self.parent = self._held.enter_context(control.DirectoryLease(command.directory / 'artifacts'))
            self.path = self.parent.path / payload_name(value['nonce'])
            self.directory = self._held.enter_context(control.DirectoryLease(self.path))
            packet.require(directory_hash(self.directory) == ready['payloadDirectorySha256'])
            self.pin = self._held.enter_context(process.PinnedFile(self.path / MARKER, ready['ownerSha256']))
            expected = bundle.canonical(marker(value, observed['pid'], ready['payloadDirectorySha256']))
            packet.require(self.pin.digest == packet.digest(expected))
            packet.require(value['controlDirectorySha256'] == directory_hash(session._directory))
            session._write_once('payload-binding.json', dict(schema='fleetory.audit-payload-binding.v1',
                nonce=value['nonce'], reservationSha256=value['controlSha256'], bundleSha256=value['bundleSha256'],
                controlDirectorySha256=value['controlDirectorySha256'], ownerSha256=ready['ownerSha256'],
                payloadDirectorySha256=ready['payloadDirectorySha256'], actualOwnedProcess=observed,
                payloadNamespaceBound=True, backendNamespaceBound=False, cleanupAuthorized=False))
            self.check()
        except BaseException:
            self.close()
            raise

    def owner_identity(self):
        self.command.check()
        self.session.check()
        return self.fence.identity(self.process, self.command.executable)

    def check(self):
        packet.require(not self.released)
        self.owner_identity()
        self.parent.check()
        self.directory.check()
        self.pin.check()

    def release(self):
        self.check()
        digest = packet.digest(self.session._records['payload-binding.json'][1])
        self.session._write_once('payload-release.json', dict(schema='fleetory.audit-payload-release.v1',
            nonce=self.session._plan['nonce'], payloadBindingSha256=digest, backendCleanupAuthorized=False))
        self.pin.close()
        self.released = True
        return packet.digest(self.session._records['payload-release.json'][1])

    def verify_removed(self):
        packet.require(self.released)
        self.parent.check()
        if os.name == 'nt':
            info = ctypes.create_string_buffer(24)
            held = self.directory.windows
            packet.require(held._info(held._handle, 1, info, 24) and info.raw[20] == 1)
        else:
            packet.require(os.fstat(self.directory.fd).st_nlink == 0)
        self.directory.close()
        try:
            self.path.lstat()
        except FileNotFoundError:
            return
        raise ValueError('Payload absence unverified.')

    def close(self):
        self._held.close()
