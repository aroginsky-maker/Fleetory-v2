"""Fixed source/runtime inventory for the payload reservation owner, not approval authority."""
from contextlib import ExitStack
import json
from pathlib import Path

import audit_control_identity as control
import audit_process_fence as process
import fresh_server_pair as packet
import recovery_files as files

SCHEMA = 'fleetory.audit-payload-launch-bundle.v1'
SOURCES = tuple('eng/pilot/' + name + '.py' for name in (
    'audit_archive', 'audit_control_identity', 'audit_launch_bundle', 'audit_payload_binding',
    'audit_payload_launch', 'audit_payload_owner', 'audit_process_fence', 'audit_process_posix',
    'audit_process_windows', 'fresh_server_pair', 'recovery_files'))
MAX_MANIFEST = 8192


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode('ascii')


def measure(trusted_repository, trusted_python, nonce, revision):
    """Trusted-host preparation only. A measured hash does not authenticate its origin."""
    packet.identity(nonce)
    root = Path(trusted_repository).resolve(strict=True)
    values = {}
    with files.rooted(root) as (directory, fd):
        for name in SOURCES:
            values[name] = files.inspect_file(directory, fd, name, 512 * 1024)[0]
    runtime = Path(trusted_python).resolve(strict=True)
    with control.DirectoryLease(runtime.parent) as parent:
        runtime_hash = files.inspect_file(parent.path, parent.fd, runtime.name, 64 * 1024 * 1024)[0]
    value = dict(schema=SCHEMA, nonce=nonce, revision=revision, pythonSha256=runtime_hash, sources=values)
    frozen = canonical(value)
    admit(frozen, packet.digest(frozen))
    return frozen


def admit(data, expected):
    packet.hex_value(expected)
    packet.require(type(data) in (bytes, bytearray) and 0 < len(data) <= MAX_MANIFEST)
    frozen = bytes(data)
    packet.require(packet.digest(frozen) == expected)
    value = packet.strict_json(frozen, MAX_MANIFEST)
    packet.keys(value, 'schema nonce revision pythonSha256 sources')
    packet.require(value['schema'] == SCHEMA)
    packet.identity(value['nonce'])
    packet.require(type(value['revision']) is str and len(value['revision']) == 40)
    packet.hex_value(value['revision'] + '0' * 24)
    packet.hex_value(value['pythonSha256'])
    packet.require(type(value['sources']) is dict and set(value['sources']) == set(SOURCES))
    for digest in value['sources'].values():
        packet.hex_value(digest)
    return value


class HeldBundle:
    def __init__(self, repository, python, data, expected, session):
        value = admit(data, expected)
        session.check()
        packet.require(value['nonce'] == session._plan['nonce'] and value['revision'] == session._plan['revision'])
        packet.require(expected == session._plan['codeSha256'] and value['pythonSha256'] == session._plan['runtimes']['python'])
        self.repository, self.digest = Path(repository).resolve(strict=True), expected
        self._held = ExitStack()
        try:
            self.root = self._held.enter_context(control.DirectoryLease(self.repository))
            self.python = self._held.enter_context(process.PinnedFile(python, value['pythonSha256'], True))
            self.sources = {}
            for name in SOURCES:
                path = self.repository / name
                packet.require(files.regular_single_file(path.lstat()))
                held = self._held.enter_context(process.PinnedFile(path, value['sources'][name]))
                packet.require(held.path == path and held.state[2] <= 512 * 1024)
                self.sources[name] = held
            self.check()
        except BaseException:
            self.close()
            raise

    def check(self):
        self.root.check()
        self.python.check()
        for held in self.sources.values():
            held.check()

    def close(self):
        self._held.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
