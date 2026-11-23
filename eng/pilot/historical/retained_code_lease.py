"""Held reviewed public source set; no data reader, native command or permission API."""
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
import os
from pathlib import Path
import re
import threading
import weakref

import audit_native_preparation as prep

packet, control, files = prep.packet, prep.control, prep.files
SCHEMA = 'fleetory.retained-code-lease-plan.v1'
MAX_PLAN, MAX_FILE, MAX_TOTAL, MAX_FILES = 131072, 1048576, 8388608, 448
EXTENSIONS = frozenset(('.cs', '.csproj', '.ps1', '.py', '.sql', '.json', '.props', '.targets', '.js', '.sh', '.toml'))
_LIVE = weakref.WeakKeyDictionary()


@dataclass(frozen=True)
class CodeReference:
    path: str
    size: int
    sha256: str


def _name(value):
    packet.require(type(value) is str and 0 < len(value) <= 240)
    if value in prep.ROOTS:
        return value
    packet.require(re.fullmatch(r'(?:eng|src|tests/Fleetory\.Tools\.Tests)/[A-Za-z0-9_./-]+', value)
                   and not any(part in ('', '.', '..') for part in value.split('/'))
                   and (Path(value).suffix in EXTENSIONS or Path(value).name == '.gitattributes'))
    # Match the actual held-file reader before emitting a plan. Namespace-only
    # directories need no __init__.py; unsupported basenames must fail preflight.
    if Path(value).name != '.gitattributes':
        files.relative_parts(Path(value).name)
    return value


def _plan(data, expected, trusted_names):
    packet.require(type(data) in (bytes, bytearray) and 0 < len(data) <= MAX_PLAN)
    frozen, expected = bytes(data), packet.hex_value(expected)
    packet.require(type(trusted_names) is tuple and 0 < len(trusted_names) <= MAX_FILES)
    names = tuple(_name(n) for n in trusted_names)
    packet.require(len({n.casefold() for n in names}) == len(names))
    packet.require(packet.digest(frozen) == expected)
    value = packet.strict_json(frozen, MAX_PLAN)
    packet.keys(value, 'schema revision nonce sourcePins')
    packet.require(value['schema'] == SCHEMA and type(value['revision']) is str
                   and re.fullmatch('[a-f0-9]{40}', value['revision']))
    packet.identity(value['nonce'])
    packet.keys(value['sourcePins'], ' '.join(names))
    references = []
    for name in sorted(names):
        entry = value['sourcePins'][name]
        packet.keys(entry, 'bytes sha256')
        packet.require(type(entry['bytes']) is int and 0 < entry['bytes'] <= MAX_FILE)
        references.append(CodeReference(name, entry['bytes'], packet.hex_value(entry['sha256'])))
    packet.require(sum(r.size for r in references) <= MAX_TOTAL)
    return value['revision'], value['nonce'], expected, tuple(references)


class _HeldCode:
    def _open(self):
        if self.path.name == '.editorconfig':
            return prep._editor_open(self.parent)
        if self.path.name == '.gitattributes':
            # Source-only exception. Generic recovery-file path rules stay unchanged.
            self.parent.check()
            descriptor = (files.windows_open(self.path) if os.name == 'nt' else
                          os.open(self.path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self.parent.fd))
            try:
                self.parent.check()
                return descriptor
            except BaseException:
                os.close(descriptor)
                raise
        return files.relative_open(self.parent.path, self.parent.fd, self.path.name)

    def __init__(self, parent, reference):
        self.fd, self.parent, self.reference = None, parent, reference
        self.path = parent.path / Path(reference.path).name
        try:
            self.fd = self._open()
            os.set_inheritable(self.fd, False)
            info = os.fstat(self.fd)
            packet.require(files.regular_single_file(info) and info.st_size == reference.size)
            self.state = files.file_state(info)
            self.path_state = files.file_state(self.path.lstat())
            # Windows descriptor/path APIs can expose distinct ctime views.
            # Bind identity/size/mtime together, retaining each ctime independently.
            packet.require(self.state[:4] == self.path_state[:4])
            self.check()
        except BaseException:
            self.close()
            raise

    def check(self):
        packet.require(self.fd is not None and not os.get_inheritable(self.fd))
        held, current = os.fstat(self.fd), self.path.lstat()
        packet.require(files.regular_single_file(held) and files.regular_single_file(current)
                       and files.file_state(held) == self.state and files.file_state(current) == self.path_state)
        os.lseek(self.fd, 0, os.SEEK_SET)
        with os.fdopen(os.dup(self.fd), 'rb') as stream:
            data = stream.read(self.reference.size + 1)
        packet.require(len(data) == self.reference.size and packet.digest(data) == self.reference.sha256
                       and files.file_state(os.fstat(self.fd)) == self.state)

    def close(self):
        if self.fd is not None:
            descriptor, self.fd = self.fd, None
            os.close(descriptor)


class CodeLease:
    """Only the live owner/thread can check this held set; reports cannot recreate it."""
    def _state(self):
        packet.require(self in _LIVE)
        value = _LIVE[self]
        packet.require(value['pid'] == os.getpid() and value['thread'] == threading.get_ident())
        return value

    def check(self):
        value = self._state()
        value['root'].check()
        for parent in value['parents']:
            parent.check()
        for source in value['sources']:
            source.check()

    def report(self):
        self.check()
        value = self._state()
        return dict(schema='fleetory.retained-code-lease.v1', revision=value['revision'], nonce=value['nonce'],
                    planSha256=value['pin'], files=len(value['sources']),
                    bytes=sum(s.reference.size for s in value['sources']),
                    listedSourceIdentitiesAndBytesStable=True, noninheritableDescriptorsHeld=True,
                    metadataControlsRoot=False, sourceContentsReturned=False,
                    sourceOriginAuthenticated=False, fullTransitiveInventoryVerified=False,
                    nativeLaunchAuthorized=False, originalDataUseAuthorized=False,
                    fullSystemRecoveryVerified=False, phase7Complete=False)


@contextmanager
def hold(trusted_repository, plan_bytes, expected_plan, trusted_names):
    """Trusted host supplies root/name set and protected plan pin; wire metadata cannot expand it."""
    revision, nonce, pin, references = _plan(plan_bytes, expected_plan, trusted_names)
    with ExitStack() as held:
        root = held.enter_context(control.DirectoryLease(Path(trusted_repository).absolute()))
        parents, sources = {}, []
        for reference in references:
            parent_path = root.path / Path(reference.path).parent
            if parent_path not in parents:
                parents[parent_path] = held.enter_context(control.DirectoryLease(parent_path))
            source = _HeldCode(parents[parent_path], reference)
            held.callback(source.close)
            sources.append(source)
        value = CodeLease()
        _LIVE[value] = dict(pid=os.getpid(), thread=threading.get_ident(), revision=revision,
                            nonce=nonce, pin=pin, root=root, parents=tuple(parents.values()), sources=tuple(sources))
        try:
            value.check()
            yield value
            value.check()
        finally:
            _LIVE.pop(value, None)


if __name__ == '__main__':
    raise SystemExit('Retained code lease is a library; no root, input, reset, native command or permission CLI.')
