"""Held public ServerBackendProbe publication and deterministic bounded build context; no CLI."""
from contextlib import ExitStack
import io
import os
from pathlib import Path
import re
import tarfile

import audit_native_preparation as prep

packet, control, process, files = prep.packet, prep.control, prep.process, prep.files
MAX_MANIFEST, MAX_CONTEXT = 98304, 16 * 1024 * 1024
MAX_CONTENT = 15 * 1024 * 1024
REQUIRED = ('ServerBackendProbe.dll', 'ServerBackendProbe.deps.json', 'ServerBackendProbe.runtimeconfig.json')


def relative_name(value):
    packet.require(type(value) is str and 0 < len(value) <= 240)
    parts = value.split('/')
    packet.require(1 <= len(parts) <= 8 and len(parts[-1]) <= 100 and len('/'.join(parts[:-1])) <= 155)
    packet.require(all(re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', p) and p not in ('.', '..') for p in parts))
    return value


def _manifest_entry(item, aliases):
    packet.keys(item, 'kind path bytes sha256')
    name = relative_name(item['path'])
    packet.require(name.casefold() not in aliases and type(item['bytes']) is int)
    aliases.add(name.casefold())
    if item['kind'] == 'f':
        packet.hex_value(item['sha256'])
        packet.require(0 < item['bytes'] <= MAX_CONTENT and Path(name).suffix in ('.dll', '.json', '.pdb'))
    else:
        packet.require(item['kind'] == 'd' and item['bytes'] == 0 and item['sha256'] == '-')
    return name


def _manifest_tree(entries):
    packet.require(list(entries) == sorted(entries))
    for name in entries:
        parent = str(Path(name).parent).replace('\\', '/')
        packet.require(parent == '.' or (parent in entries and entries[parent]['kind'] == 'd'))
    packet.require(all(n in entries and entries[n]['kind'] == 'f' for n in REQUIRED))


def manifest(data, expected):
    packet.hex_value(expected)
    packet.require(type(data) in (bytes, bytearray) and 0 < len(data) <= MAX_MANIFEST and packet.digest(data) == expected)
    value = packet.strict_json(data, MAX_MANIFEST)
    packet.keys(value, 'schema sha256 entries files bytes runtimeDependenciesAuthenticated softwareOriginAuthenticated')
    packet.require(value['schema'] == 'fleetory.historical-probe-bundle.v1' and
        value['runtimeDependenciesAuthenticated'] is False and value['softwareOriginAuthenticated'] is False)
    packet.require(type(value['entries']) is list and 0 < len(value['entries']) <= 256)
    entries, aliases = {}, set()
    lines = bytearray(b'fleetory.historical.probe-bundle.v1\n')
    for item in value['entries']:
        entries[_manifest_entry(item, aliases)] = item
        lines.extend((item['kind'] + ':' + item['path'] + '\n' + str(item['bytes']) + '\n' + item['sha256'] + '\n').encode('ascii'))
    total = sum(v['bytes'] for v in entries.values())
    count = sum(v['kind'] == 'f' for v in entries.values())
    _manifest_tree(entries)
    packet.require(0 < count <= 128 and total <= MAX_CONTENT and value['sha256'] == packet.digest(lines))
    packet.require(type(value['files']) is int and type(value['bytes']) is int and value['files'] == count and value['bytes'] == total)
    return value, entries


def tree(root):
    """Names/kinds only; reject links before any target resolution or content read."""
    result, pending = {}, [root]
    while pending:
        parent = pending.pop()
        files.ordinary_directory(parent)
        for path in parent.iterdir():
            name = relative_name(path.relative_to(root).as_posix())
            packet.require(len(result) < 256 and name not in result)
            state = path.lstat()
            if files.regular_single_file(state):
                result[name] = 'f'
            else:
                files.ordinary_directory(path)
                result[name] = 'd'
                pending.append(path)
    return result


class _PublishedPin(process.PinnedFile):
    """Keep the relative open anchored to the held publication, including a raced leaf."""
    def __init__(self, root, name, expected):
        self._root, self._name = root, relative_name(name)
        root.check()
        packet.require(files.regular_single_file((root.path / name).lstat()))
        super().__init__(root.path / name, expected)

    def _open(self):
        self._root.check()
        packet.require(self.path == self._root.path / self._name)
        return files.relative_open(self._root.path, self._root.fd, self._name)

    def check(self):
        self._root.check()
        super().check()


class HeldProbeBundle:
    """Trusted public publication root only; held file and directory identities stay live."""
    def __init__(self, root, data, expected):
        self.value, self.entries = manifest(data, expected)
        self.raw, self.pin = bytes(data), expected
        self._held, self.directories, self.pins = ExitStack(), [], {}
        try:
            self.directory = self._held.enter_context(control.DirectoryLease(Path(root)))
            self.root = self.directory.path
            packet.require(tree(self.root) == {n: v['kind'] for n, v in self.entries.items()})
            for name, item in self.entries.items():
                path = self.root / name
                if item['kind'] == 'd':
                    self.directories.append(self._held.enter_context(control.DirectoryLease(path)))
                else:
                    pin = self._held.enter_context(_PublishedPin(self.directory, name, item['sha256']))
                    packet.require(pin.state[2] == item['bytes'])
                    self.pins[name] = pin
            self.check()
        except BaseException:
            self.close()
            raise

    def check(self):
        self.directory.check()
        checked, _ = manifest(self.raw, self.pin)
        packet.require(checked == self.value and {n: v['kind'] for n, v in self.entries.items()} == tree(self.root))
        for directory in self.directories:
            directory.check()
        for pin in self.pins.values():
            pin.check()

    def _content(self, name):
        pin = self.pins[name]
        pin.check()
        os.lseek(pin.fd, 0, os.SEEK_SET)
        with os.fdopen(os.dup(pin.fd), 'rb') as stream:
            data = stream.read(self.entries[name]['bytes'] + 1)
        packet.require(len(data) == self.entries[name]['bytes'] and packet.digest(data) == pin.digest)
        pin.check()
        return data

    def context(self, definition):
        packet.require(type(definition) is bytes and 0 < len(definition) <= 4096)
        self.check()
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode='w', format=tarfile.USTAR_FORMAT) as archive:
            def add(name, data):
                item = tarfile.TarInfo(name)
                item.size, item.mode, item.uid, item.gid, item.mtime = len(data), 0o644, 0, 0, 0
                archive.addfile(item, io.BytesIO(data))
                packet.require(output.tell() <= MAX_CONTEXT - 10240)
            add('Dockerfile', definition)
            for name in self.pins:
                add('publish/' + name, self._content(name))
        data = output.getvalue()
        packet.require(0 < len(data) <= MAX_CONTEXT)
        self.check()
        return data

    def close(self):
        self._held.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def verify_readback(data, held):
    packet.require(type(held) is HeldProbeBundle and type(data) is bytes and 0 < len(data) <= MAX_CONTEXT)
    held.check()
    seen = set()
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:') as archive:
        for item in archive:
            packet.require(len(seen) <= 256 and set(item.pax_headers) <= {'mtime', 'atime', 'ctime'})
            if item.name in ('.', 'tool'):
                packet.require(item.isdir() and '' not in seen)
                seen.add('')
                continue
            prefix = './' if item.name.startswith('./') else 'tool/'
            packet.require(item.name.startswith(prefix))
            name = relative_name(item.name[len(prefix):])
            packet.require(name not in seen and name in held.entries)
            seen.add(name)
            expected = held.entries[name]
            packet.require(item.uid == item.gid == 0 and not item.issym() and not item.islnk())
            if expected['kind'] == 'd':
                packet.require(item.isdir() and item.mode == 0o755)
            else:
                packet.require(item.isfile() and item.mode == 0o644 and item.size == expected['bytes'])
                with archive.extractfile(item) as stream:
                    body = stream.read(expected['bytes'] + 1)
                packet.require(len(body) == expected['bytes'] and packet.digest(body) == expected['sha256'])
    packet.require(seen - {''} == set(held.entries))
    held.check()
    return dict(verified=True, files=held.value['files'], bytes=held.value['bytes'], bundleSha256=held.value['sha256'])


if __name__ == '__main__':
    raise SystemExit('Public probe bundle library; no root, command, Docker or original-data CLI.')
