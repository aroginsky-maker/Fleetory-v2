#!/usr/bin/env python3
"""Read-only byte preflight of an explicitly pinned six-component recovery set."""
import argparse
from contextlib import contextmanager
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

import audit_archive as archive

SCHEMA = 'fleetory.recovery-files.v1'
KINDS = {'application-postgres', 'signer-postgres', 'audit-export',
         'audit-immudb', 'identity-postgres', 'provider-raft'}
MAX_MANIFEST = 64 * 1024
MAX_ARTIFACT = 64 * 1024 * 1024
SEGMENT = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z')
RESERVED = re.compile(r'(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?\Z', re.I)


def relative_parts(value):
    archive.require(type(value) is str and 0 < len(value) <= 512)
    parts = value.split('/')
    archive.require(1 <= len(parts) <= 4)
    for part in parts:
        archive.require(SEGMENT.fullmatch(part) and not part.endswith('.') and not RESERVED.fullmatch(part))
    return parts


def ordinary_directory(path):
    info = path.lstat()
    archive.require(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode)
                    and not getattr(info, 'st_file_attributes', 0) & 0x400)
    if os.name == 'posix':
        archive.require(info.st_uid in (0, os.geteuid()))
        writable = info.st_mode & 0o022
        archive.require(not writable or (info.st_uid == 0 and info.st_mode & stat.S_ISVTX))


def windows_open(path):
    """Deny write/delete sharing, refuse a reparse leaf and check the final path before reading."""
    import msvcrt
    from ctypes import wintypes
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    create = kernel.CreateFileW
    create.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                       wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    create.restype = wintypes.HANDLE
    final = kernel.GetFinalPathNameByHandleW
    final.argtypes = [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD]
    final.restype = wintypes.DWORD
    close = kernel.CloseHandle
    close.argtypes = [wintypes.HANDLE]
    close.restype = wintypes.BOOL
    handle = create(str(path), 0x80000000, 1, None, 3, 0x08200000, None)
    if handle == ctypes.c_void_p(-1).value:
        raise OSError('Recovery input cannot be opened.')
    try:
        buffer = ctypes.create_unicode_buffer(32768)
        length = final(handle, buffer, len(buffer), 0)
        archive.require(0 < length < len(buffer))
        name = buffer.value
        if name.startswith('\\\\?\\UNC\\'):
            name = '\\\\' + name[8:]
        elif name.startswith('\\\\?\\'):
            name = name[4:]
        archive.require(os.path.normcase(name) == os.path.normcase(str(path)))
        fd = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
        handle = None
        return fd
    finally:
        if handle is not None:
            close(handle)


@contextmanager
def rooted(root):
    root = Path(root).absolute()
    for ancestor in reversed([root, *root.parents]):
        ordinary_directory(ancestor)
    if os.name == 'nt':
        # CI TEMP may use RUNNER~1. Expand names without resolving reparse targets.
        root = windows_long_root(root)
        for ancestor in reversed([root, *root.parents]):
            ordinary_directory(ancestor)
    if os.name == 'posix':
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            yield root, fd
        finally:
            os.close(fd)
    else:
        yield root, None


def windows_long_root(root):
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    convert = kernel.GetLongPathNameW
    convert.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32]
    convert.restype = ctypes.c_uint32
    buffer = ctypes.create_unicode_buffer(32768)
    length = convert(str(root), buffer, len(buffer))
    archive.require(0 < length < len(buffer))
    return Path(buffer.value)


def relative_open(root, root_fd, parts):
    if os.name == 'nt':
        parent = root
        for part in parts[:-1]:
            parent /= part
            ordinary_directory(parent)
        return windows_open(parent / parts[-1])
    archive.require(os.name == 'posix')
    parent = os.dup(root_fd)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            os.close(parent)
            parent = child
        return os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    finally:
        os.close(parent)


def file_state(info):
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def inspect_file(root, root_fd, parts, limit, retain=False):
    with os.fdopen(relative_open(root, root_fd, parts), 'rb') as stream:
        before = os.fstat(stream.fileno())
        archive.require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                        and not getattr(before, 'st_file_attributes', 0) & 0x400
                        and 0 < before.st_size <= limit)
        digest, count, data = hashlib.sha256(), 0, bytearray()
        while True:
            packet = stream.read(min(64 * 1024, limit + 1 - count))
            if not packet:
                break
            count += len(packet)
            archive.require(count <= limit)
            digest.update(packet)
            if retain:
                data.extend(packet)
        archive.require(count == before.st_size and file_state(os.fstat(stream.fileno())) == file_state(before))
    return digest.hexdigest(), count, bytes(data)


def verify(root, manifest, expected):
    archive.require(type(expected) is str and re.fullmatch(r'[A-Fa-f0-9]{64}', expected))
    manifest_parts = relative_parts(manifest)
    with rooted(root) as (directory, root_fd):
        digest, _, packet = inspect_file(directory, root_fd, manifest_parts, MAX_MANIFEST, retain=True)
        archive.require(digest == expected.lower())
        record = archive.parse(packet, MAX_MANIFEST)
        archive.fields(record, ('schema', 'artifacts'))
        archive.require(record['schema'] == SCHEMA)
        archive.fields(record['artifacts'], KINDS)
        paths, total = {manifest.casefold()}, 0
        # Validate the whole schema/path set before opening any artifact.
        for entry in record['artifacts'].values():
            archive.fields(entry, ('path', 'bytes', 'sha256'))
            relative_parts(entry['path'])
            archive.require(entry['path'].casefold() not in paths)
            paths.add(entry['path'].casefold())
            archive.require(type(entry['bytes']) is int and 0 < entry['bytes'] <= MAX_ARTIFACT)
            archive.require(type(entry['sha256']) is str and archive.HEX.fullmatch(entry['sha256']))
        for kind in sorted(KINDS):
            entry = record['artifacts'][kind]
            actual, size, _ = inspect_file(directory, root_fd, relative_parts(entry['path']), entry['bytes'])
            archive.require(size == entry['bytes'] and actual == entry['sha256'])
            total += size
    return {'schema': 'fleetory.recovery-files-verification.v1', 'manifestSha256': digest,
            'verifiedArtifacts': len(KINDS), 'verifiedBytes': total,
            'fullSystemRecoveryVerified': False, 'independentCustodyVerified': False,
            'globalAtomicSnapshotClaimed': False, 'phase7Complete': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', required=True)
    parser.add_argument('--manifest', required=True)
    parser.add_argument('--expected-sha256', required=True)
    args = parser.parse_args()
    try:
        result = verify(args.root, args.manifest, args.expected_sha256)
    except Exception:
        print('Recovery files verification failed; no input contents logged.', file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
