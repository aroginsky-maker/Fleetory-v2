#!/usr/bin/env python3
"""Inventory an explicitly pinned pilot code archive without extracting or executing it."""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tarfile

import audit_archive as archive
import recovery_files as files

MAX_COMPRESSED = 16 * 1024 * 1024
MAX_EXPANDED = 32 * 1024 * 1024
MAX_MEMBER = 8 * 1024 * 1024
MAX_ENTRIES = 128
ARCHIVE_NAME = re.compile(r'release-[a-f0-9]{7,40}(?:-verified)?\.tar\.gz\Z')
RECIPES = {'server/Server.Dockerfile', 'signer/Dockerfile',
           'signer/.dockerignore', 'signer/entrypoint.sh'}
MODULES = {'Assets', 'CMDB', 'Core', 'Integrations', 'ITSM', 'Monitoring', 'Platform'}
SERVER_ASSEMBLIES = ({f'Fleetory.{name}{suffix}' for name in MODULES for suffix in ('', '.Contracts')}
                     | {'Fleetory.ModuleAbstractions', 'Fleetory.Security.Infrastructure',
                        'Fleetory.Server', 'Fleetory.SharedKernel'})
DEPENDENCIES = {'Microsoft.AspNetCore.Authentication.JwtBearer', 'Microsoft.Bcl.Cryptography',
                'Microsoft.EntityFrameworkCore', 'Microsoft.EntityFrameworkCore.Abstractions',
                'Microsoft.EntityFrameworkCore.Relational', 'Npgsql',
                'Npgsql.EntityFrameworkCore.PostgreSQL', 'System.IdentityModel.Tokens.Jwt'}
DEPENDENCIES |= {f'Microsoft.IdentityModel.{name}' for name in
                 ('Abstractions', 'JsonWebTokens', 'Logging', 'Protocols', 'Protocols.OpenIdConnect', 'Tokens')}
SIGNER_ASSEMBLIES = {'Fleetory.CommandSigner.Host', 'Fleetory.CommandSigning', 'Fleetory.Core.Contracts',
                     'Fleetory.ModuleAbstractions', 'Fleetory.Platform.Contracts',
                     'Fleetory.Security.Infrastructure', 'Fleetory.SharedKernel', 'Npgsql'}
SERVER_FILES = ({f'{name}.{ext}' for name in SERVER_ASSEMBLIES for ext in ('dll', 'pdb')}
                | {f'{name}.dll' for name in DEPENDENCIES}
                | {'appsettings.json', 'appsettings.Production.json', 'web.config',
                   'Fleetory.Server.deps.json', 'Fleetory.Server.runtimeconfig.json',
                   'Fleetory.Server.staticwebassets.endpoints.json'})
SIGNER_FILES = ({f'{name}.dll' for name in SIGNER_ASSEMBLIES}
                | {'Fleetory.CommandSigner.Host.deps.json', 'Fleetory.CommandSigner.Host.runtimeconfig.json'})
REQUIRED = RECIPES | {f'signer/publish/{name}' for name in SIGNER_FILES} | {
    'server/publish/Fleetory.Server.dll', 'server/publish/Fleetory.Server.deps.json',
    'server/publish/Fleetory.Server.runtimeconfig.json', 'server/publish/appsettings.json',
    'server/publish/appsettings.Production.json'}
DIRECTORIES = {'server', 'server/publish', 'signer', 'signer/publish'}


def allowed_file(name):
    if name in RECIPES:
        return True
    for role, names in (('server', SERVER_FILES), ('signer', SIGNER_FILES)):
        prefix = role + '/publish/'
        if name.startswith(prefix) and name[len(prefix):] in names:
            return True
    return False


def record_bytes(packet):
    return {'bytes': len(packet), 'sha256': hashlib.sha256(packet).hexdigest()}


def inventory_tar(packet):
    """Parse ordinary 512-byte tar records only; extension headers are refused before processing."""
    archive.require(len(packet) % 512 == 0 and len(packet) <= MAX_EXPANDED)
    position, entries, seen, result = 0, 0, set(), {}
    while position + 512 <= len(packet):
        header = packet[position:position + 512]
        if header == bytes(512):
            archive.require(len(packet) - position >= 1024 and not any(packet[position:]))
            archive.require(REQUIRED <= result.keys())
            return result
        info = tarfile.TarInfo.frombuf(header, 'utf-8', 'strict')
        archive.require(info.type in (tarfile.REGTYPE, tarfile.DIRTYPE) and not info.linkname)
        name = info.name
        archive.require(name not in seen and name.casefold() not in seen)
        seen.update((name, name.casefold()))
        entries += 1
        archive.require(entries <= MAX_ENTRIES and 0 <= info.size <= MAX_MEMBER)
        position += 512
        end = position + info.size
        archive.require(end <= len(packet))
        if info.type == tarfile.DIRTYPE:
            archive.require(name in DIRECTORIES and info.size == 0)
        else:
            archive.require(allowed_file(name) and info.size > 0)
            result[name] = record_bytes(memoryview(packet)[position:end])
        position += ((info.size + 511) // 512) * 512
    raise archive.ArchiveError('Release archive has no complete terminator.')


def expand(stream):
    packet = bytearray()
    with gzip.GzipFile(fileobj=stream, mode='rb') as compressed:
        while True:
            block = compressed.read(min(64 * 1024, MAX_EXPANDED + 1 - len(packet)))
            if not block:
                return packet
            packet.extend(block)
            archive.require(len(packet) <= MAX_EXPANDED)


def inspect(root, name, expected):
    archive.require(type(name) is str and ARCHIVE_NAME.fullmatch(name))
    archive.require(type(expected) is str and archive.HEX.fullmatch(expected))
    with files.rooted(root) as (directory, root_fd):
        with os.fdopen(files.relative_open(directory, root_fd, name), 'rb') as stream:
            before = os.fstat(stream.fileno())
            archive.require(0 < before.st_size <= MAX_COMPRESSED)
            digest, count = hashlib.sha256(), 0
            while True:
                block = stream.read(min(64 * 1024, MAX_COMPRESSED + 1 - count))
                if not block:
                    break
                count += len(block)
                archive.require(count <= MAX_COMPRESSED)
                digest.update(block)
            archive.require(count == before.st_size and digest.hexdigest() == expected)
            stream.seek(0)
            expanded = expand(stream)
            members = inventory_tar(expanded)
            archive.require(files.file_state(before) == files.file_state(os.fstat(stream.fileno())))
    return {'schema': 'fleetory.release-input-inventory.v1', 'archiveSha256': expected,
            'compressedBytes': count, 'expandedBytes': len(expanded), 'files': members,
            'releaseSignatureVerified': False, 'sourceRevisionAuthenticated': False,
            'fullSystemRecoveryVerified': False, 'phase7Complete': False}


def payloads(inventory):
    result = {}
    for role in ('server', 'signer'):
        prefix = role + '/publish/'
        result[role] = {name[len(prefix):]: entry for name, entry in inventory['files'].items()
                        if name.startswith(prefix)}
    result['signer']['entrypoint.sh'] = inventory['files']['signer/entrypoint.sh']
    return result


def compare_runtime(inventory, observed):
    """Compare a separately observed complete code-path inventory, including unexpected files."""
    archive.fields(observed, ('server', 'signer'))
    expected = payloads(inventory)
    for role in expected:
        record = observed[role]
        archive.fields(record, ('imageId', 'readOnlyImageCodePathVerified', 'files'))
        archive.require(type(record['imageId']) is str and
                        re.fullmatch(r'sha256:[a-f0-9]{64}', record['imageId']))
        archive.require(record['readOnlyImageCodePathVerified'] is True)
        archive.require(type(record['files']) is dict and record['files'].keys() == expected[role].keys())
        for value in record['files'].values():
            archive.fields(value, ('bytes', 'sha256'))
            archive.require(type(value['bytes']) is int and 0 < value['bytes'] <= MAX_MEMBER)
            archive.require(type(value['sha256']) is str and archive.HEX.fullmatch(value['sha256']))
        archive.require(record['files'] == expected[role])
    return {'schema': 'fleetory.release-payload-continuity.v1', 'archiveSha256': inventory['archiveSha256'],
            'matchedFiles': sum(len(value) for value in expected.values()),
            'codePayloadContinuityVerified': True, 'imageConfigurationVerified': False,
            'releaseSignatureVerified': False, 'sourceRevisionAuthenticated': False,
            'fullSystemRecoveryVerified': False, 'phase7Complete': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', required=True)
    parser.add_argument('--expected-sha256', required=True)
    args = parser.parse_args()
    try:
        result = inspect(Path.cwd(), args.archive, args.expected_sha256)
    except Exception:
        print('Release inventory failed; no input contents logged.', file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
