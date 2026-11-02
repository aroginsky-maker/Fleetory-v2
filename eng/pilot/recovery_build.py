#!/usr/bin/env python3
"""Prepare deterministic code-only build contexts; never invokes Docker or starts services."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import sys
import tarfile

import audit_archive as archive
import release_inputs as release

RECIPE_PINS = {
    'server/Server.Dockerfile': '179d0b166b717c55eecff14c7c73ccca9d7b2938a286eb56680ec290d9454f9e',
    'signer/Dockerfile': 'fd92f6f6abf18343f0a2ed593f9807e02eb9849fb045bfe25cebe6e8945641a4',
    'signer/.dockerignore': 'dd1d65bf6ad71a77ae3efc2e65dfd03e1fbcaa060146d6cdc7d58608b2f882d9',
    'signer/entrypoint.sh': '285963e09d3fa33544415a47d88a3e4735eb3bf17b10196ed21f342c1de5fd56',
    'keycloak/Dockerfile': 'de70cc0f47204505b20064129e8b5630db5a01cc0af4ab0bff908c268a3146b2',
}
BASES = {
    'server': 'mcr.microsoft.com/dotnet/aspnet:10.0@sha256:de0ee358cdd672f7017a003bed21e9ac9ed48a27c922a59b18175b6e82fa7fee',
    'keycloak': 'quay.io/keycloak/keycloak:26.8.0@sha256:27b3230fbabb8c9ff3c66c864cf09dcd8a41aca82e5100679d109ef0eeb05741',
}
BASES['signer'] = BASES['server']


def recipe(name, packet):
    archive.require(type(packet) is bytes and len(packet) <= 16384)
    normalized = packet.replace(b'\r\n', b'\n')
    archive.require(hashlib.sha256(normalized).hexdigest() == RECIPE_PINS[name])
    return normalized


def pack(members):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w', format=tarfile.USTAR_FORMAT) as writer:
        for name, packet in sorted(members.items()):
            info = tarfile.TarInfo(name)
            info.size, info.mode, info.mtime = len(packet), 0o444, 0
            if name == 'entrypoint.sh':
                info.mode = 0o555
            writer.addfile(info, io.BytesIO(packet))
    return output.getvalue()


def contexts(root, name, expected, keycloak_recipe):
    inventory, packet = release.read_verified(root, name, expected)
    content = {}
    # read_verified already refuses every extension/link/path record and bounds
    # the entire in-memory packet. Never extract to host paths or re-open input.
    with tarfile.open(fileobj=io.BytesIO(packet), mode='r:') as reader:
        for entry in reader:
            if entry.isfile():
                content[entry.name] = reader.extractfile(entry).read()
    archive.require(content.keys() == inventory['files'].keys())
    for member in release.RECIPES:
        normalized = recipe(member, content[member])
        # Keep COPY payload bytes, including the signer entrypoint, unchanged.
        if member != 'signer/entrypoint.sh':
            content[member] = normalized
    result = {}
    for role in ('server', 'signer'):
        prefix = role + '/'
        members = {path[len(prefix):]: value for path, value in content.items() if path.startswith(prefix)}
        if role == 'server':
            members['Dockerfile'] = members.pop('Server.Dockerfile')
        result[role] = pack(members)
    result['keycloak'] = pack({'Dockerfile': recipe('keycloak/Dockerfile', keycloak_recipe)})
    return inventory, result


def summary(inventory, packets):
    return {'schema': 'fleetory.code-build-contexts.v1', 'archiveSha256': inventory['archiveSha256'],
            'contexts': {role: {'bytes': len(packet), 'sha256': hashlib.sha256(packet).hexdigest(),
                                'pinnedBase': BASES[role]} for role, packet in sorted(packets.items())},
            'dockerInvoked': False, 'servicesStarted': False, 'releaseSignatureVerified': False,
            'sourceRevisionAuthenticated': False, 'fullSystemRecoveryVerified': False, 'phase7Complete': False}


def environment(values):
    archive.require(type(values) is list and all(type(value) is str and '=' in value for value in values))
    pairs = [value.split('=', 1) for value in values]
    archive.require(all(key for key, _ in pairs) and len({key for key, _ in pairs}) == len(pairs))
    return dict(pairs)


def verify_image(role, image, base):
    """Check selected metadata of a fresh local build against its separately pinned base."""
    archive.require(role in BASES)
    for value in (image, base):
        archive.require(value['os'] == 'linux' and value['arch'] == 'amd64')
        archive.require(type(value['id']) is str and re.fullmatch(r'sha256:[a-f0-9]{64}', value['id']))
        archive.require(type(value['layers']) is list and value['layers'] and
                        all(type(layer) is str and re.fullmatch(r'sha256:[a-f0-9]{64}', layer)
                            for layer in value['layers']))
    archive.require(image['layers'][:len(base['layers'])] == base['layers'] and
                    len(image['layers']) > len(base['layers']))
    archive.require(image['volumes'] is None or image['volumes'] == {})
    expected_env = environment(base['env'])
    if role == 'keycloak':
        user, workdir, entrypoint, command = '1000:0', base['workdir'], base['entrypoint'], base['cmd']
        expected_env.update(KC_DB='postgres', KC_HEALTH_ENABLED='true')
    else:
        user, workdir, command = '1654', '/app', None
        entrypoint = ['dotnet', '/app/Fleetory.Server.dll'] if role == 'server' else ['/app/entrypoint.sh']
        expected_env.update(DOTNET_ENVIRONMENT='Production', DOTNET_EnableDiagnostics='0')
        expected_env['ASPNETCORE_URLS' if role == 'server' else 'ASPNETCORE_HTTP_PORTS'] = ''
    # A child Dockerfile that sets ENTRYPOINT resets an inherited base CMD.
    archive.require(image['user'] == user and image['workdir'] == workdir and
                    image['entrypoint'] == entrypoint and image['cmd'] == command)
    archive.require(environment(image['env']) == expected_env)
    ports = dict(base['ports'] or {})
    if role == 'signer':
        ports['9443/tcp'] = {}
    archive.require((image['ports'] or {}) == ports)
    return {'role': role, 'baseRootfsPrefixMatches': True, 'runtimeMetadataVerified': True,
            'historicalSourceImageReproduced': False, 'fullSystemRecoveryVerified': False, 'phase7Complete': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', required=True)
    parser.add_argument('--expected-sha256', required=True)
    args = parser.parse_args()
    try:
        # This recipe belongs to the installed checkout; CLI cannot select an
        # arbitrary recipe path, filesystem root, destination or Docker host.
        keycloak = (Path(__file__).resolve().parents[2] / 'infra/pilot/Keycloak.Dockerfile').read_bytes()
        inventory, packets = contexts(Path.cwd(), args.archive, args.expected_sha256, keycloak)
        result = summary(inventory, packets)
    except Exception:
        print('Code build preparation refused; no input contents logged.', file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
