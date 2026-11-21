#!/usr/bin/env python3
"""Render/validate a creation-only real-image target; never starts Docker or services."""
import argparse
from decimal import Decimal
import json
from pathlib import Path
import re
import sys
import uuid

import audit_archive as archive
import recovery_files as files
import recovery_isolation as isolation

PREFIX = 'fleetory-recovery-target-'
SESSION = 'fleetory.recovery.target.session'
ROLE = 'fleetory.recovery.target.role'
CUSTOM = {'server', 'signer', 'keycloak'}
PUBLIC = {
    'postgres': 'postgres:18.6@sha256:74935e72241653ca55e0414067e6d8763aceb8a810eb51b452253ec3dcfc4336',
    'openbao': 'ghcr.io/openbao/openbao:2.7.1@sha256:6d2b93856e3fcf7b18ad855a0b51eaba474dc8b79cf554379ea32034797d2acf',
    'audit-store': 'codenotary/immudb:1.11.2@sha256:f2efcf6a3de73b31691e0afb8dfec972642aaf0699b93387d1ec6074aedb2953',
    'audit-gateway': 'nginx@sha256:0e52bd054126cdc040b1276c0af347aeb02a41b9cfe305d6094767ac30e97949',
    'caddy': 'caddy@sha256:e70b164da81ef698b3ad19af799ea6086ce6d9e48ed4079eb9fe26f6fbf14ee5',
}
USERS = {'postgres': '999:999', 'openbao': '100:1000', 'audit-store': '3322:3322',
         'audit-gateway': '101:101', 'caddy': '65534:65534', 'server': '1654:1654',
         'signer': '1654:1654', 'keycloak': '1000:0'}
MEMORY = {'postgres': '512m', 'keycloak': '900m', 'openbao': '384m', 'audit-store': '256m',
          'audit-gateway': '32m', 'server': '256m', 'signer': '192m', 'caddy': '32m'}
TEMP = '/tmp:rw,nosuid,noexec,size=16m,mode=1777'
POSTGRES_TEMP = '/var/lib/postgresql:rw,nosuid,noexec,size=64m,mode=0700,uid=999,gid=999'
MAX_INPUT = 64 * 1024


def session(project):
    archive.require(type(project) is str and re.fullmatch(PREFIX + '[a-f0-9]{32}', project))
    return project[len(PREFIX):]


def validate_images(images):
    archive.fields(images, isolation.MEMBERS)
    for role, reference in images.items():
        if role in CUSTOM:
            archive.require(type(reference) is str and re.fullmatch(r'sha256:[a-f0-9]{64}', reference))
        else:
            archive.require(reference == PUBLIC[role])
    archive.require(len({reference.rsplit('sha256:', 1)[1] for reference in images.values()}) == 8)


def load_images(root, name, expected):
    archive.require(type(expected) is str and archive.HEX.fullmatch(expected))
    with files.rooted(root) as (directory, descriptor):
        digest, _, packet = files.inspect_file(directory, descriptor, name, MAX_INPUT, retain=True)
    archive.require(digest == expected)
    record = archive.parse(packet, MAX_INPUT)
    archive.fields(record, ('schema', 'images'))
    archive.require(record['schema'] == 'fleetory.recovery-target-images.v1')
    validate_images(record['images'])
    return record['images']


def render(project, images):
    validate_images(images)
    identity = session(project)
    services = {}
    for role, members in isolation.MEMBERS.items():
        services[role] = {'image': images[role], 'pull_policy': 'never', 'user': USERS[role],
            'read_only': True, 'cap_drop': ['ALL'], 'security_opt': ['no-new-privileges:true'],
            'restart': 'no', 'healthcheck': {'disable': True}, 'networks': list(members),
            'labels': {SESSION: identity, ROLE: role}, 'mem_limit': MEMORY[role], 'cpus': 0.25,
            'pids_limit': 64, 'tmpfs': [TEMP, POSTGRES_TEMP] if role == 'postgres' else [TEMP]}
    return {'name': project, 'services': services, 'networks': {
        name: isolation.network(identity, SESSION) for name in sorted(isolation.NETWORKS)}}


def validate(model, images):
    archive.fields(model, ('name', 'services', 'networks'))
    expected = render(model['name'], images)
    isolation.validate_networks(model['networks'], session(model['name']), SESSION)
    archive.fields(model['services'], isolation.MEMBERS)
    for role, value in model['services'].items():
        archive.fields(value, expected['services'][role])
        archive.require(value['read_only'] is True and value['healthcheck']['disable'] is True)
        archive.require(type(value['pids_limit']) is int and type(value['cpus']) in (int, float, Decimal))
        archive.require(Decimal(str(value['cpus'])) == Decimal('0.25'))
        archive.require(value == expected['services'][role])
    return {'schema': 'fleetory.recovery-target-validation.v1', 'services': 8, 'internalNetworks': 3,
            'creationOnly': True, 'applicationsStarted': False, 'sourceMaterialLoaded': False,
            'fullSystemRecoveryVerified': False, 'phase7Complete': False}


def compose_environment(environment):
    result = {key: value for key, value in environment.items() if not key.startswith('COMPOSE_')}
    result['COMPOSE_DISABLE_ENV_FILE'] = '1'
    return result


def verify_created(role, service, container, image, project):
    """Check only selected metadata; never reads Env, logs or mounted contents."""
    identity = session(project)
    archive.require(role in isolation.MEMBERS)
    archive.require(container['name'] == '/' + project + '-' + role + '-1')
    labels = container['labels']
    archive.require(labels.get(SESSION) == identity and labels.get(ROLE) == role and
                    labels.get('com.docker.compose.project') == project)
    state = container['state']
    archive.require(state['Status'] == 'created' and state['Running'] is False and
                    state['StartedAt'].startswith('0001-') and state['FinishedAt'].startswith('0001-'))
    archive.require(type(container['restartCount']) is int and container['restartCount'] == 0)
    archive.require(container['imageReference'] == service['image'] and container['imageId'] == image['id'])
    archive.require(container['entrypoint'] == image['entrypoint'] and container['command'] == image['command'])
    archive.require(container['user'] == service['user'] and container['healthcheck']['Test'] == ['NONE'])
    host = container['host']
    archive.require(host['ReadonlyRootfs'] is True and host['Privileged'] is False)
    archive.require(host['CapDrop'] == ['ALL'] and not host['CapAdd'] and
                    'no-new-privileges:true' in host['SecurityOpt'])
    archive.require(not host['PortBindings'] and not host['Binds'] and not host['VolumesFrom'])
    archive.require(host['Memory'] == int(MEMORY[role][:-1]) * 1024 * 1024 and
                    host['NanoCpus'] == 250000000 and host['PidsLimit'] == 64)
    archive.require(host['NetworkMode'] in {project + '_' + name for name in isolation.MEMBERS[role]})
    archive.require(host['PidMode'] == '' and host['UTSMode'] == '' and host['UsernsMode'] == '' and
                    host['IpcMode'] == 'private')
    expected_tmpfs = dict(value.split(':', 1) for value in service['tmpfs'])
    archive.require(host['Tmpfs'] == expected_tmpfs)
    archive.require(set(image['volumes'] or {}) <= expected_tmpfs.keys())
    archive.require(all(mount['Type'] == 'tmpfs' and mount['Destination'] in expected_tmpfs
                        for mount in container['mounts']))
    archive.require(set(container['networks']) == {project + '_' + name for name in isolation.MEMBERS[role]})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--images', required=True)
    parser.add_argument('--expected-images-sha256', required=True)
    parser.add_argument('--project')
    parser.add_argument('--validate', action='store_true')
    args = parser.parse_args()
    try:
        images = load_images(Path.cwd(), args.images, args.expected_images_sha256)
        if args.validate:
            archive.require(args.project is None)
            result = validate(archive.parse(sys.stdin.buffer.read(MAX_INPUT + 1), MAX_INPUT), images)
        else:
            result = render(args.project if args.project is not None else PREFIX + uuid.uuid4().hex, images)
            validate(result, images)
    except Exception:
        print('Creation-only target refused; no input contents logged.', file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
