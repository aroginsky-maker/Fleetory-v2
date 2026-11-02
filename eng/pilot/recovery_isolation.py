#!/usr/bin/env python3
"""Render/check a synthetic recovery network rehearsal; never starts Docker or reads backups."""
import argparse
import copy
from decimal import Decimal
import json
import re
import sys
import uuid

import audit_archive as archive

IMAGE = 'python:3.12-slim@sha256:aa943ce411423c7582288f18707ff66eddcbaeb510502d747a72aeb34f30d159'
PREFIX = 'fleetory-recovery-proof-'
PROJECT = re.compile(PREFIX + r'[0-9a-f]{32}\Z')
SESSION = 'fleetory.recovery.probe.session'
ROLE = 'fleetory.recovery.probe.role'
GATEWAY_OPTION = 'com.docker.network.bridge.gateway_mode_ipv4'
MAX_MODEL = 64 * 1024
MEMBERS = {
    'caddy': ('app_net',), 'server': ('app_net',), 'keycloak': ('app_net',),
    'postgres': ('app_net', 'signer_net'), 'signer': ('signer_net',),
    'openbao': ('signer_net',), 'audit-gateway': ('app_net', 'audit_net'),
    'audit-store': ('audit_net',),
}
NETWORKS = {'app_net', 'signer_net', 'audit_net'}
PROBE = '''import socket,sys
role=sys.argv[1].encode('ascii')+b'\\n'
with socket.socket() as listener:
    listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    listener.bind(('0.0.0.0',18080))
    listener.listen(16)
    while True:
        connection,_=listener.accept()
        with connection:
            connection.settimeout(1)
            connection.sendall(role)
'''
SERVICE_FIELDS = {'image', 'entrypoint', 'command', 'user', 'read_only', 'cap_drop',
                  'security_opt', 'restart', 'networks', 'labels', 'mem_limit', 'cpus', 'pids_limit'}


def session(project):
    archive.require(type(project) is str and PROJECT.fullmatch(project))
    return project[len(PREFIX):]


def command(role):
    return ['python', '-I', '-B', '-u', '-c', PROBE, role]


def network(identity):
    return {'driver': 'bridge', 'internal': True, 'enable_ipv6': False,
            'driver_opts': {GATEWAY_OPTION: 'isolated'}, 'labels': {SESSION: identity}}


def render(project):
    identity = session(project)
    common = {'image': IMAGE, 'entrypoint': [], 'user': '65534:65534', 'read_only': True,
              'cap_drop': ['ALL'], 'security_opt': ['no-new-privileges:true'], 'restart': 'no',
              'mem_limit': '64m', 'cpus': 0.25, 'pids_limit': 32}
    services = {}
    for role, networks in MEMBERS.items():
        service = copy.deepcopy(common)
        service.update(command=command(role), networks=list(networks), labels={SESSION: identity, ROLE: role})
        services[role] = service
    return {'name': project, 'services': services, 'networks': {name: network(identity) for name in sorted(NETWORKS)}}


def validate_networks(networks, identity):
    archive.fields(networks, NETWORKS)
    for value in networks.values():
        archive.fields(value, ('driver', 'internal', 'enable_ipv6', 'driver_opts', 'labels'))
        archive.require(value['driver'] == 'bridge' and value['internal'] is True and value['enable_ipv6'] is False)
        archive.fields(value['driver_opts'], (GATEWAY_OPTION,))
        archive.require(value['driver_opts'][GATEWAY_OPTION] == 'isolated')
        archive.fields(value['labels'], (SESSION,))
        archive.require(value['labels'][SESSION] == identity)


def validate_service(role, service, identity):
    archive.fields(service, SERVICE_FIELDS)
    archive.require(service['image'] == IMAGE and service['entrypoint'] == [] and service['command'] == command(role))
    archive.require(service['user'] == '65534:65534' and service['read_only'] is True and service['restart'] == 'no')
    archive.require(service['cap_drop'] == ['ALL'] and service['security_opt'] == ['no-new-privileges:true'])
    archive.require(service['mem_limit'] == '64m' and type(service['cpus']) in (int, float, Decimal)
                    and Decimal(str(service['cpus'])) == Decimal('0.25')
                    and type(service['pids_limit']) is int and service['pids_limit'] == 32)
    labels = service['labels']
    archive.fields(labels, (SESSION, ROLE))
    archive.require(labels[SESSION] == identity and labels[ROLE] == role)
    networks = service['networks']
    archive.require(type(networks) is list and all(type(n) is str for n in networks))
    archive.require(len(networks) == len(set(networks)) and set(networks) == set(MEMBERS[role]))


def validate(model):
    archive.fields(model, ('name', 'services', 'networks'))
    identity = session(model['name'])
    validate_networks(model['networks'], identity)
    archive.fields(model['services'], MEMBERS)
    for role, service in model['services'].items():
        validate_service(role, service, identity)
    return {'schema': 'fleetory.recovery-isolation-validation.v1', 'services': len(MEMBERS),
            'internalNetworks': len(NETWORKS), 'realRecoveryStarted': False,
            'fullSystemRecoveryVerified': False, 'independentCustodyVerified': False, 'phase7Complete': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project', help='Only a unique fleetory-recovery-proof-<32 lowercase hex> namespace.')
    parser.add_argument('--validate', action='store_true', help='Validate bounded JSON from stdin; no files or Docker access.')
    args = parser.parse_args()
    try:
        if args.validate:
            archive.require(args.project is None)
            result = validate(archive.parse(sys.stdin.buffer.read(MAX_MODEL + 1), MAX_MODEL))
        else:
            result = render(args.project if args.project is not None else PREFIX + uuid.uuid4().hex)
            validate(result)
    except Exception:
        print('Recovery isolation contract refused; no input content logged.', file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, allow_nan=False))
    return 0


if __name__ == '__main__':
    sys.exit(main())
