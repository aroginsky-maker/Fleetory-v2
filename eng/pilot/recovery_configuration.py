"""Closed File-provider configuration profile for an unstarted native recovery probe."""
import argparse
import json
import sys

import audit_archive as archive

ROOT = '/tmp/material/'
SLOTS = {
    'server': ('fleetory-postgresql','agent-gateway-root-ca','agent-gateway-server-cert','agent-gateway-server-key',
               'admin-gateway-root-ca','admin-gateway-server-cert','admin-gateway-server-key','audit-immudb-password','infrastructure-ca'),
    'signer': ('infrastructure-ca','signer-policy','signer-postgresql','signer-server-ca','signer-server-cert',
               'signer-server-key','signer-transit-public-key','signer-transit-token')
}


def render():
    return {'schema':'fleetory.recovery-configuration.v1', 'provider':'File', 'profiles':{
        'server': {'Fleetory:Secrets:Provider':'File','Fleetory:Secrets:Directory':ROOT+'server',
                   'Fleetory:Web:Port':'5088','Fleetory:AgentGateway:Enabled':'true','Fleetory:AgentGateway:Port':'5443',
                   'Fleetory:AdminGateway:Enabled':'true','Fleetory:AdminGateway:BindAddress':'127.0.0.1',
                   'Fleetory:AdminGateway:Port':'5444','Fleetory:AdminGateway:Oidc:Enabled':'true',
                   'Fleetory:AdminGateway:Oidc:Authority':'https://identity.recovery.invalid/realms/recovery',
                   'Fleetory:AdminGateway:Oidc:Audience':'fleetory-recovery-test',
                   'Fleetory:AdminGateway:Oidc:ClientId':'fleetory-recovery-test',
                   'Fleetory:AuditExport:Enabled':'true','Fleetory:AuditExport:Sink':'Immudb',
                   'Fleetory:AuditExport:Address':'https://immudb:8080','Fleetory:AuditExport:Username':'fleetory_audit_writer',
                   'Fleetory:AuditExport:Database':'fleetoryaudit','AllowedHosts':'localhost;127.0.0.1'},
        'signer': {'Signer:SecretsDirectory':ROOT+'signer','Signer:BindAddress':'127.0.0.1','Signer:Port':'9443',
                   'Signer:TransitAddress':'https://openbao:8200','Signer:TransitKey':'recovery-only','Signer:TransitKeyVersion':'1'}},
        'slots':{name:list(values) for name, values in SLOTS.items()}}


def validate(record):
    archive.fields(record, ('schema','provider','profiles','slots'))
    archive.require(record == render())


def arguments(record, role):
    validate(record)
    archive.require(role in SLOTS)
    return [role]+['--'+key+'='+value for key,value in record['profiles'][role].items()]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--validate',action='store_true')
    args = parser.parse_args()
    try:
        record = archive.parse(sys.stdin.buffer.read(16385),16384) if args.validate else render()
        validate(record)
        result = {'schema':'fleetory.recovery-configuration-validation.v1','provider':'File','roles':2,'requiredFiles':17,
                  'originalMaterialApproved':False,'servicesStarted':False,'fullSystemRecoveryVerified':False,'phase7Complete':False} if args.validate else record
        print(json.dumps(result,sort_keys=True))
        return 0
    except Exception:
        print('Recovery configuration refused; no secret values logged.',file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
