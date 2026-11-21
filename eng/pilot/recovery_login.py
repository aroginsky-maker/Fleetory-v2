"""Fixed target-only LOGIN/SCRAM acceptance contract. Never reads source credentials."""
import re

import audit_archive as archive

RUNTIME = {'fleetory_server': 'fleetory', 'fleetory_signer': 'fleetory_signer'}
OWNERS = ('fleetory_migrator', 'fleetory_signer_owner')
ROLES = (*RUNTIME, *OWNERS)
INSERT_TABLES = {'fleetory_server': ('platform.audit_events',),
                 'fleetory_signer': ('signer.signing_requests', 'signer.signing_results', 'signer.signing_rejections')}
HBA = ('local all postgres peer\nlocal all all scram-sha-256\n'
       'host all all 0.0.0.0/0 reject\nhost all all ::/0 reject\n')
START = '''set -eu
export PGDATA=/var/lib/postgresql/18/recovery
if [ ! -s "$PGDATA/PG_VERSION" ]; then
  initdb -D "$PGDATA" --auth-local=peer --auth-host=reject --no-instructions >/dev/null
fi
printf 'local all postgres peer\\nlocal all all scram-sha-256\\nhost all all 0.0.0.0/0 reject\\nhost all all ::/0 reject\\n' > /var/lib/postgresql/recovery_hba.conf
exec postgres -D "$PGDATA" -c listen_addresses= -c unix_socket_directories=/var/run/postgresql -c hba_file=/var/lib/postgresql/recovery_hba.conf -c password_encryption=scram-sha-256 -c log_statement=none -c log_min_error_statement=panic
'''
DENIALS = {
 'fleetory_server': (
    'CREATE SCHEMA recovery_forbidden;', 'CREATE DATABASE recovery_forbidden;',
    'CREATE ROLE recovery_forbidden;', 'SET ROLE fleetory_migrator;',
    'ALTER ROLE fleetory_server SUPERUSER;', 'CREATE TEMP TABLE recovery_forbidden(x int);',
    'UPDATE platform.audit_events SET action=action;', 'DELETE FROM platform.audit_events;',
    'UPDATE platform."__EFMigrationsHistory" SET "ProductVersion"="ProductVersion";',
    'DELETE FROM platform.admin_certificate_registrations;'),
 'fleetory_signer': (
    'CREATE SCHEMA recovery_forbidden;', 'CREATE DATABASE recovery_forbidden;',
    'CREATE ROLE recovery_forbidden;', 'SET ROLE fleetory_signer_owner;',
    'ALTER ROLE fleetory_signer SUPERUSER;', 'CREATE TEMP TABLE recovery_forbidden(x int);',
    'DELETE FROM signer.signing_requests;', 'DELETE FROM signer.signing_results;',
    'DELETE FROM signer.signing_rejections;', 'DELETE FROM signer.client_certificate_revocations;',
    'TRUNCATE signer.signing_results;'),
}


def password(value):
    archive.require(type(value) is str and re.fullmatch(r'[a-f0-9]{64}', value))
    return value


def role(value):
    archive.require(type(value) is str and value in ROLES)
    return value


def password_sql(name, value):
    role(name)
    password(value)
    admission = 'LOGIN' if name in RUNTIME else 'NOLOGIN'
    return "BEGIN; SET LOCAL password_encryption='scram-sha-256'; ALTER ROLE " + name + ' ' + admission + " PASSWORD '" + value + "'; COMMIT;"


def password_file(name, value):
    return 'localhost:5432:*:' + role(name) + ':' + password(value) + '\n'


def readback_sql(name):
    archive.require(name in RUNTIME)
    table = 'platform.audit_events' if name == 'fleetory_server' else 'signer.signing_results'
    return 'SELECT json_build_array(current_user,session_user,current_database(),(SELECT count(*) FROM ' + table + '))::text;'


def denied(result, kind):
    archive.require(result.returncode != 0 and not result.stdout.strip())
    diagnostic = result.stderr.decode('utf-8', errors='replace')
    if kind == 'privilege':
        archive.require(result.returncode == 3 and re.search(r'ERROR:\s+42501\b', diagnostic))
    else:
        patterns = {'password': 'password authentication failed for user',
                    'nologin': 'is not permitted to log in', 'database': 'permission denied for database'}
        archive.require(kind in patterns and result.returncode == 2 and patterns[kind] in diagnostic)


def evidence(successful_logins, denied_privileges, permitted_inserts):
    archive.require(type(successful_logins) is int and successful_logins == 8)
    archive.require(type(denied_privileges) is int and denied_privileges == sum(map(len, DENIALS.values())))
    archive.require(type(permitted_inserts) is int and permitted_inserts == 4)
    return {'schema': 'fleetory.target-login-acceptance.v1', 'runtimeRoles': 2,
            'successfulReadbackSessions': successful_logins, 'privilegeDenials': denied_privileges,
            'permittedZeroRowInserts': permitted_inserts,
            'wrongPasswordDenials': 2, 'oldPasswordDenials': 2, 'noLoginOwnerDenials': 2,
            'crossDatabaseDenials': 2, 'targetPasswordRotationVerified': True,
            'restartAuthenticationVerified': True, 'transport': 'private Unix socket SCRAM-SHA-256',
            'sourcePasswordsRead': False, 'sourcePasswordRecoveryVerified': False,
            'remoteTlsVerified': False, 'fullSystemRecoveryVerified': False, 'phase7Complete': False}
