"""Target-only PostgreSQL TCP/TLS contract with regenerated disposable test PKI."""
import json
import re

import recovery_login as login

HBA = ('local all postgres peer\nlocal all all reject\n'
       'hostssl fleetory fleetory_server 127.0.0.1/32 scram-sha-256\n'
       'hostssl fleetory_signer fleetory_signer 127.0.0.1/32 scram-sha-256\n'
       'host all all 0.0.0.0/0 reject\nhost all all ::/0 reject\n')
MATERIAL = {'tls-ca': 'postgres/ca.crt', 'tls-cert': 'postgres/server.crt',
            'tls-key': 'postgres/server.key', 'tls-wrong-ca': 'server/admin-gateway-root-ca'}
START = login.START.split("printf 'local all postgres peer", 1)[0] + '''
for attempt in $(seq 1 100); do
  if [ -f /tmp/tls-ready ]; then break; fi
  sleep 0.1
done
test -f /tmp/tls-ready
printf '%s' ''' + "'" + HBA + "'" + ''' > /var/lib/postgresql/recovery_hba.conf
exec postgres -D "$PGDATA" -c listen_addresses=127.0.0.1 -c unix_socket_directories=/var/run/postgresql -c hba_file=/var/lib/postgresql/recovery_hba.conf -c password_encryption=scram-sha-256 -c ssl=on -c ssl_cert_file=/tmp/tls-cert -c ssl_key_file=/tmp/tls-key -c ssl_min_protocol_version=TLSv1.2 -c log_statement=none -c log_min_error_statement=panic
'''


def options(name, hostname='postgres', ca='tls-ca', mode='verify-full'):
    login.archive.require(name in login.RUNTIME and hostname in ('postgres', 'wrong.recovery.invalid') and
                          ca in ('tls-ca', 'tls-wrong-ca') and mode in ('verify-full', 'disable'))
    return ['-e', 'LC_ALL=C', '-e', 'PGCONNECT_TIMEOUT=5', '-e', 'PGHOSTADDR=127.0.0.1',
            '-e', 'PGGSSENCMODE=disable', '-e', 'PGSSLMODE=' + mode,
            '-e', 'PGSSLROOTCERT=/tmp/' + ca, '-e', 'PGPASSFILE=/tmp/pgpass-' + name,
            '-e', 'PGAPPNAME=fleetory-recovery-tls']


def password_file(name, value):
    login.archive.require(name in login.RUNTIME)
    return 'postgres:5432:*:' + name + ':' + login.password(value) + '\n'


def readback(name):
    login.archive.require(name in login.RUNTIME)
    table = 'platform.audit_events' if name == 'fleetory_server' else 'signer.signing_results'
    return 'SELECT json_build_array(current_user,session_user,current_database(),(SELECT count(*) FROM ' + table + '),ssl,version,cipher)::text FROM pg_stat_ssl WHERE pid=pg_backend_pid();'


def accept_readback(name, packet):
    login.archive.require(name in login.RUNTIME)
    row = json.loads(packet)
    login.archive.require(type(row) is list and len(row) == 7)
    login.archive.require(row[:3] == [name, name, login.RUNTIME[name]] and type(row[3]) is int and row[3] >= 0)
    login.archive.require(row[4] is True and row[5] in ('TLSv1.2', 'TLSv1.3') and
                          type(row[6]) is str and re.fullmatch(r'[A-Za-z0-9_-]{3,128}', row[6]))
    return {'role': name, 'database': row[2], 'ownTableRows': row[3], 'ssl': True,
            'version': row[5], 'cipher': row[6]}


def denied(result, kind):
    login.archive.require(result.returncode == 2 and not result.stdout.strip())
    text = result.stderr.decode('utf-8', errors='replace')
    expected = {'ca': ('SSL error: certificate verify failed',),
                'hostname': ('server certificate for', 'does not match host name'),
                'plaintext': ('pg_hba.conf rejects connection', 'no encryption'),
                'password': ('password authentication failed for user',)}
    login.archive.require(kind in expected and all(marker in text for marker in expected[kind]))


def evidence(rows, counts):
    login.archive.fields(counts, ('ca', 'hostname', 'plaintext', 'password'))
    login.archive.require(all(type(value) is int and value == 2 for value in counts.values()))
    login.archive.require(type(rows) is list and len(rows) == 2)
    for row in rows:
        login.archive.fields(row, ('role','database','ownTableRows','ssl','version','cipher'))
        checked = accept_readback(row['role'],json.dumps([row['role'],row['role'],row['database'],
                                  row['ownTableRows'],row['ssl'],row['version'],row['cipher']]))
        login.archive.require(checked == row)
    login.archive.require({row['role'] for row in rows} == set(login.RUNTIME))
    return {'schema': 'fleetory.postgres-tcp-tls-acceptance.v1', 'runtimeRoles': 2,
            'tlsReadbackSessions': rows, 'denials': counts, 'loopbackPostgresTcpTlsVerified': True,
            'transport': 'native PostgreSQL/libpq TLS verify-full and SCRAM-SHA-256 over private container TCP loopback',
            'originalPasswordsRead': False, 'originalPkiUsed': False, 'sourceVpsAccessed': False,
            'externalNetworkTlsVerified': False, 'deployedCertificateEqualityVerified': False,
            'mtlsClientAuthorizationVerified': False, 'fullSystemRecoveryVerified': False, 'phase7Complete': False}
