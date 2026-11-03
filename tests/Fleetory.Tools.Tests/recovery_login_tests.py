"""Portable LOGIN contract and optional synthetic local PostgreSQL/SCRAM fixture."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import time
import unittest
import uuid

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / 'eng/pilot'))
import recovery_login as contract

PG = 'postgres:18.6@sha256:74935e72241653ca55e0414067e6d8763aceb8a810eb51b452253ec3dcfc4336'
PYTHON = 'python:3.12-slim@sha256:aa943ce411423c7582288f18707ff66eddcbaeb510502d747a72aeb34f30d159'
LABEL = 'fleetory.recovery.login.session'


class ContractTests(unittest.TestCase):
    def test_only_fixed_role_names_and_hex_passwords_are_accepted(self):
        for name in contract.ROLES:
            result = contract.password_sql(name, 'a' * 64)
            self.assertIn(' LOGIN ' if name in contract.RUNTIME else ' NOLOGIN ', result)
            self.assertIn("password_encryption='scram-sha-256'", result)
            self.assertNotIn('GRANT', result)
        for name in ('postgres', 'role;DROP DATABASE fleetory', '', None):
            with self.assertRaises(Exception):
                contract.password_sql(name, 'a' * 64)
        for value in ('x', 'a' * 65, 'a' * 63, 'A' * 64, "'" * 64, None):
            with self.assertRaises(Exception):
                contract.password_sql('fleetory_server', value)

    def test_pgpass_has_fixed_socket_and_no_extra_records(self):
        self.assertEqual(contract.password_file('fleetory_server', 'a' * 64),
                         'localhost:5432:*:fleetory_server:' + 'a' * 64 + '\n')

    def test_hba_uses_peer_only_for_admin_and_scram_for_runtime(self):
        self.assertEqual(contract.HBA.splitlines(), ['local all postgres peer', 'local all all scram-sha-256',
                         'host all all 0.0.0.0/0 reject', 'host all all ::/0 reject'])
        self.assertNotIn('trust', contract.START)
        self.assertIn('listen_addresses=', contract.START)

    def test_denials_require_expected_auth_or_sqlstate_not_arbitrary_error(self):
        examples = {'password': (2, b'password authentication failed for user'),
                    'nologin': (2, b'role is not permitted to log in'),
                    'database': (2, b'permission denied for database'), 'privilege': (3, b'ERROR: 42501')}
        for kind, (code, text) in examples.items():
            contract.denied(subprocess.CompletedProcess([], code, b'', text), kind)
            for result in (subprocess.CompletedProcess([], 0, b'', text),
                           subprocess.CompletedProcess([], code, b'unexpected', text),
                           subprocess.CompletedProcess([], code, b'', b'ERROR: 42P01')):
                with self.assertRaises(Exception):
                    contract.denied(result, kind)

    def test_readback_and_privilege_sets_are_role_scoped(self):
        for name, database in contract.RUNTIME.items():
            query = contract.readback_sql(name)
            self.assertIn('session_user', query)
            self.assertIn('current_database()', query)
            self.assertEqual(len(contract.DENIALS[name]), 10 if database == 'fleetory' else 11)
        with self.assertRaises(Exception):
            contract.readback_sql('postgres')

    def test_evidence_refuses_partial_acceptance_and_keeps_recovery_limits(self):
        record = contract.evidence(8, 21, 4)
        for key in ('sourcePasswordsRead', 'sourcePasswordRecoveryVerified', 'remoteTlsVerified',
                    'fullSystemRecoveryVerified', 'phase7Complete'):
            self.assertIs(record[key], False)
        for args in ((7, 21, 4), (8, 20, 4), (True, 21, 4), (8, 21, 3)):
            with self.assertRaises(Exception):
                contract.evidence(*args)


class PostgresLab:
    def __init__(self):
        self.identity = uuid.uuid4().hex
        self.name = 'fleetory-login-' + self.identity
        self.volume = self.name + '-data'
        self.created = False
        self.volume_created = False
        self.context = None
        self.passwords = {name: secrets.token_hex(32) for name in contract.ROLES}

    def call(self, args, packet=None, check=True, timeout=40):
        command = ['docker'] + (['--context', self.context] if self.context else []) + args
        result = subprocess.run(command, input=packet, capture_output=True, timeout=timeout)
        if len(result.stdout) > 1024 * 1024 or len(result.stderr) > 1024 * 1024 or check and result.returncode:
            raise RuntimeError('Owned LOGIN fixture operation failed; no SQL, passwords or database contents logged.')
        return result

    def preflight(self):
        if os.environ.get('DOCKER_HOST') or os.environ.get('DOCKER_CONTEXT'):
            raise RuntimeError('Unreviewed Docker overrides refused.')
        self.context = self.call(['context', 'show']).stdout.decode().strip()
        contract.archive.require(self.context in ('default', 'desktop-linux'))
        endpoint = self.call(['context', 'inspect', self.context, '--format', '{{.Endpoints.docker.Host}}']).stdout.decode().strip()
        contract.archive.require(endpoint in ('unix:///var/run/docker.sock', 'npipe:////./pipe/dockerDesktopLinuxEngine', 'npipe:////./pipe/docker_engine'))
        contract.archive.require(self.call(['info', '--format', '{{.OSType}}']).stdout.strip() == b'linux')
        self.call(['image', 'inspect', PG, '--format', '{{.Id}}'])
        self.call(['image', 'inspect', PYTHON, '--format', '{{.Id}}'])

    def owned(self):
        fields = ('NetworkMode', 'ReadonlyRootfs', 'Privileged', 'PortBindings', 'CapDrop', 'CapAdd', 'SecurityOpt', 'Memory', 'PidsLimit', 'NanoCpus')
        host_template = '{' + ','.join('"' + key + '":{{json (index .HostConfig "' + key + '")}}' for key in fields) + '}'
        template = '{"name":{{json .Name}},"labels":{{json .Config.Labels}},"image":{{json .Config.Image}},"user":{{json .Config.User}},"host":' + host_template + ',"mounts":{{json .Mounts}}}'
        value = json.loads(self.call(['container', 'inspect', self.name, '--format', template]).stdout)
        host = value['host']
        contract.archive.require(value['name'] == '/' + self.name and value['labels'].get(LABEL) == self.identity)
        contract.archive.require(value['image'] == PG and value['user'] == '999:999' and host['ReadonlyRootfs'])
        contract.archive.require(host['NetworkMode'] == 'none' and not host['Privileged'] and not host['PortBindings'])
        contract.archive.require(host['CapDrop'] == ['ALL'] and not host['CapAdd'] and 'no-new-privileges' in host['SecurityOpt'][0])
        contract.archive.require(host['Memory'] == 384 * 1024 * 1024 and host['PidsLimit'] == 128 and host['NanoCpus'] == 1000000000)
        mounts = value['mounts']
        contract.archive.require(len(mounts) == 1 and mounts[0]['Type'] == 'volume' and
                                 mounts[0]['Name'] == self.volume and mounts[0]['Destination'] == '/var/lib/postgresql')

    def setup(self):
        self.preflight()
        self.call(['volume', 'create', '--label', LABEL + '=' + self.identity, self.volume])
        self.volume_created = True
        self.call(['run', '--rm', '--network', 'none', '--read-only', '--cap-drop', 'ALL', '--cap-add', 'CHOWN',
                   '--security-opt', 'no-new-privileges', '--memory', '128m', '--mount',
                   'type=volume,src=' + self.volume + ',dst=/data', PYTHON, 'python', '-c',
                   "import os;os.chmod('/data',0o700);os.chown('/data',999,999)"])
        self.call(['create', '--name', self.name, '--label', LABEL + '=' + self.identity, '--network', 'none',
                   '--read-only', '--user', '999:999', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
                   '--memory', '384m', '--cpus', '1', '--pids-limit', '128', '--mount',
                   'type=volume,src=' + self.volume + ',dst=/var/lib/postgresql',
                   '--tmpfs', '/var/run/postgresql:rw,noexec,nosuid,size=8m,mode=0775,uid=999,gid=999',
                   '--tmpfs', '/tmp:rw,noexec,nosuid,size=16m,mode=0700,uid=999,gid=999',
                   '--entrypoint', 'sh', PG, '-ec', contract.START])
        self.created = True
        self.owned()
        self.call(['start', self.name])
        self.ready()

    def ready(self):
        for _ in range(60):
            result = self.call(['exec', self.name, 'pg_isready', '-q', '-U', 'postgres'], check=False)
            if not result.returncode:
                self.owned()
                return
            time.sleep(0.3)
        raise RuntimeError('Owned LOGIN fixture not ready.')

    def admin(self, database, sql):
        contract.archive.require(database in ('postgres', 'fleetory', 'fleetory_signer'))
        self.owned()
        return self.call(['exec', '-i', '-u', 'postgres', self.name, 'psql', '-XqAt', '-v',
                          'ON_ERROR_STOP=1', '-U', 'postgres', '-d', database], sql.encode()).stdout

    def provision_password_file(self, name, value):
        path = '/tmp/pgpass-' + contract.role(name)
        self.call(['exec', '-i', self.name, 'sh', '-ec', 'umask 077; cat > "$1"; chmod 0600 "$1"',
                   'private-password-file', path], contract.password_file(name, value).encode())
        actual = self.call(['exec', self.name, 'stat', '-c', '%a:%u:%h', path]).stdout.strip()
        contract.archive.require(actual == b'600:999:1')

    def client(self, name, database, sql='SELECT 1;'):
        contract.role(name)
        contract.archive.require(database in ('fleetory', 'fleetory_signer'))
        self.owned()
        packet = ('\\set VERBOSITY sqlstate\n' + sql + '\n').encode()
        return self.call(['exec', '-i', '-e', 'LC_ALL=C', '-e', 'PGCONNECT_TIMEOUT=5', '-e',
                          'PGPASSFILE=/tmp/pgpass-' + name, self.name, 'psql', '-XqAt', '-w', '-v',
                          'ON_ERROR_STOP=1', '-h', '/var/run/postgresql', '-U', name, '-d', database], packet, check=False)

    def configure(self):
        self.admin('postgres', '\n'.join(contract.password_sql(name, value) for name, value in self.passwords.items()))
        for name, value in self.passwords.items():
            self.provision_password_file(name, value)
        rows = json.loads(self.admin('postgres', "SELECT json_agg(json_build_array(rolname,rolcanlogin,rolpassword LIKE 'SCRAM-SHA-256$%') ORDER BY rolname) FROM pg_authid WHERE rolname IN ('fleetory_server','fleetory_signer','fleetory_migrator','fleetory_signer_owner');").decode())
        contract.archive.require(len(rows) == 4 and all(login == (name in contract.RUNTIME) and scram is True for name, login, scram in rows))
        hba = json.loads(self.admin('postgres', 'SELECT json_agg(json_build_array(type,database,user_name,auth_method,error) ORDER BY line_number) FROM pg_hba_file_rules;').decode())
        contract.archive.require(len(hba) == 4 and all(row[-1] is None for row in hba))
        contract.archive.require(hba[0][3] == 'peer' and hba[1][3] == 'scram-sha-256' and hba[2][3] == hba[3][3] == 'reject')
        contract.archive.require(self.call(['exec', self.name, 'cat', '/var/lib/postgresql/recovery_hba.conf']).stdout == contract.HBA.encode())
        contract.archive.require(self.admin('postgres', 'SHOW listen_addresses;').strip() == b'')

    def success(self):
        for name, database in contract.RUNTIME.items():
            result = self.client(name, database, contract.readback_sql(name))
            if result.returncode:
                diagnostic = result.stderr.decode(errors='replace')
                kind = next((key for key in ('no password supplied', 'password authentication failed',
                                              'permission denied', 'does not exist') if key in diagnostic), 'unclassified')
                raise RuntimeError('Runtime readback failed: ' + kind + '; code=' + str(result.returncode))
            values = json.loads(result.stdout)
            contract.archive.require(values[:3] == [name, name, database] and type(values[3]) is int)
        return 2

    def exercise(self):
        self.configure()
        successes = self.success()
        permitted_inserts = 0
        for name, tables in contract.INSERT_TABLES.items():
            for table in tables:
                sql = 'BEGIN; WITH inserted AS (INSERT INTO ' + table + ' SELECT * FROM ' + table + ' WHERE false RETURNING 1) SELECT count(*) FROM inserted; ROLLBACK;'
                result = self.client(name, contract.RUNTIME[name], sql)
                contract.archive.require(result.returncode == 0 and result.stdout.strip() == b'0')
                permitted_inserts += 1
        for name, database in contract.RUNTIME.items():
            self.provision_password_file(name, secrets.token_hex(32))
            contract.denied(self.client(name, database), 'password')
            self.provision_password_file(name, self.passwords[name])
            other = 'fleetory_signer' if database == 'fleetory' else 'fleetory'
            contract.denied(self.client(name, other), 'database')
        for owner, database in zip(contract.OWNERS, ('fleetory', 'fleetory_signer')):
            contract.denied(self.client(owner, database), 'nologin')
        denied_count = 0
        for name, queries in contract.DENIALS.items():
            for sql in queries:
                contract.denied(self.client(name, contract.RUNTIME[name], sql), 'privilege')
                denied_count += 1
        for name, database in contract.RUNTIME.items():
            old = self.passwords[name]
            self.passwords[name] = secrets.token_hex(32)
            self.admin('postgres', contract.password_sql(name, self.passwords[name]))
            self.provision_password_file(name, old)
            contract.denied(self.client(name, database), 'password')
            self.provision_password_file(name, self.passwords[name])
        successes += self.success()
        self.call(['restart', self.name])
        self.ready()
        for name, value in self.passwords.items():
            self.provision_password_file(name, value)
        successes += self.success()
        # A second post-restart independent client session proves no connection reuse.
        successes += self.success()
        return contract.evidence(successes, denied_count, permitted_inserts)

    def cleanup(self):
        if self.created:
            self.owned()
            self.call(['container', 'rm', '-f', self.name])
            self.created = False
        if self.volume_created:
            meta = json.loads(self.call(['volume', 'inspect', self.volume]).stdout)[0]
            contract.archive.require(meta['Name'] == self.volume and meta['Labels'].get(LABEL) == self.identity)
            self.call(['volume', 'rm', self.volume])
            self.volume_created = False
        self.passwords.clear()


def synthetic():
    lab = PostgresLab()
    try:
        lab.setup()
        lab.admin('postgres', '\n'.join('CREATE ROLE ' + name + ' NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;' for name in contract.ROLES))
        lab.admin('postgres', 'CREATE DATABASE fleetory OWNER fleetory_migrator; CREATE DATABASE fleetory_signer OWNER fleetory_signer_owner; REVOKE ALL ON DATABASE fleetory,fleetory_signer FROM PUBLIC; GRANT CONNECT ON DATABASE fleetory TO fleetory_server; GRANT CONNECT ON DATABASE fleetory_signer TO fleetory_signer;')
        lab.admin('fleetory', 'CREATE SCHEMA platform AUTHORIZATION fleetory_migrator; REVOKE ALL ON SCHEMA public FROM PUBLIC; SET ROLE fleetory_migrator; CREATE TABLE platform.audit_events(action text); CREATE TABLE platform."__EFMigrationsHistory"("ProductVersion" text); CREATE TABLE platform.admin_certificate_registrations(id int); INSERT INTO platform.audit_events VALUES(\'fixture\'); RESET ROLE; GRANT USAGE ON SCHEMA platform TO fleetory_server; GRANT SELECT,INSERT ON platform.audit_events TO fleetory_server; GRANT SELECT ON platform."__EFMigrationsHistory",platform.admin_certificate_registrations TO fleetory_server;')
        lab.admin('fleetory_signer', 'CREATE SCHEMA signer AUTHORIZATION fleetory_signer_owner; REVOKE ALL ON SCHEMA public FROM PUBLIC; SET ROLE fleetory_signer_owner; CREATE TABLE signer.signing_requests(id int); CREATE TABLE signer.signing_results(id int); CREATE TABLE signer.signing_rejections(id int); CREATE TABLE signer.client_certificate_revocations(id int); INSERT INTO signer.signing_results VALUES(1); RESET ROLE; GRANT USAGE ON SCHEMA signer TO fleetory_signer; GRANT SELECT,INSERT ON signer.signing_requests,signer.signing_results,signer.signing_rejections TO fleetory_signer; GRANT SELECT ON signer.client_certificate_revocations TO fleetory_signer;')
        record = lab.exercise()
    finally:
        lab.cleanup()
    record['ownedResourcesRemoved'] = True
    return record


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--docker', action='store_true')
    args = parser.parse_args()
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(ContractTests))
    if not result.wasSuccessful():
        sys.exit(1)
    if args.docker:
        print('LOGIN SCRAM DOCKER PASS: ' + json.dumps(synthetic(), sort_keys=True))
