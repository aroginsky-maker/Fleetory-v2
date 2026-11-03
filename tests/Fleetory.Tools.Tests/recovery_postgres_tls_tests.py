"""Portable native PostgreSQL TLS contract and generated-only owned Docker fixture."""
import argparse
import copy
import json
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / 'eng/pilot'))
import recovery_postgres_tls as tls
import recovery_files as files
from recovery_login_tests import PostgresLab, seed_synthetic
from recovery_tls_tests import generate_material


class TlsContractTests(unittest.TestCase):
    def test_native_client_verifies_name_root_and_transport(self):
        args = tls.options('fleetory_server')
        for value in ('PGSSLMODE=verify-full','PGHOSTADDR=127.0.0.1','PGGSSENCMODE=disable',
                      'PGSSLROOTCERT=/tmp/tls-ca','PGPASSFILE=/tmp/pgpass-fleetory_server'):
            self.assertIn(value, args)
        self.assertNotIn('PGPASSWORD', ' '.join(args))

    def test_only_fixed_negative_variants_are_accepted(self):
        for kwargs in ({'hostname':'remote.invalid'}, {'ca':'../../private'}, {'mode':'prefer'}):
            with self.assertRaises(Exception):
                tls.options('fleetory_server', **kwargs)
        with self.assertRaises(Exception):
            tls.options('postgres')

    def test_hba_accepts_only_role_scoped_loopback_ssl_scram(self):
        lines = tls.HBA.splitlines()
        self.assertEqual(len(lines), 6)
        self.assertEqual(lines[:2], ['local all postgres peer','local all all reject'])
        self.assertEqual(lines[2:4], ['hostssl fleetory fleetory_server 127.0.0.1/32 scram-sha-256',
                                    'hostssl fleetory_signer fleetory_signer 127.0.0.1/32 scram-sha-256'])
        self.assertEqual(lines[-2:], ['host all all 0.0.0.0/0 reject','host all all ::/0 reject'])
        self.assertIn('ssl_min_protocol_version=TLSv1.2', tls.START)
        self.assertIn('listen_addresses=127.0.0.1', tls.START)
        self.assertNotIn('trust', tls.START)

    def test_password_file_has_exact_hostname_and_no_extra_record(self):
        self.assertEqual(tls.password_file('fleetory_signer','a'*64), 'postgres:5432:*:fleetory_signer:'+'a'*64+'\n')
        for name, password in (('postgres','a'*64),('fleetory_server',"'"*64)):
            with self.assertRaises(Exception):
                tls.password_file(name,password)

    def test_readback_requires_actual_current_session_ssl_and_role(self):
        valid = ['fleetory_server','fleetory_server','fleetory',4,True,'TLSv1.3','TLS_AES_256_GCM_SHA384']
        self.assertTrue(tls.accept_readback('fleetory_server',json.dumps(valid))['ssl'])
        for index, value in ((0,'postgres'),(1,'postgres'),(2,'fleetory_signer'),(3,True),(3,-1),
                             (4,False),(4,1),(5,'TLSv1.1'),(6,''),(6,'unsafe\ntext')):
            row = copy.deepcopy(valid)
            row[index] = value
            with self.assertRaises(Exception):
                tls.accept_readback('fleetory_server',json.dumps(row))

    def test_denials_reject_arbitrary_connection_or_missing_table_errors(self):
        examples = {'ca':b'SSL error: certificate verify failed',
                    'hostname':b'server certificate for "postgres" does not match host name "wrong"',
                    'plaintext':b'pg_hba.conf rejects connection, no encryption',
                    'password':b'password authentication failed for user'}
        for kind, message in examples.items():
            tls.denied(subprocess.CompletedProcess([],2,b'',message),kind)
            for code, stdout, stderr in ((0,b'',message),(3,b'',message),(2,b'unexpected',message),
                                         (2,b'',b'connection refused'),(2,b'',b'relation does not exist')):
                with self.assertRaises(Exception):
                    tls.denied(subprocess.CompletedProcess([],code,stdout,stderr),kind)

    def test_partial_evidence_cannot_promote_readiness(self):
        rows = [tls.accept_readback(name,json.dumps([name,name,db,1,True,'TLSv1.3','TLS_AES_256_GCM_SHA384']))
                for name, db in tls.login.RUNTIME.items()]
        counts = dict.fromkeys(('ca','hostname','plaintext','password'),2)
        result = tls.evidence(rows, counts)
        for key in ('originalPkiUsed','originalPasswordsRead','externalNetworkTlsVerified',
                    'deployedCertificateEqualityVerified','fullSystemRecoveryVerified','phase7Complete'):
            self.assertIs(result[key], False)
        false_tls = copy.deepcopy(rows)
        false_tls[0]['ssl'] = False
        for bad_rows, bad_counts in ((rows[:1],counts),(rows,{**counts,'ca':1}),(rows,{**counts,'ca':True}),
                                    (false_tls,counts),([rows[0],rows[0]],counts)):
            with self.assertRaises(Exception):
                tls.evidence(bad_rows,bad_counts)

    def test_private_writer_refuses_path_expansion_before_docker(self):
        lab = TlsPostgresLab(Path('unopened'))
        with patch.object(lab,'call') as invoked:
            for name in ('../../root.key','postgres-password','/tmp/tls-key'):
                with self.assertRaises(Exception):
                    lab.write_private(name,b'not-a-secret')
            invoked.assert_not_called()


class TlsPostgresLab(PostgresLab):
    def __init__(self, generated):
        super().__init__()
        self.generated = Path(generated)

    def startup_script(self):
        return tls.START

    def write_private(self, name, packet, replace=False):
        passwords = {'pgpass-' + name for name in tls.login.RUNTIME}
        tls.login.archive.require(name in (set(tls.MATERIAL) | passwords | {'tls-ready'}) and
                                  0 < len(packet) <= 16384 and (not replace or name in passwords))
        self.owned()
        script = 'umask 077; ' + ('' if replace else 'set -C; ') + 'cat > "$1"; chmod 0600 "$1"'
        path = '/tmp/' + name
        self.call(['exec','-i',self.name,'sh','-ec',script,'private-tls-file',path],packet)
        tls.login.archive.require(self.call(['exec',self.name,'stat','-c','%a:%u:%h',path]).stdout.strip() == b'600:999:1')

    def ready(self):
        public = json.loads((self.generated / 'manifest.json').read_text(encoding='utf-8-sig'))
        tls.login.archive.require(public['applicationCommit'] == 'a'*40 and
                                  public['appHost'] == 'app.synthetic.invalid' and public['authHost'] == 'auth.synthetic.invalid')
        with files.rooted(self.generated / 'upload/secrets') as (root, descriptor):
            for name, path in tls.MATERIAL.items():
                _, _, packet = files.inspect_file(root,descriptor,path,16384,retain=True)
                self.write_private(name,packet)
        self.write_private('tls-ready',b'ready')
        super().ready()

    def tls_client(self, name, sql='SELECT 1;', **variant):
        args = tls.options(name, **variant)
        hostname = variant.get('hostname','postgres')
        self.owned()
        return self.call(['exec','-i',*args,self.name,'psql','-XqAt','-w','-v','ON_ERROR_STOP=1',
                          '-h',hostname,'-U',name,'-d',tls.login.RUNTIME[name]],sql.encode(),check=False)

    def exercise_tls(self):
        for name in tls.login.RUNTIME:
            self.admin('postgres',tls.login.password_sql(name,self.passwords[name]))
            self.write_private('pgpass-'+name,tls.password_file(name,self.passwords[name]).encode())
        auth = json.loads(self.admin('postgres',"SELECT json_agg(json_build_array(rolname,rolcanlogin,rolpassword LIKE 'SCRAM-SHA-256$%') ORDER BY rolname) FROM pg_authid WHERE rolname IN ('fleetory_server','fleetory_signer');"))
        tls.login.archive.require(len(auth) == 2 and all(login is True and scram is True for _,login,scram in auth))
        owners = json.loads(self.admin('postgres',"SELECT json_agg(rolcanlogin) FROM pg_roles WHERE rolname IN ('fleetory_migrator','fleetory_signer_owner');"))
        tls.login.archive.require(owners == [False,False])
        tls.login.archive.require(self.call(['exec',self.name,'cat','/var/lib/postgresql/recovery_hba.conf']).stdout == tls.HBA.encode())
        hba = json.loads(self.admin('postgres','SELECT json_agg(error) FROM pg_hba_file_rules;'))
        tls.login.archive.require(hba == [None]*6)
        for setting, value in (('listen_addresses',b'127.0.0.1'),('ssl',b'on'),('ssl_min_protocol_version',b'TLSv1.2')):
            tls.login.archive.require(self.admin('postgres','SHOW '+setting+';').strip() == value)
        rows, counts = [], dict.fromkeys(('ca','hostname','plaintext','password'),0)
        for name in tls.login.RUNTIME:
            result = self.tls_client(name,tls.readback(name))
            tls.login.archive.require(result.returncode == 0)
            rows.append(tls.accept_readback(name,result.stdout))
            for kind, variant in (('ca',{'ca':'tls-wrong-ca'}),('hostname',{'hostname':'wrong.recovery.invalid'}),
                                  ('plaintext',{'mode':'disable'})):
                tls.denied(self.tls_client(name,**variant),kind)
                counts[kind] += 1
            self.write_private('pgpass-'+name,tls.password_file(name,secrets.token_hex(32)).encode(),replace=True)
            tls.denied(self.tls_client(name),'password')
            counts['password'] += 1
        return tls.evidence(rows,counts)


def synthetic():
    with tempfile.TemporaryDirectory(prefix='fleetory-postgres-tls-') as temp:
        generated = generate_material(Path(temp))
        lab = TlsPostgresLab(generated)
        try:
            lab.setup()
            seed_synthetic(lab)
            result = lab.exercise_tls()
        finally:
            lab.cleanup()
    result.update(syntheticOnly=True,ownedResourcesRemoved=True,generatedMaterialRemoved=True)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--docker',action='store_true')
    args = parser.parse_args()
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(TlsContractTests))
    if not result.wasSuccessful():
        sys.exit(1)
    if args.docker:
        print('POSTGRES TCP TLS SYNTHETIC PASS: '+json.dumps(synthetic(),sort_keys=True))
