"""Leaf TLS scope contracts and generated-only network-none transport fixture."""
import argparse
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / 'eng/pilot'))
import recovery_tls as tls


def certificate(value):
    return b'-----BEGIN CERTIFICATE-----\n' + base64.b64encode(value) + b'\n-----END CERTIFICATE-----\n'


class LeafTests(unittest.TestCase):
    def setUp(self):
        self.roots = {name: hashlib.sha256(name.encode()).hexdigest().upper() for name in tls.ROOTS}
        self.plan = tls.plan(self.roots)

    def refuse(self, change):
        candidate = copy.deepcopy(self.plan)
        change(candidate)
        with self.assertRaises(Exception):
            tls.validate_plan(candidate)

    def test_seven_fixed_leaf_triples_only(self):
        self.assertEqual(len(self.plan['roles']), 7)
        self.assertEqual(sum(len(row['files']) for row in self.plan['roles'].values()), 21)
        tls.validate_plan(self.plan)

    def test_unknown_fields_roles_and_missing_roles_are_refused(self):
        self.refuse(lambda p: p.update(issuer=True))
        self.refuse(lambda p: p['roles'].update(issuer=p['roles']['signer']))
        self.refuse(lambda p: p['roles'].pop('signer'))

    def test_every_path_is_fixed_and_cannot_expand_private_scope(self):
        for role in tls.ROLES:
            for kind in ('ca', 'cert', 'key'):
                for path in ('../root.key', '/private.key', 'offline/root.key', 'operator/seal-share', 'postgres/password'):
                    self.refuse(lambda p: p['roles'][role]['files'].update({kind: path}))

    def test_names_and_root_assignments_cannot_be_changed(self):
        for role in tls.ROLES:
            self.refuse(lambda p: p['roles'][role].update(serverName='attacker.invalid'))
            self.refuse(lambda p: p['roles'][role].update(root='signer-client'))

    def test_pins_must_be_three_distinct_exact_uppercase_digests(self):
        for value in (None, True, 'a' * 64, 'A' * 63, 'A' * 65, 'A' * 64 + '\n'):
            self.refuse(lambda p: p['roots'].update(admin=value))
        self.refuse(lambda p: p['roots'].update(admin=p['roots']['agent']))
        self.refuse(lambda p: p['roots'].update(extra='F' * 64))

    def test_single_public_pem_only_and_bounded(self):
        packet = certificate(b'admin')
        self.assertEqual(tls.root_digest(packet), self.roots['admin'])
        for value in (packet * 2, packet + b'private', b'PRIVATE KEY', b'\xff', b' ' * tls.MAX_FILE + packet):
            with self.assertRaises(Exception):
                tls.root_digest(value)

    def fixture(self, directory):
        source = directory / 'source'
        source.mkdir(mode=0o700)
        for root, _, ca, cert, key in tls.ROLES.values():
            for path, packet in ((ca, certificate(root.encode())), (cert, certificate(b'leaf')),
                                 (key, b'-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n')):
                target = source / path
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                target.write_bytes(packet)
        return source

    def test_staging_is_minimal_and_does_not_change_source(self):
        with tempfile.TemporaryDirectory(prefix='fleetory-leaf-unit-') as temp:
            directory = Path(temp)
            source = self.fixture(directory)
            before = {str(p.relative_to(source)): p.read_bytes() for p in source.rglob('*') if p.is_file()}
            target = directory / 'stage'
            tls.stage(source, target, self.plan)
            after = {str(p.relative_to(source)): p.read_bytes() for p in source.rglob('*') if p.is_file()}
            self.assertEqual(before, after)
            self.assertEqual(len([p for p in target.rglob('*') if p.is_file()]), 22)
            self.assertEqual(json.loads((target / 'plan.json').read_text()), self.plan)
            if os.name == 'posix':
                self.assertEqual(target.stat().st_mode & 0o777, 0o700)
                self.assertTrue(all(p.stat().st_mode & 0o777 == 0o600 for p in target.rglob('*') if p.is_file()))

    def test_bad_pin_fails_before_reading_first_key(self):
        with tempfile.TemporaryDirectory(prefix='fleetory-leaf-unit-') as temp:
            source = self.fixture(Path(temp))
            bad = copy.deepcopy(self.plan)
            bad['roots']['infrastructure'] = 'F' * 64
            with patch.object(tls.files, 'inspect_file', wraps=tls.files.inspect_file) as opened:
                with self.assertRaises(Exception):
                    tls.stage(source, Path(temp) / 'stage', bad)
            self.assertEqual(opened.call_count, 1)

    def test_invalid_scope_and_existing_target_refused_before_source_read(self):
        with tempfile.TemporaryDirectory(prefix='fleetory-leaf-unit-') as temp:
            with patch.object(tls.files, 'inspect_file') as opened:
                with self.assertRaises(Exception):
                    tls.stage('unopened-source', Path(temp), self.plan)
                bad = copy.deepcopy(self.plan)
                bad['roles']['signer']['files']['key'] = 'ca/root.key'
                with self.assertRaises(Exception):
                    tls.stage('unopened-source', Path(temp) / 'stage', bad)
                opened.assert_not_called()

    def test_git_destination_refused(self):
        with tempfile.TemporaryDirectory(prefix='fleetory-leaf-unit-') as temp:
            directory = Path(temp)
            (directory / '.git').mkdir()
            with self.assertRaises(Exception):
                tls.stage('unopened-source', directory / 'stage', self.plan)
            self.assertFalse((directory / 'stage').exists())

    def test_hardlinked_and_oversized_inputs_refused(self):
        with tempfile.TemporaryDirectory(prefix='fleetory-leaf-unit-') as temp:
            directory = Path(temp)
            source = self.fixture(directory)
            path = source / 'postgres/ca.crt'
            os.link(path, directory / 'alias')
            with self.assertRaises(Exception):
                tls.stage(source, directory / 'stage-one', self.plan)
            (directory / 'alias').unlink()
            path.write_bytes(b'x' * (tls.MAX_FILE + 1))
            with self.assertRaises(Exception):
                tls.stage(source, directory / 'stage-two', self.plan)

    def test_private_key_cannot_be_staged_as_public_certificate(self):
        packet = b'-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n'
        for kind in ('ca', 'cert'):
            with self.assertRaises(Exception):
                tls.validate_packet(kind, packet, self.roots['admin'])
        with self.assertRaises(Exception):
            tls.validate_packet('key', certificate(b'leaf'), self.roots['admin'])

    def test_remote_docker_overrides_refused_before_subprocess(self):
        with patch.dict(os.environ, {'DOCKER_HOST': 'tcp://remote.invalid:2375'}), patch.object(tls.subprocess, 'run') as invoked:
            with self.assertRaises(Exception):
                tls.local_docker()
            invoked.assert_not_called()

    def test_cli_cannot_choose_original_root(self):
        result = subprocess.run([sys.executable, '-B', tls.__file__, '--root', 'source'], capture_output=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(b'Traceback', result.stderr)


def synthetic():
    with tempfile.TemporaryDirectory(prefix='fleetory-leaf-synthetic-') as temp:
        directory = Path(temp)
        executable = shutil.which('pwsh')
        if not executable and os.name == 'nt':
            executable = str(Path(sys.executable).parents[1] / 'native/powershell/pwsh.exe')
        generated = directory / 'generated'
        result = subprocess.run([executable, '-NoProfile', '-File', str(REPO / 'eng/pilot/New-PilotMaterial.ps1'),
                                 '-OutputDirectory', str(generated), '-AppHost', 'app.synthetic.invalid',
                                 '-AuthHost', 'auth.synthetic.invalid', '-ApplicationCommit', 'a' * 40],
                                capture_output=True, timeout=90)
        tls.archive.require(result.returncode == 0)
        public = json.loads((generated / 'manifest.json').read_text(encoding='utf-8-sig'))['publicRootDerFingerprints']
        record = tls.plan({name: public[name] for name in tls.ROOTS})
        staged = directory / 'minimal'
        tls.stage(generated / 'upload/secrets', staged, record)
        proof = tls.sandbox(staged)
    proof.update(syntheticOnly=True, originalPrivateKeysRead=False, ownedResourcesRemoved=True)
    return proof


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--docker', action='store_true')
    args = parser.parse_args()
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(LeafTests))
    if not result.wasSuccessful():
        sys.exit(1)
    if args.docker:
        print('LEAF TLS SYNTHETIC PASS: ' + json.dumps(synthetic(), sort_keys=True))
