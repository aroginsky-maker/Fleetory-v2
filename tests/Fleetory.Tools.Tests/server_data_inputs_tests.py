"""Fresh binary admission fixtures; no original backups, keys, services or restore."""
import copy
from dataclasses import FrozenInstanceError
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'eng' / 'pilot'))
import recovery_composition_tests as fixtures
import server_data_inputs as policy


def sha(packet):
    return hashlib.sha256(packet).hexdigest()


class ServerDataInputsTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='fleetory-server-inputs-')
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.reports = fixtures.synthetic_reports()
        self.component = dict(schema=policy.composition.SCHEMA, sourceApplicationCommit=fixtures.APP,
                              sourceConfigurationCommit=fixtures.CONFIG, operatorRevision='c' * 40, reports={})
        self.data = {'application-postgres': b'\x00SYNTHETIC_APPLICATION_CANARY\xff',
                     'audit-immudb': b'\x00SYNTHETIC_AUDIT_CANARY\xfe'}
        self.record = dict(schema=policy.SCHEMA, componentManifestSha256='', candidateCommit='d' * 40,
                           candidateBuildSha256='e' * 64, artifacts={})
        self.bind_data()

    def bind_data(self):
        for kind, name in policy.INPUTS.items():
            packet = self.data[kind]
            (self.root / name).write_bytes(packet)
            self.record['artifacts'][kind] = dict(bytes=len(packet), sha256=sha(packet))
        self.reports['database']['dumpSha256']['fleetory'] = sha(self.data['application-postgres'])
        self.reports['login']['sourceDumpSha256'] = copy.deepcopy(self.reports['database']['dumpSha256'])
        self.reports['audit']['backupSha256'] = sha(self.data['audit-immudb'])
        self.reports['audit']['backupBytes'] = len(self.data['audit-immudb'])
        self.pin_components()

    def pin_components(self):
        self.record['componentManifestSha256'] = fixtures.pin_reports(self.root, self.reports, self.component)
        self.pin()

    def pin(self, packet=None):
        packet = json.dumps(self.record).encode() if packet is None else packet
        (self.root / policy.MANIFEST).write_bytes(packet)
        self.expected = sha(packet)

    def load(self):
        return policy.load(self.root, self.expected)

    def cli(self, *extra, expected=None):
        return subprocess.run([sys.executable, '-B', str(Path(policy.__file__)), '--expected-sha256',
                               expected or self.expected, *extra], capture_output=True, timeout=5, cwd=self.root)

    def refused_before_data(self):
        original = policy.files.inspect_file
        opened = []

        def observed(directory, descriptor, name, *args, **kwargs):
            opened.append(name)
            return original(directory, descriptor, name, *args, **kwargs)

        with patch.object(policy.files, 'inspect_file', side_effect=observed):
            with self.assertRaises(Exception):
                self.load()
        self.assertTrue(set(opened).isdisjoint(policy.INPUTS.values()), opened)

    def test_complete_capsule_and_cli_preserve_original_bytes_and_partial_scope(self):
        before = {p.name: p.read_bytes() for p in self.root.iterdir()}
        capsule = self.load()
        for kind, packet in self.data.items():
            self.assertEqual(capsule.packet(kind), packet)
            self.assertIs(type(capsule.packet(kind)), bytes)
        result = self.cli()
        self.assertEqual(result.returncode, 0, result.stderr)
        record = json.loads(result.stdout)
        self.assertEqual(record['verifiedInputs'], 2)
        self.assertEqual(record['verifiedInputBytes'], sum(map(len, self.data.values())))
        self.assertEqual(record['expectedAuditEvents'], 4)
        self.assertEqual(record['expectedAuditTransactions'], 5)
        self.assertNotEqual(record['candidateCommit'], record['reportedSourceApplicationCommit'])
        for key in ('nativeBackupFormatsValidated', 'databaseSchemaCompatibilityVerified', 'candidateBuildAuthenticated',
                    'sourceRevisionAuthenticated', 'restoredDataContentsVerified', 'originalSigningKeyContinuityVerified',
                    'servicesStarted', 'newOperationsAuthorized', 'standingAuthorizationRemaining',
                    'postRestoreHumanLoginVerified', 'fullSystemRecoveryVerified', 'phase7Complete'):
            self.assertIs(record[key], False)
        for packet in self.data.values():
            self.assertNotIn(packet[1:-1], result.stdout + result.stderr)
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.root.iterdir()})

    def test_verified_bytes_survive_source_replacement_without_reopening(self):
        capsule = self.load()
        for kind, name in policy.INPUTS.items():
            (self.root / name).write_bytes(b'X' * len(self.data[kind]))
            self.assertEqual(capsule.packet(kind), self.data[kind])
        with self.assertRaises(Exception):
            self.load()

    def test_immutable_carrier_does_not_expose_packets_in_repr_or_mutable_summary(self):
        capsule = self.load()
        with self.assertRaises(FrozenInstanceError):
            capsule.application = b'changed'
        self.assertEqual(repr(capsule), 'VerifiedServerData()')
        result = capsule.result()
        result['artifacts']['application-postgres']['sha256'] = '0' * 64
        self.assertEqual(capsule.result()['artifacts']['application-postgres']['sha256'], sha(capsule.application))
        for kind in ('provider-raft', 'identity-postgres', '../application.dump', None):
            with self.subTest(kind=kind), self.assertRaises(Exception):
                capsule.packet(kind)

    def test_late_second_input_failure_returns_no_partial_result_or_contents(self):
        (self.root / policy.INPUTS['audit-immudb']).write_bytes(b'X' * len(self.data['audit-immudb']))
        result = self.cli()
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, b'')
        self.assertEqual(result.stderr.strip(), b'Server data admission failed; no input contents logged.')

    def test_only_fixed_metadata_and_two_data_files_are_opened(self):
        canary = self.root / 'unapproved-provider-key'
        canary.write_text('NOT_APPROVED_CANARY')
        for report in self.reports.values():
            report['backupPath'] = str(canary)
            report['proofPath'] = str(canary)
        self.pin_components()
        original = policy.files.inspect_file
        opened = []

        def observed(directory, descriptor, name, *args, **kwargs):
            opened.append(name)
            return original(directory, descriptor, name, *args, **kwargs)

        with patch.object(policy.files, 'inspect_file', side_effect=observed):
            self.load()
        self.assertEqual(opened, [policy.MANIFEST, policy.composition.MANIFEST,
                                 *policy.composition.REPORTS.values(), *policy.INPUTS.values()])
        self.assertEqual(canary.read_text(), 'NOT_APPROVED_CANARY')

    def test_stale_pin_and_changed_component_report_refused_before_data(self):
        self.record['candidateCommit'] = 'a' * 40
        (self.root / policy.MANIFEST).write_bytes(json.dumps(self.record).encode())
        self.refused_before_data()
        self.pin()
        path = self.root / policy.composition.REPORTS['database']
        path.write_bytes(b'X' * path.stat().st_size)
        self.refused_before_data()

    def test_unknown_path_secret_authority_and_runtime_fields_refused_before_data(self):
        for key, value in (('root', '/'), ('path', '../source'), ('providerToken', 'canary'),
                           ('ports', [443]), ('image', 'source-live'), ('newOperationsAuthorized', True)):
            with self.subTest(key=key):
                self.record[key] = value
                self.pin(); self.refused_before_data()
                del self.record[key]
        for key, value in (('path', '../source.dump'), ('bytesOverride', 2), ('sha256Override', 'a' * 64)):
            with self.subTest(key=key):
                entry = self.record['artifacts']['application-postgres']
                entry[key] = value
                self.pin(); self.refused_before_data()
                del entry[key]

    def test_missing_extra_or_aliased_input_kinds_refused_before_data(self):
        baseline = copy.deepcopy(self.record)
        for kind in ('application-postgres', 'audit-immudb'):
            self.record = copy.deepcopy(baseline)
            del self.record['artifacts'][kind]
            self.pin(); self.refused_before_data()
        for kind in ('provider-raft', 'identity-postgres', 'pki', 'Application-postgres'):
            self.record = copy.deepcopy(baseline)
            self.record['artifacts'][kind] = baseline['artifacts']['application-postgres']
            self.pin(); self.refused_before_data()

    def test_invalid_typed_counts_and_both_memory_limits_refused_before_data(self):
        baseline = copy.deepcopy(self.record)
        for value in (True, 0, -1, 1.0, '12', policy.MAX_INPUT + 1):
            self.record = copy.deepcopy(baseline)
            self.record['artifacts']['application-postgres']['bytes'] = value
            self.pin(); self.refused_before_data()
        self.record = copy.deepcopy(baseline)
        for entry in self.record['artifacts'].values():
            entry['bytes'] = policy.MAX_INPUT
        self.pin(); self.refused_before_data()

    def test_digest_candidate_and_component_pin_shapes_refused_before_data(self):
        baseline = copy.deepcopy(self.record)
        mutations = [('candidateCommit', value) for value in (None, 'a' * 39, 'A' * 40, '0' * 40, '../source')]
        mutations += [(key, value) for key in ('candidateBuildSha256', 'componentManifestSha256')
                      for value in (None, 'a' * 63, 'g' * 64, 'A' * 64)]
        for key, value in mutations:
            with self.subTest(key=key, value=value):
                self.record = copy.deepcopy(baseline)
                self.record[key] = value
                self.pin(); self.refused_before_data()

    def test_rebased_manifest_cannot_select_a_different_dump_or_backup(self):
        baseline = copy.deepcopy(self.record)
        for kind in policy.INPUTS:
            self.record = copy.deepcopy(baseline)
            self.record['artifacts'][kind]['sha256'] = 'f' * 64
            self.pin(); self.refused_before_data()
        self.record = copy.deepcopy(baseline)
        self.record['artifacts']['audit-immudb']['bytes'] += 1
        self.pin(); self.refused_before_data()

    def test_metadata_scope_mutations_refused_before_data_even_with_new_pins(self):
        baseline = copy.deepcopy(self.reports)
        for kind, key, value in (('database', 'currentAuditEvents', 3), ('audit', 'transactions', 9),
                                  ('provider', 'permissionConsumed', False), ('configuration', 'servicesStarted', True),
                                  ('identity', 'fullSystemRecoveryVerified', True), ('audit', 'backupBytes', True)):
            self.reports = copy.deepcopy(baseline)
            self.reports[kind][key] = value
            self.pin_components(); self.refused_before_data()

    def test_hardlink_missing_directory_and_oversized_raw_inputs_are_refused(self):
        path = self.root / policy.INPUTS['application-postgres']
        alias = self.root / 'alias.dump'
        os.link(path, alias)
        with self.assertRaises(Exception):
            self.load()
        alias.unlink(); path.unlink()
        with self.assertRaises(Exception):
            self.load()
        path.mkdir()
        with self.assertRaises(Exception):
            self.load()
        path.rmdir()
        path.write_bytes(self.data['application-postgres'] + b'overflow')
        with self.assertRaises(Exception):
            self.load()

    def test_exact_byte_limits_are_accepted_without_reinterpreting_native_formats(self):
        self.data = {'application-postgres': b'P' * 512, 'audit-immudb': b'A' * 256}
        self.bind_data()
        with patch.object(policy, 'MAX_INPUT', 512), patch.object(policy, 'MAX_TOTAL', 768):
            capsule = self.load()
        self.assertEqual(capsule.result()['verifiedInputBytes'], 768)
        self.assertIs(capsule.result()['nativeBackupFormatsValidated'], False)

    def test_duplicate_json_invalid_utf8_and_unknown_schema_are_refused(self):
        for packet in (b'{"schema":"a","schema":"b"}', b'\xff', b'[]', b'{"bytes":NaN}', b'{}',
                       json.dumps(self.record).replace('"bytes":', '"bytes":1,"bytes":', 1).encode()):
            self.pin(packet); self.refused_before_data()

    def test_cli_has_no_root_path_data_kind_or_execution_switch(self):
        for extra in (('--root', str(self.root)), ('--manifest', '../secret'), ('--restore',),
                      ('--artifact', 'provider-raft'), ('--image', 'source-live')):
            self.assertEqual(self.cli(*extra).returncode, 2)


if __name__ == '__main__':
    unittest.main()
