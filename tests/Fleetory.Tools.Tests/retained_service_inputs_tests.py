"""Four generated retained inputs through the integration path; no native services or originals."""
import base64
import copy
import dataclasses
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'eng' / 'pilot'))
from historical import retained_service_inputs as policy
import audit_expectation_source_tests as source_tests

H = policy.packet.digest


class RetainedServiceInputsTests(unittest.TestCase):
    def setUp(self):
        self.source = source_tests.AuditExpectationSourceTests('runTest')
        self.source.setUp()
        self.addCleanup(self.source.doCleanups)
        self.root = self.source.root
        self.data = dict(zip(policy.KINDS[:3], (b'PGDMP_SYNTHETIC_APP', b'PGDMP_SYNTHETIC_SIGNER',
            b'IMMUBACKUP' + b'PRIVATE_SYNTHETIC_AUDIT' * 4)))
        relatives = ('coherent-postgres-' + '2' * 32 + '/fleetory.dump',
            'coherent-postgres-' + '2' * 32 + '/fleetory_signer.dump',
            'immudb-restore-' + '3' * 32 + '/backup.bin')
        refs = []
        for (kind, data), relative in zip(self.data.items(), relatives):
            path = self.root / relative
            path.parent.mkdir(exist_ok=True)
            path.write_bytes(data)
            entry = dict(path=relative, bytes=len(data), sha256=H(data))
            self.source.manifest['artifacts'][kind] = entry
            refs.append(policy.selection.ArtifactReference(kind=kind, **entry))
        self.source.pin()
        self.record = policy.selection.Selection(tuple(refs),
            (('audit', 'a' * 64), ('database', 'b' * 64), ('manifest', self.source.pins['manifest']))).report()
        self.pin()

    def pin(self):
        self.raw = bytearray(json.dumps(self.record).encode())
        self.pin_value = H(self.raw)

    def capture(self):
        return policy.capture(self.root, self.raw, self.pin_value,
            self.source.metadata, self.source.pins, source_tests.NONCE)

    def before_open_refusal(self):
        with patch.object(policy.files, 'inspect_file', side_effect=AssertionError('Artifact opened')) as observed:
            with self.assertRaises((ValueError, policy.files.archive.ArchiveError)):
                self.capture()
            self.assertEqual(observed.call_count, 0)

    def test_exact_four_opens_and_frozen_packets_without_excluded_categories(self):
        with patch.object(policy.files, 'inspect_file', wraps=policy.files.inspect_file) as observed, \
             patch.object(policy.files, 'verify', side_effect=AssertionError('Broad verifier')), \
             patch('subprocess.Popen', side_effect=AssertionError('Process')), \
             patch('socket.socket', side_effect=AssertionError('Socket')):
            result = self.capture()
        expected_paths = [item['path'] for item in self.record['selected']] + [self.source.relative]
        self.assertEqual([call.args[2] for call in observed.call_args_list], expected_paths)
        for kind, data in self.data.items():
            self.assertEqual(result.packet(kind), data)
        self.assertEqual(result.packet('audit-export'), policy.expectations.archive.canonical(self.source.snapshot))
        self.assertEqual(result.report()['verifiedArtifacts'], 4)
        self.assertEqual(result.report()['verifiedInputBytes'], sum(map(len, self.data.values())) + len(self.source.data))
        for key in ('nativeRestorePerformed', 'databaseInventoryVerified', 'originalServiceStarted',
                    'providerOrIdentityRead', 'executionAuthorized', 'fullSystemRecoveryVerified', 'phase7Complete'):
            self.assertIs(result.report()[key], False)
        for kind in ('identity-postgres', 'provider-raft', 'anything'):
            with self.assertRaises(ValueError):
                result.packet(kind)

    def test_all_caller_metadata_and_pins_frozen_before_first_parse(self):
        original = policy.packet.strict_json
        def mutate(*args):
            self.raw[:] = b'changed'
            for raw in self.source.metadata.values():
                raw[:] = b'changed'
            self.source.pins.clear()
            return original(*args)
        with patch.object(policy.packet, 'strict_json', side_effect=mutate):
            result = self.capture()
        self.assertEqual(result.packet('application-postgres'), self.data['application-postgres'])
        self.assertEqual(result.packet('audit-export'), policy.expectations.archive.canonical(self.source.snapshot))

    def test_replaced_paths_and_metadata_cannot_change_result_or_leak_repr(self):
        result = self.capture()
        for item in self.record['selected']:
            (self.root / item['path']).write_bytes(b'changed')
        self.source.path.write_bytes(b'changed')
        for kind, data in self.data.items():
            self.assertEqual(result.packet(kind), data)
            self.assertNotIn(data.decode(), repr(result))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            result.nonce = 'changed'

    def test_mismatched_manifest_pin_refused_before_any_open(self):
        self.record['metadataPins']['manifest'] = '0' * 64
        self.pin()
        self.before_open_refusal()

    def test_consistent_selection_pin_cannot_substitute_manifest_reference(self):
        self.record['selected'][0]['sha256'] = 'c' * 64
        self.pin()
        self.before_open_refusal()

    def test_invalid_export_metadata_and_path_refused_before_postgres_open(self):
        original = copy.deepcopy(self.source.checkpoint)
        for field, value in (('artifactPath', str(self.root.parent / 'PRIVATE_OTHER_ROOT' / 'export.json')),
                             ('eventCount', 5), ('extra', 'PRIVATE_CANARY')):
            with self.subTest(field=field):
                self.source.checkpoint = dict(original, **{field: value})
                self.source.pin()
                self.before_open_refusal()

    def test_late_corrupt_archive_or_export_never_returns_partial_bundle(self):
        audit_path = self.root / self.record['selected'][2]['path']
        audit_path.write_bytes(b'changed')
        with self.assertRaises(ValueError):
            self.capture()
        audit_path.write_bytes(self.data['audit-immudb'])
        self.source.path.write_bytes(b'changed')
        with self.assertRaises(ValueError):
            self.capture()

    def test_combined_bound_refused_before_any_artifact_open(self):
        first = self.record['selected'][0]
        first['bytes'] = policy.MAX_TOTAL - self.record['selected'][1]['bytes']
        self.source.manifest['artifacts']['application-postgres']['bytes'] = first['bytes']
        self.source.pin()
        self.record['metadataPins']['manifest'] = self.source.pins['manifest']
        self.record['selectedBytes'] = sum(item['bytes'] for item in self.record['selected'])
        self.pin()
        self.before_open_refusal()

    def test_cli_sanitized_and_excluded_option_refused(self):
        body = dict(selection=base64.b64encode(self.raw).decode(),
            **{name: base64.b64encode(raw).decode() for name, raw in self.source.metadata.items()})
        command = [sys.executable, '-B', str(Path(policy.__file__)), '--selection-sha256', self.pin_value,
            '--manifest-sha256', self.source.pins['manifest'], '--checkpoint-sha256',
            self.source.pins['checkpoint'], '--nonce', source_tests.NONCE]
        raw = json.dumps(body).encode()
        reply = subprocess.run(command, input=raw, cwd=self.root, capture_output=True, timeout=10)
        self.assertEqual(reply.returncode, 0, reply.stderr)
        self.assertEqual(json.loads(reply.stdout)['verifiedArtifacts'], 4)
        for data in self.data.values():
            self.assertNotIn(data, reply.stdout + reply.stderr)
        denied = subprocess.run(command + ['--provider', 'PRIVATE_CANARY'], input=raw,
            cwd=self.root, capture_output=True, timeout=10)
        self.assertNotEqual(denied.returncode, 0)
        self.assertFalse(denied.stdout)
        self.assertNotIn(b'PRIVATE_CANARY', denied.stderr)


if __name__ == '__main__':
    unittest.main(verbosity=2)
