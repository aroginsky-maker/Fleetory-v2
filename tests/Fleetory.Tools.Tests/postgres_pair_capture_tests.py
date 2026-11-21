"""Same fixed-purpose PG input path on synthetic files; no original inputs or native restore."""
import dataclasses
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'eng' / 'pilot'))
from historical import postgres_pair_capture as policy

H = policy.packet.digest


class PostgresPairCaptureTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='fleetory-pg-pair-capture-')
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        directory = 'coherent-postgres-' + '1' * 32
        self.data = [b'PGDMP_PRIVATE_SYNTHETIC_APP_VALUE', b'PGDMP_PRIVATE_SYNTHETIC_SIGNER_VALUE']
        refs = []
        self.paths = []
        for kind, name, data in zip(policy.KINDS, ('fleetory.dump', 'fleetory_signer.dump'), self.data):
            relative = directory + '/' + name
            path = self.root / relative
            path.parent.mkdir(exist_ok=True)
            path.write_bytes(data)
            self.paths.append(path)
            refs.append(policy.selection.ArtifactReference(kind, relative, len(data), H(data)))
        refs.append(policy.selection.ArtifactReference('audit-immudb', 'immudb-restore-' + '2' * 32 + '/backup.bin', 100, 'a' * 64))
        self.record = policy.selection.Selection(tuple(refs), tuple((name, char * 64) for name, char in
            (('audit', 'b'), ('database', 'c'), ('manifest', 'd')))).report()
        self.pin()

    def pin(self):
        self.raw = bytearray(json.dumps(self.record).encode())
        self.expected = H(self.raw)

    def capture(self):
        return policy.capture(self.root, self.raw, self.expected)

    def test_only_two_selected_files_open_with_unrelated_artifacts_absent(self):
        with patch.object(policy.files, 'inspect_file', wraps=policy.files.inspect_file) as observed, \
             patch.object(policy.files, 'verify', side_effect=AssertionError('Broad verifier forbidden')), \
             patch('subprocess.Popen', side_effect=AssertionError('Process forbidden')), \
             patch('socket.socket', side_effect=AssertionError('Socket forbidden')):
            result = self.capture()
        self.assertEqual(observed.call_count, 2)
        self.assertEqual([call.args[2] for call in observed.call_args_list], [str(p.relative_to(self.root)).replace('\\', '/') for p in self.paths])
        self.assertEqual([result.packet(kind) for kind in policy.KINDS], self.data)
        self.assertFalse(result.report()['otherArtifactsOpened'])
        self.assertFalse(result.report()['nativeRestorePerformed'])
        self.assertFalse(result.report()['executionAuthorized'])

    def test_frozen_metadata_and_bytes_survive_caller_and_path_replacement(self):
        original = policy.files.inspect_file
        def changed(*args, **kwargs):
            self.raw[:] = b'changed-untrusted-metadata'
            return original(*args, **kwargs)
        with patch.object(policy.files, 'inspect_file', side_effect=changed):
            result = self.capture()
        for path in self.paths:
            path.write_bytes(b'changed')
        self.assertEqual([result.packet(kind) for kind in policy.KINDS], self.data)
        self.assertEqual(result.selection_sha256, self.expected)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            result.signer = b'changed'
        for data in self.data:
            self.assertNotIn(data.decode(), repr(result))

    def test_promoted_scope_and_excluded_paths_fail_before_any_open(self):
        mutations = [('executionAuthorized', True), ('originalRawInputsOpened', True), ('extra', 'untrusted')]
        for key, value in mutations:
            original = self.record.copy()
            self.record[key] = value; self.pin()
            with self.subTest(field=key), patch.object(policy.files, 'inspect_file', side_effect=AssertionError('No open')) as observed:
                with self.assertRaises(ValueError):
                    self.capture()
                self.assertEqual(observed.call_count, 0)
            self.record = original
        self.record['selected'][1]['path'] = 'openbao/snapshot.snap'; self.pin()
        with patch.object(policy.files, 'inspect_file', side_effect=AssertionError('No open')) as observed:
            with self.assertRaises(ValueError):
                self.capture()
            self.assertEqual(observed.call_count, 0)

    def test_wrong_external_pin_and_pair_bound_fail_before_open(self):
        self.expected = '0' * 64
        with patch.object(policy.files, 'inspect_file', side_effect=AssertionError('No open')):
            with self.assertRaises(ValueError):
                self.capture()
        self.record['selected'][0]['bytes'] = policy.MAX_PAIR
        self.record['selectedBytes'] = sum(v['bytes'] for v in self.record['selected']); self.pin()
        with patch.object(policy.files, 'inspect_file', side_effect=AssertionError('No open')):
            with self.assertRaises(ValueError):
                self.capture()

    def test_corrupt_signer_returns_no_partial_capture(self):
        self.paths[1].write_bytes(self.data[1][:-1] + b'!')
        with self.assertRaises(ValueError):
            self.capture()
        self.assertEqual(self.paths[0].read_bytes(), self.data[0])

    def test_matching_digest_does_not_accept_non_custom_dump_magic(self):
        bad = b'NOTPG' + self.data[1][5:]
        self.paths[1].write_bytes(bad)
        self.record['selected'][1]['sha256'] = H(bad); self.pin()
        with self.assertRaises(ValueError):
            self.capture()

    def test_linked_signer_is_not_admitted(self):
        target = self.root / 'other.dump'; target.write_bytes(self.data[1])
        self.paths[1].unlink(); os.link(target, self.paths[1])
        with self.assertRaises(policy.files.archive.ArchiveError):
            self.capture()

    def test_cli_is_sanitized_and_has_no_root_or_extra_category_switch(self):
        command = [sys.executable, '-B', str(Path(policy.__file__)), '--expected-selection-sha256', self.expected]
        result = subprocess.run(command, input=self.raw, cwd=self.root, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0)
        self.assertFalse(result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report['verifiedArtifacts'], 2)
        self.assertFalse(report['nativeChecksumVerified'])
        self.assertFalse(report['databaseInventoryVerified'])
        for data in self.data:
            self.assertNotIn(data, result.stdout)
        for kind in ('audit-immudb', 'identity-postgres', 'provider-raft'):
            with self.assertRaises(ValueError):
                self.capture().packet(kind)
        refused = subprocess.run(command + ['--root', 'PRIVATE_SYNTHETIC_CANARY'], input=self.raw, cwd=self.root, capture_output=True, timeout=10)
        self.assertNotEqual(refused.returncode, 0)
        self.assertFalse(refused.stdout)
        self.assertNotIn(b'PRIVATE_SYNTHETIC_CANARY', refused.stderr)


if __name__ == '__main__':
    unittest.main(verbosity=2)
