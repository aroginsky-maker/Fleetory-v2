"""Generated source exports and pinned metadata only. Original data is never a fixture."""
import base64
import argparse
import copy
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
import audit_expectation_source as policy
import audit_event_expectations_tests as native

NONCE = native.NONCE
H = policy.packet.digest
B = lambda data: base64.b64encode(data).decode()


class AuditExpectationSourceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='fleetory-pg-expectation-source-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.relative = 'audit-archive-20260101T000000Z-' + '1' * 32 + '/export.json'
        self.path = self.root / self.relative
        self.path.parent.mkdir()
        self.snapshot = native.snapshot()
        receipt = dict(schema='fleetory.audit-archive-receipt.v1', sequence=1, capturedAt='2026-01-01T00:00:00.000000Z',
            snapshotSha256=policy.archive.digest(self.snapshot), previousReceiptSha256='0' * 64)
        self.export = dict(schema='fleetory.audit-archive-export.v1', receipts=[receipt], snapshot=self.snapshot)
        self.data = policy.archive.canonical(self.export)
        self.path.write_bytes(self.data)
        entries = {kind: dict(path=f'other-{index}/backup.bin', bytes=100 + index, sha256=str(index + 1) * 64)
                   for index, kind in enumerate(sorted(policy.files.KINDS))}
        entries['audit-export'] = dict(path=self.relative, bytes=len(self.data), sha256=H(self.data))
        self.manifest = dict(schema=policy.files.SCHEMA, artifacts=entries)
        self.checkpoint = dict(source='Synthetic PostgreSQL periodic export declaration', artifactPath=str(self.path),
            exportSha256=H(self.data), bytes=len(self.data), snapshotCount=1, eventCount=4,
            lastReceiptSha256=policy.archive.digest(receipt), portableVerification='PASS', isolatedFileRestore='PASS',
            checkpointVerified=True, tamperedRestoreRejected=True, independentCustodyVerified=False,
            administratorTamperProof=False, fullSystemRecoveryVerified=False, verifiedAtUtc='2026-01-01T00:00:01+00:00')
        self.pin()

    def pin(self):
        self.metadata = {name: bytearray(json.dumps(value).encode()) for name, value in
                         (('manifest', self.manifest), ('checkpoint', self.checkpoint))}
        self.pins = {name: H(data) for name, data in self.metadata.items()}

    def republish(self):
        self.export['receipts'][-1]['snapshotSha256'] = policy.archive.digest(self.export['snapshot'])
        self.data = policy.archive.canonical(self.export)
        self.path.write_bytes(self.data)
        self.manifest['artifacts']['audit-export'].update(bytes=len(self.data), sha256=H(self.data))
        self.checkpoint.update(bytes=len(self.data), exportSha256=H(self.data),
                               lastReceiptSha256=policy.archive.digest(self.export['receipts'][-1]))
        self.pin()

    def capture(self):
        return policy.capture(self.root, self.metadata, self.pins, NONCE)

    def refused(self):
        with self.assertRaises((ValueError, TypeError, KeyError, OSError, policy.archive.ArchiveError)):
            self.capture()

    def cli(self, extra=()):
        body = {name: B(data) for name, data in self.metadata.items()}
        return subprocess.run([sys.executable, '-B', str(Path(policy.__file__)), '--manifest-sha256', self.pins['manifest'],
            '--checkpoint-sha256', self.pins['checkpoint'], '--nonce', NONCE, *extra], input=json.dumps(body).encode(),
            cwd=self.root, capture_output=True, timeout=10)

    def test_exactly_one_source_open_and_no_native_or_broad_apis(self):
        with patch.object(policy.files, 'inspect_file', wraps=policy.files.inspect_file) as observed, \
             patch.object(policy.files, 'verify', side_effect=AssertionError('Broad verifier forbidden')), \
             patch.object(policy.archive, 'capture', side_effect=AssertionError('Source VPS forbidden')), \
             patch('subprocess.Popen', side_effect=AssertionError('Process forbidden')), \
             patch('socket.socket', side_effect=AssertionError('Socket forbidden')):
            result = self.capture()
        self.assertEqual(observed.call_count, 1)
        self.assertEqual(observed.call_args.args[2:], (self.relative, len(self.data)))
        self.assertEqual(result.snapshot, policy.archive.canonical(self.snapshot))
        self.assertEqual(result.report()['verifiedArtifacts'], 1)

    def test_immutable_source_survives_file_and_caller_replacement(self):
        result = self.capture()
        expected = result.snapshot
        self.path.write_bytes(b'changed')
        for data in self.metadata.values():
            data[:] = b'changed'
        self.pins.clear()
        self.assertEqual(result.snapshot, expected)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            result.snapshot = b'changed'

    def test_all_buffers_and_pins_frozen_before_parsing(self):
        parser = policy.packet.strict_json
        def interleaved(data, bound):
            for buffer in self.metadata.values():
                buffer[:] = b'changed'
            self.pins.clear()
            return parser(data, bound)
        with patch.object(policy.packet, 'strict_json', side_effect=interleaved):
            self.assertEqual(self.capture().snapshot, policy.archive.canonical(self.snapshot))

    def test_wrong_stale_and_malformed_metadata_before_file_access(self):
        original = copy.deepcopy(self.metadata)
        for data in (b'', b'{', b'{"x":NaN}', b'{"x":1,"x":2}', b'\xff', b' ' * (policy.MAX_METADATA + 1)):
            self.metadata = copy.deepcopy(original)
            self.metadata['manifest'] = data
            self.pins['manifest'] = H(data)
            with patch.object(policy.files, 'rooted', side_effect=AssertionError('Filesystem reached')):
                self.refused()
        self.metadata = original
        self.pins['manifest'] = '0' * 64
        self.refused()

    def test_excluded_reference_relabelling_and_path_escape_refused(self):
        original = copy.deepcopy(self.manifest)
        for path in ('../outside', '/absolute', 'C:/private', r'a\b', 'a/../b', 'a:b', 'CON',
                     'keycloak/backup.bin', 'openbao/snapshot.snap', 'native/backup.bin', self.relative + '.'):
            self.manifest = copy.deepcopy(original)
            self.manifest['artifacts']['audit-export']['path'] = path
            self.pin()
            with patch.object(policy.files, 'inspect_file', side_effect=AssertionError('File reached')):
                self.refused()
        self.manifest = copy.deepcopy(original)
        self.manifest['artifacts'].pop('identity-postgres')
        self.pin(); self.refused()

    def test_absolute_checkpoint_path_only_compared_never_followed(self):
        self.checkpoint['artifactPath'] = str(self.root.parent / 'PRIVATE_PATH_CANARY')
        self.pin()
        with patch.object(policy.files, 'inspect_file', side_effect=AssertionError('File reached')):
            self.refused()

    def test_checkpoint_scope_types_and_promoted_readiness_refused(self):
        original = copy.deepcopy(self.checkpoint)
        for field, value in (('bytes', True), ('snapshotCount', True), ('eventCount', 3), ('eventCount', 4.0),
                            ('checkpointVerified', 1), ('tamperedRestoreRejected', False), ('portableVerification', 'SKIP'),
                            ('isolatedFileRestore', 'FAIL'), ('independentCustodyVerified', True),
                            ('administratorTamperProof', 0), ('fullSystemRecoveryVerified', True), ('lastReceiptSha256', 'A' * 64),
                            ('exportSha256', '0' * 64), ('approved', True)):
            self.checkpoint = copy.deepcopy(original)
            self.checkpoint[field] = value
            self.pin()
            with self.subTest(field=field), patch.object(policy.files, 'inspect_file', side_effect=AssertionError('File reached')):
                self.refused()

    def test_changed_empty_stale_and_oversized_source(self):
        for data in (b'', b'x' + self.data[1:], b'older-three-events', self.data + b'x'):
            self.path.write_bytes(data)
            self.refused()

    def test_broken_receipt_binding_and_chain_refused(self):
        for field, value in (('sequence', True), ('previousReceiptSha256', 'f' * 64), ('snapshotSha256', 'e' * 64),
                            ('capturedAt', '2026-01-01T00:00:00Z')):
            saved = copy.deepcopy(self.export)
            self.export['receipts'][0][field] = value
            self.data = policy.archive.canonical(self.export)
            self.path.write_bytes(self.data)
            self.manifest['artifacts']['audit-export'].update(bytes=len(self.data), sha256=H(self.data))
            self.checkpoint.update(bytes=len(self.data), exportSha256=H(self.data))
            self.pin(); self.refused()
            self.export = saved
        self.republish()
        self.checkpoint['lastReceiptSha256'] = '0' * 64
        self.pin(); self.refused()

    def test_snapshot_schema_count_order_duplicates_and_pending_refused(self):
        original = copy.deepcopy(self.export)
        for change in ('schema', 'missing-event', 'duplicate', 'order', 'pending', 'pending-bool', 'field-missing'):
            self.export = copy.deepcopy(original)
            snap = self.export['snapshot']
            if change == 'schema':
                snap['schema'] = 'fleetory.audit-native-observation.v1'
            elif change == 'missing-event':
                snap['events'].pop()
            elif change == 'duplicate':
                snap['events'][1] = copy.deepcopy(snap['events'][0])
            elif change == 'order':
                snap['events'].reverse()
            elif change == 'pending':
                snap['pendingExportCount'] = 1
            elif change == 'pending-bool':
                snap['pendingExportCount'] = False
            else:
                snap['events'][0].pop('action')
            self.republish(); self.refused()

    def test_cross_scope_size_and_source_bounds(self):
        self.manifest['artifacts']['audit-export']['bytes'] = policy.MAX_EXPORT + 1
        self.checkpoint['bytes'] = policy.MAX_EXPORT + 1
        self.pin(); self.refused()
        self.setUp()
        self.export['snapshot']['events'][0]['context_json'] = json.dumps({'A': 'x' * policy.MAX_SNAPSHOT})
        self.republish(); self.refused()

    def test_hardlink_leaf_and_directory_link_refused(self):
        other = self.root / 'unrelated'
        self.path.rename(other)
        os.link(other, self.path)
        self.refused()
        self.path.unlink()
        self.path.mkdir()
        self.refused()
        self.path.rmdir()
        if os.name == 'posix':
            self.path.symlink_to(other)
        else:
            other.unlink(); other.mkdir()
            r = subprocess.run(['cmd.exe', '/d', '/c', 'mklink', '/J', str(self.path), str(other)], capture_output=True, timeout=5)
            self.assertEqual(r.returncode, 0)
        self.refused()

    def test_replacement_at_actual_open_and_wrong_root_descriptor_refused(self):
        original = policy.files.relative_open
        def swapped(root, descriptor, path):
            self.path.unlink(); self.path.mkdir()
            return original(root, descriptor, path)
        with patch.object(policy.files, 'relative_open', side_effect=swapped):
            self.refused()
        self.path.rmdir(); self.path.write_bytes(self.data)
        from contextlib import contextmanager
        rooted = policy.files.rooted
        with tempfile.TemporaryDirectory(prefix='fleetory-other-source-') as other, rooted(other) as (_, fd):
            @contextmanager
            def borrowed(root):
                with rooted(root) as (directory, _):
                    yield directory, 0 if os.name == 'nt' else fd
            with patch.object(policy.files, 'rooted', borrowed):
                self.refused()

    def test_cli_receipt_never_emits_events_paths_or_authority(self):
        result = self.cli()
        self.assertEqual(result.returncode, 0, result.stderr)
        value = json.loads(result.stdout)
        self.assertEqual(value['events'], 4)
        self.assertEqual(value['snapshotSha256'], H(policy.archive.canonical(self.snapshot)))
        for name in ('otherArtifactsOpened', 'nativeSelectionBroadened', 'sourceOriginAuthenticated', 'sourceIndependenceAuthenticated',
                     'signaturesVerified', 'independentCustodyVerified', 'administratorTamperProof', 'executionAuthorized',
                     'fullSystemRecoveryVerified', 'phase7Complete'):
            self.assertIs(value[name], False)
        for text in ('Actor1', 'Correlation1', str(self.root), self.relative):
            self.assertNotIn(text.encode(), result.stdout + result.stderr)
        failed = self.cli(('--root', 'PRIVATE_PATH_CANARY'))
        self.assertEqual(failed.returncode, 1)
        self.assertEqual(failed.stdout, b'')
        self.assertNotIn(b'PRIVATE_PATH_CANARY', failed.stderr)

    def test_direct_extract_enforces_nonce_and_bounded_bytes(self):
        plan = policy.source_plan(self.metadata, self.pins)
        with self.assertRaises(ValueError):
            policy.extract(self.data, plan, 'invalid')
        altered = dataclasses.replace(plan, artifact=dataclasses.replace(plan.artifact, bytes=policy.MAX_EXPORT + 1))
        with self.assertRaises(ValueError):
            policy.extract(b' ' * (policy.MAX_EXPORT + 1), altered, NONCE)


def integration(probe):
    case = AuditExpectationSourceTests('test_exactly_one_source_open_and_no_native_or_broad_apis')
    case.setUp()
    root = case.root
    try:
        captured = case.capture()
        result = subprocess.run(['dotnet', str(probe), 'audit-expectations', H(captured.snapshot), NONCE],
            input=captured.snapshot, capture_output=True, timeout=25)
        case.assertEqual(result.returncode, 0, 'Generated native source integration failed.')
        case.assertEqual(result.stderr, b'')
        value = json.loads(result.stdout)
        case.assertEqual(value['snapshotSha256'], H(captured.snapshot))
        case.assertEqual(value['nonce'], NONCE)
        case.assertEqual(len(value['knownEvents']), 4)
        for row, known in zip(case.snapshot['events'], value['knownEvents']):
            expected = json.dumps(native.wire(row), ensure_ascii=True, separators=(',', ':')).encode()
            case.assertEqual(known['valueSha256'], H(expected))
        case.assertIs(value['realBackendContacted'], False)
        case.assertIs(value['sourceOriginAuthenticated'], False)
    finally:
        case.doCleanups()
    case.assertFalse(root.exists())
    return dict(schema='fleetory.generated-expectation-source-integration.v1', verified=True, events=4, eventFields=10,
        sourceArtifactsOpened=1, productionGoldenValuesMatched=True, cleanupVerified=True, realBackendContacted=False,
        originalInputsRead=False, sourceVpsAccessed=False, sourceOriginAuthenticated=False, executionAuthorized=False,
        fullSystemRecoveryVerified=False, phase7Complete=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--integration-probe')
    arguments, remaining = parser.parse_known_args()
    if arguments.integration_probe:
        if remaining:
            raise SystemExit('Unexpected integration arguments.')
        probe = Path(arguments.integration_probe).resolve(strict=True)
        if probe.name != 'ServerBackendProbe.dll':
            raise SystemExit('Unexpected source integration probe.')
        print(json.dumps(integration(probe), sort_keys=True))
    else:
        unittest.main(argv=[sys.argv[0], *remaining])
