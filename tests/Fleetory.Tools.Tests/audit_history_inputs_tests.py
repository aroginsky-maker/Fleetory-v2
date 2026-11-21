"""Synthetic capture/point contracts; no original material, files or services."""
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
import audit_history_inputs as policy

FIXTURE = '00000000-0000-4000-8000-000000000001'


def point():
    return dict(database='fleetoryaudit', tx=5, txHash='A' * 64, keyFingerprint='B' * 64,
                historySha256='c' * 64, events=4, keys=5, transactions=5)


class AuditHistoryInputsTests(unittest.TestCase):
    def setUp(self):
        self.backup = bytearray(b'IMMUBACKUP' + b'x' * 100)
        p = point()
        self.record = dict(schema=policy.SCHEMA, scope=policy.SCOPE, fixture=FIXTURE,
                           probeSha256='d' * 64, imageId='sha256:' + 'e' * 64, sourceContainer='f' * 64,
                           point=p, capture=dict(before=copy.deepcopy(p), after=copy.deepcopy(p)),
                           artifact=dict(bytes=len(self.backup), sha256=policy.packet.digest(self.backup)))
        self.pin()

    def pin(self):
        self.manifest = json.dumps(self.record).encode()
        self.expected = policy.packet.digest(self.manifest)

    def admit(self):
        return policy.admit(self.manifest, self.expected, FIXTURE, self.backup)

    def test_frozen_byte_capture_survives_caller_replacement(self):
        original = bytes(self.backup)
        result = self.admit()
        self.backup[:] = b'replaced'
        self.assertEqual(result.backup, original)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            result.backup = b'replaced'

    def test_same_data_with_distinct_signers(self):
        source, target = point(), point()
        target['keyFingerprint'] = 'D' * 64
        policy.same_data_distinct_signers(source, target)
        with self.assertRaises(policy.packet.PairError):
            policy.same_data_distinct_signers(source, source)

    def test_changed_target_fields_and_type_confusion_refused(self):
        for name in point():
            if name == 'keyFingerprint':
                continue
            target = point()
            target['keyFingerprint'] = 'D' * 64
            target[name] = 'wrong' if type(target[name]) is str else True
            with self.subTest(name=name), self.assertRaises(policy.packet.PairError):
                policy.same_data_distinct_signers(point(), target)

    def test_wrong_pin_fixture_artifact_and_code_identity(self):
        for field in ('fixture', 'probeSha256', 'imageId', 'sourceContainer'):
            self.setUp()
            self.record[field] = 'invalid'
            self.pin()
            with self.assertRaises((ValueError, TypeError)):
                self.admit()
        self.setUp()
        self.expected = '0' * 64
        with self.assertRaises(policy.packet.PairError):
            self.admit()

    def test_before_after_mixed_stale_and_signature_identity_drift(self):
        for name, value in (('tx', 4), ('keys', 4), ('events', 5), ('transactions', 6),
                            ('keyFingerprint', 'D' * 64), ('txHash', 'E' * 64),
                            ('historySha256', 'e' * 64), ('tx', 5.0)):
            self.setUp()
            self.record['capture']['after'][name] = value
            self.pin()
            with self.subTest(name=name), self.assertRaises(policy.packet.PairError):
                self.admit()

    def test_missing_extra_relabelled_original_and_placeholder_fields(self):
        for change in ('missing', 'extra', 'schema', 'scope', 'approval', 'placeholder'):
            self.setUp()
            if change == 'missing':
                self.record.pop('point')
            elif change == 'extra':
                self.record['path'] = 'C:/do-not-open'
            elif change == 'schema':
                self.record['schema'] = 'fleetory.fresh-native-server-pair.v1'
            elif change == 'scope':
                self.record['scope'] = 'original-approved'
            elif change == 'approval':
                self.record['approved'] = True
            else:
                self.record['postgres'] = 'PLACEHOLDER'
            self.pin()
            with self.assertRaises(policy.packet.PairError):
                self.admit()

    def test_changed_bytes_length_digest_and_native_magic(self):
        for change in ('byte', 'length', 'digest', 'magic', 'boolean'):
            self.setUp()
            if change == 'byte':
                self.backup[-1] ^= 1
            elif change == 'length':
                self.record['artifact']['bytes'] += 1
            elif change == 'digest':
                self.record['artifact']['sha256'] = '0' * 64
            elif change == 'magic':
                self.backup[0] = 0
                self.record['artifact']['sha256'] = policy.packet.digest(self.backup)
            else:
                self.record['artifact']['bytes'] = True
            self.pin()
            with self.assertRaises(policy.packet.PairError):
                self.admit()

    def test_boundary_and_empty_packets(self):
        for value in (b'', b'IMMUBACKUP', b'x' * (policy.packet.MAX_ARTIFACT + 1), 'not-bytes'):
            self.setUp()
            self.backup = value
            with self.assertRaises(policy.packet.PairError):
                self.admit()
        self.setUp()
        self.manifest = b'x' * (policy.packet.MAX_MANIFEST + 1)
        self.expected = policy.packet.digest(self.manifest)
        with self.assertRaises(policy.packet.PairError):
            self.admit()

    def test_duplicate_nonfinite_invalid_utf8_and_trailing_json(self):
        for data in (b'{"x":1,"x":2}', b'{"x":NaN}', b'\xff', b'{}{}'):
            self.manifest = data
            self.expected = policy.packet.digest(data)
            with self.assertRaises(ValueError):
                self.admit()

    def test_no_file_process_or_socket_api(self):
        with patch('builtins.open', side_effect=AssertionError()), patch('subprocess.Popen', side_effect=AssertionError()), patch('socket.socket', side_effect=AssertionError()):
            self.assertEqual(self.admit().fixture, FIXTURE)

    def test_cli_comparison_has_no_signature_or_authority_claim(self):
        source, target = point(), point()
        target['keyFingerprint'] = 'D' * 64
        command = [sys.executable, '-B', policy.__file__, 'compare']
        body = dict(source=source, target=target)
        result = subprocess.run(command, input=json.dumps(body).encode(), capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        value = json.loads(result.stdout)
        self.assertIs(value['sameDataDistinctSigners'], True)
        for name in ('signaturesVerified', 'originalKeyContinuityVerified', 'executionAuthorized'):
            self.assertIs(value[name], False)
        for arguments, packet in ((['--pin', self.expected], body), ([], dict(source=source, target=source)),
                                  ([], dict(body, approved=True)), ([], dict(body, target=dict(target, tx=True)))):
            result = subprocess.run(command + arguments, input=json.dumps(packet).encode(), capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stdout, b'')
            self.assertEqual(result.stderr.splitlines(), [b'Audit history capture refused; no packet contents logged.'])

    def test_cli_payload_is_private_and_errors_canary_safe(self):
        body = dict(manifestBase64=base64.b64encode(self.manifest).decode(), backupBase64=base64.b64encode(self.backup).decode())
        command = [sys.executable, '-B', policy.__file__, '--pin', self.expected, '--fixture', FIXTURE]
        result = subprocess.run(command, input=json.dumps(body).encode(), capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        value = json.loads(result.stdout)
        self.assertEqual(base64.b64decode(value['backupBase64']), self.backup)
        for name in ('executionAuthorized', 'signaturesVerified', 'nativeChecksumVerified', 'originalKeyContinuityVerified', 'fullSystemRecoveryVerified'):
            self.assertIs(value[name], False)
        for data in (b'{"CANARY_PRIVATE_PACKET":NaN}', b' ' * (policy.MAX_BODY + 1)):
            result = subprocess.run(command, input=data, capture_output=True, timeout=5)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, b'')
            self.assertEqual(result.stderr.splitlines(), [b'Audit history capture refused; no packet contents logged.'])


if __name__ == '__main__':
    unittest.main()
