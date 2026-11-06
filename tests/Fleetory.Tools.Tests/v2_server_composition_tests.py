"""Generated observations only; no original data, credentials or services."""
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
import v2_server_composition as policy

FIXTURE = '00000000-0000-4000-8000-000000000001'


def point():
    pg = {}
    for database, counts in policy.COUNTS.items():
        inv = dict(algorithm='fleetory.application-signer-recovery.v2', database=database,
                   inventorySha256='a' * 64, securitySha256='b' * 64, tableCount=len(counts),
                   totalRows=sum(counts.values()), sequenceCount=0, tableCounts=dict(counts),
                   audit=dict(snapshotSha256='c' * 64, events=4, pendingExportCount=0) if database == 'fleetory' else None,
                   rolePasswordsAndLoginRecoveryVerified=False, globalAtomicSnapshotClaimed=False)
        pg[database] = dict(schema='fleetory.native-pg-v2-readback.v1', inventory=inv,
                            additionalSecuritySha256='d' * 64, generatedRolePolicyAccepted=True,
                            nativeMeasurementAuthenticated=False, originalInputsVerified=False,
                            executionAuthorized=False, fullSystemRecoveryVerified=False)
    return dict(postgres=pg, audit=dict(database='fleetoryaudit', tx=5, txHash='E' * 64,
                keyFingerprint='F' * 64, historySha256='a' * 64, events=4, keys=5, transactions=5))


class CompositionTests(unittest.TestCase):
    def setUp(self):
        self.artifacts = {n: bytearray((b'IMMUBACKUP' if n == 'audit' else b'PGDMP') + b'x' * 100) for n in ('application', 'signer', 'audit')}
        self.source = point()
        self.manifest = dict(schema=policy.SCHEMA, scope=policy.history.SCOPE, fixture=FIXTURE,
            probeSha256='b' * 64, images=dict(postgres='sha256:' + 'c' * 64, audit='sha256:' + 'd' * 64),
            sourceContainers=dict(postgres='e' * 64, audit='f' * 64), point=self.source,
            capture=dict(before=copy.deepcopy(self.source), after=copy.deepcopy(self.source)),
            artifacts={n: dict(bytes=len(b), sha256=policy.packet.digest(b)) for n, b in self.artifacts.items()})

    def capture(self):
        data = json.dumps(self.manifest).encode()
        return policy.admit(data, policy.packet.digest(data), FIXTURE, self.artifacts)

    def target(self):
        value = copy.deepcopy(self.source)
        value['audit']['keyFingerprint'] = 'A' * 64
        return value

    def test_three_frozen_archives_survive_caller_replacement(self):
        result = self.capture()
        for name, value in self.artifacts.items():
            original = bytes(value)
            value[:] = b'replaced'
            self.assertEqual(getattr(result, name), original)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            result.signer = b'changed'

    def test_distinct_signers_with_exact_data_and_security(self):
        policy.compare(self.source, self.target())
        with self.assertRaises(policy.CompositionMismatch):
            policy.compare(self.source, self.source)

    def test_all_database_digests_and_role_policy_are_bound(self):
        for db in policy.COUNTS:
            for name in ('inventorySha256', 'securitySha256', 'additionalSecuritySha256', 'generatedRolePolicyAccepted'):
                target = self.target()
                pg = target['postgres'][db]
                if name in pg:
                    pg[name] = False if name == 'generatedRolePolicyAccepted' else '0' * 64
                else:
                    pg['inventory'][name] = '0' * 64
                with self.subTest(db=db, name=name), self.assertRaises(policy.CompositionMismatch):
                    policy.compare(self.source, target)

    def test_exact_audit_root_and_full_history_are_bound(self):
        for name in ('txHash', 'historySha256'):
            target = self.target()
            target['audit'][name] = '0' * 64
            with self.assertRaises(policy.CompositionMismatch):
                policy.compare(self.source, target)

    def test_mixed_capture_windows_and_stale_points(self):
        self.manifest['capture']['after']['postgres']['fleetory_signer']['inventory']['inventorySha256'] = '0' * 64
        with self.assertRaises(ValueError):
            self.capture()

    def test_missing_signer_placeholder_and_extra_approval_are_refused(self):
        for name in ('missing', 'placeholder', 'approval', 'legacy'):
            self.setUp()
            if name == 'missing':
                self.artifacts.pop('signer')
            elif name == 'placeholder':
                self.artifacts['signer'] = b'PLACEHOLDER' * 10
            elif name == 'approval':
                self.manifest['approved'] = True
            else:
                self.manifest['schema'] = 'fleetory.fresh-native-server-pair.v1'
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.capture()

    def test_type_confusion_is_malformed_not_a_data_mismatch(self):
        for key in ('totalRows', 'tableCount', 'sequenceCount'):
            target = self.target()
            target['postgres']['fleetory']['inventory'][key] = False
            with self.assertRaises(ValueError) as context:
                policy.compare(self.source, target)
            self.assertNotIsInstance(context.exception, policy.CompositionMismatch)

    def test_source_profile_cannot_be_relabelled_23_rows(self):
        self.source['postgres']['fleetory']['inventory']['tableCounts']['platform.authorization_assignments'] = 0
        self.source['postgres']['fleetory']['inventory']['totalRows'] = 23
        with self.assertRaises(ValueError):
            self.capture()

    def test_each_byte_pin_format_and_bound_is_enforced(self):
        for name in self.artifacts:
            self.setUp()
            self.artifacts[name][-1] ^= 1
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.capture()
        self.setUp()
        self.artifacts['audit'] = b'x' * (policy.packet.MAX_ARTIFACT + 1)
        with self.assertRaises(ValueError):
            self.capture()

    def test_pure_admission_has_no_file_process_or_socket_api(self):
        with patch('builtins.open', side_effect=AssertionError()), patch('subprocess.Popen', side_effect=AssertionError()), patch('socket.socket', side_effect=AssertionError()):
            self.capture()

    def cli(self, mode, body, extra=()):
        return subprocess.run([sys.executable, '-B', policy.__file__, mode, *extra], input=json.dumps(body).encode(), capture_output=True, timeout=5)

    def test_cli_separates_data_mismatch_from_process_or_packet_errors(self):
        body = dict(source=self.source, target=self.target())
        result = self.cli('compare', body)
        self.assertEqual(result.returncode, 0, result.stderr)
        body['target']['postgres']['fleetory_signer']['generatedRolePolicyAccepted'] = False
        result = self.cli('compare', body)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr, b'')
        self.assertEqual(json.loads(result.stdout)['category'], 'generated-composition-mismatch')
        for bad in (dict(body, CANARY_PRIVATE_VALUE='do-not-log'), dict(source=self.source, target=dict(self.target(), audit={})), dict(body, target=None)):
            result = self.cli('compare', bad)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout, b'')
            self.assertEqual(result.stderr.splitlines(), [b'Generated v2 composition refused; no contents logged.'])

    def test_cli_capture_returns_private_payload_without_authority(self):
        data = json.dumps(self.manifest).encode()
        body = dict(manifestBase64=base64.b64encode(data).decode(), **{n + 'Base64': base64.b64encode(v).decode() for n, v in self.artifacts.items()})
        result = self.cli('capture', body, ('--pin', policy.packet.digest(data), '--fixture', FIXTURE))
        self.assertEqual(result.returncode, 0, result.stderr)
        value = json.loads(result.stdout)
        for name in self.artifacts:
            self.assertEqual(base64.b64decode(value[name + 'Base64']), self.artifacts[name])
        for name in ('executionAuthorized', 'signaturesVerified', 'originalInputsVerified', 'fullSystemRecoveryVerified'):
            self.assertIs(value[name], False)


if __name__ == '__main__':
    unittest.main()
