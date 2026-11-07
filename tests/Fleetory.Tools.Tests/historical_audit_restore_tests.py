"""Generated controller packets only; no original files, keys or native backend."""
import base64
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

import historical_audit_observation_tests as vectors
import historical_audit_restore as policy

H = policy.packet.digest
B = lambda data: base64.b64encode(data).decode('ascii')
C = policy.history.core.canonical


def fixture():
    vector = vectors.HistoricalObservationTests()
    vector.setUp()
    parts = dict(archive=b'IMMUBACKUP' + b'a' * 54, values=C(vector.source), state=C(vector.observed['stateBefore']),
        publicKey=b'-----BEGIN PUBLIC KEY-----\nAQ==\n-----END PUBLIC KEY-----')
    declared = dict(schema=policy.SCHEMA, purpose=policy.PURPOSE, nonce=vectors.NONCE, revision='a' * 40,
        codeSha256='b' * 64, probeSha256='c' * 64, probeBundleSha256='f' * 64, ciEvidenceSha256='d' * 64, localEvidenceSha256='e' * 64,
        inputs=dict(archiveBytes=len(parts['archive']), **{name + 'Sha256': H(value) for name, value in parts.items()}),
        scope=dict(historicalComparisonOnly=True, **{name: False for name in policy.FALSE_FLAGS}),
        limits=dict(nativeSeconds=600, containerSeconds=660, maximumArchiveBytes=65536, maximumPacketBytes=131072))
    return declared, parts


class HistoricalRestoreInputTests(unittest.TestCase):
    def setUp(self):
        self.plan, self.parts = fixture()

    def body(self):
        raw = C(self.plan)
        return C(dict(schema=policy.PACKET, planBase64=B(raw), **{name + 'Base64': B(value) for name, value in self.parts.items()})), H(raw)

    def admit(self):
        return policy.admit(*self.body())

    def repin(self, name, value):
        self.parts[name] = C(value) if isinstance(value, dict) else value
        self.plan['inputs'][name + 'Sha256'] = H(self.parts[name])

    def refused(self):
        with self.assertRaises((ValueError, KeyError, TypeError)):
            self.admit()

    def test_bound_historical_input_does_not_authenticate_gates_or_signatures(self):
        value = self.admit()
        self.assertEqual((value['knownEvents'], value['nullContextMembers'], value['archiveBytes']), (4, 1, 64))
        self.assertTrue(value['inputDigestsMatched'])
        self.assertTrue(value['historicalComparisonOnly'])
        for name in ('signaturesVerified', 'externalGatesAuthenticated', 'executionAuthorized', 'sourceFileOpened', 'phase7Complete'):
            self.assertIs(value[name], False)

    def test_unknown_packet_or_plan_fields_refused(self):
        body, pin = self.body()
        changed = json.loads(body)
        changed['path'] = 'PRIVATE_INPUT_CANARY'
        with self.assertRaises(ValueError):
            policy.admit(C(changed), pin)
        self.plan['root'] = 'PRIVATE_INPUT_CANARY'
        self.refused()

    def test_stale_external_plan_pin_cannot_be_replaced_by_packet(self):
        body, _ = self.body()
        with self.assertRaises(ValueError):
            policy.admit(body, '0' * 64)

    def test_nonce_revision_and_purpose_closed(self):
        for name, value in (('nonce', 'wrong'), ('revision', 'A' * 40), ('purpose', 'restore-and-start'), ('schema', 'strict')):
            self.setUp()
            self.plan[name] = value
            self.refused()

    def test_archive_count_header_and_digest_are_independent(self):
        for change in ('count', 'header', 'digest'):
            self.setUp()
            if change == 'count':
                self.plan['inputs']['archiveBytes'] += 1
            elif change == 'header':
                self.repin('archive', b'x' * 64)
            else:
                self.parts['archive'] += b'x'
            self.refused()

    def test_all_component_pins_are_required(self):
        for name in self.parts:
            self.setUp()
            self.plan['inputs'][name + 'Sha256'] = '0' * 64
            self.refused()

    def test_v1_or_missing_or_malformed_probe_bundle_pin_is_refused(self):
        for change in ('v1', 'missing', 'wrong-type', 'bad-hash'):
            self.setUp()
            if change == 'v1':
                self.plan['schema'] = 'fleetory.historical-audit-restore-plan.v1'
            elif change == 'missing':
                self.plan.pop('probeBundleSha256')
            else:
                self.plan['probeBundleSha256'] = 42 if change == 'wrong-type' else 'z' * 64
            self.refused()

    def test_scope_authority_true_or_numeric_false_refused(self):
        for name in policy.FALSE_FLAGS:
            for value in (True, 0):
                self.setUp()
                self.plan['scope'][name] = value
                self.refused()
        self.setUp()
        self.plan['scope']['historicalComparisonOnly'] = 1
        self.refused()

    def test_limits_cannot_be_widened_rounded_or_boolean(self):
        for name, expected in self.plan['limits'].items():
            for value in (expected + 1, float(expected), True):
                self.setUp()
                self.plan['limits'][name] = value
                self.refused()

    def test_historical_source_cannot_be_promoted_to_strict(self):
        for name, value in (('writerAdmissionVerified', True), ('nullContextMembersPreserved', 0), ('schema', 'fleetory.audit-event-expectations.v1')):
            self.setUp()
            values = json.loads(self.parts['values'])
            values[name] = value
            self.repin('values', values)
            self.refused()

    def test_four_known_values_remain_bounded_and_ordered(self):
        for mutation in ('missing', 'order', 'hash'):
            self.setUp()
            values = json.loads(self.parts['values'])
            if mutation == 'missing':
                values['knownEvents'].pop()
            elif mutation == 'order':
                values['knownEvents'].reverse()
            else:
                values['knownEvents'][0]['valueSha256'] = 'wrong'
            self.repin('values', values)
            self.refused()

    def test_state_point_and_precommit_must_match_fixed_database(self):
        for name, value in (('db', 'defaultdb'), ('txId', '4'), ('precommittedTxHash', B(b'x' * 32)), ('txHash', B(b'x' * 31))):
            self.setUp()
            state = json.loads(self.parts['state'])
            state[name] = value
            self.repin('state', state)
            self.refused()

    def test_private_or_multiple_public_pem_blocks_refused(self):
        for value in (self.parts['publicKey'] * 2, b'-----BEGIN PRIVATE KEY-----\nAQ==\n-----END PRIVATE KEY-----', b'x' * 1025):
            self.setUp()
            self.repin('publicKey', value)
            self.refused()

    def test_duplicate_fields_and_nonfinite_json_refused(self):
        body, pin = self.body()
        raw = body.replace(b'"schema":', b'"schema":"duplicate","schema":', 1)
        with self.assertRaises(ValueError):
            policy.admit(raw, pin)
        self.repin('values', b'{"invalid":NaN}')
        self.refused()

    def test_entire_external_buffer_frozen_before_parser_callback(self):
        body, pin = self.body()
        mutable = bytearray(body)
        parser = policy.packet.strict_json
        def mutate(data, bound):
            mutable[:] = b'changed'
            return parser(data, bound)
        with patch.object(policy.packet, 'strict_json', side_effect=mutate):
            self.assertTrue(policy.admit(mutable, pin)['frozenPacket'])

    def test_decoder_opens_no_files_processes_or_sockets(self):
        with patch('builtins.open', side_effect=AssertionError('File forbidden')), patch('subprocess.Popen', side_effect=AssertionError('Process forbidden')), patch('socket.socket', side_effect=AssertionError('Socket forbidden')):
            self.assertTrue(self.admit()['inputDigestsMatched'])

    def test_maximum_archive_and_packet_bounds_are_actual_byte_bounds(self):
        self.repin('archive', b'IMMUBACKUP' + b'x' * (policy.MAX_ARCHIVE - 10))
        self.plan['inputs']['archiveBytes'] = policy.MAX_ARCHIVE
        self.assertEqual(self.admit()['archiveBytes'], policy.MAX_ARCHIVE)
        self.repin('archive', self.parts['archive'] + b'x')
        self.refused()
        with self.assertRaises(ValueError):
            policy.admit(b'x' * (policy.MAX_BODY + 1), '0' * 64)

    def test_cli_refuses_bad_arity_and_redacts_input(self):
        for args in ([], ['0' * 64, 'extra'], ['invalid']):
            run = subprocess.run([sys.executable, '-B', str(Path(policy.__file__)), *args], input=b'PRIVATE_INPUT_CANARY', capture_output=True, timeout=10)
            self.assertEqual(run.returncode, 1)
            self.assertNotIn(b'PRIVATE_INPUT_CANARY', run.stdout + run.stderr)

    def test_binary_and_boolean_archive_lengths_cannot_alias_valid_input(self):
        self.plan['inputs']['archiveBytes'] = True
        self.refused()
        self.setUp()
        body, pin = self.body()
        changed = json.loads(body)
        changed['archiveBase64'] = changed['archiveBase64'] + '\n'
        with self.assertRaises(ValueError):
            policy.admit(C(changed), pin)


if __name__ == '__main__':
    unittest.main()
