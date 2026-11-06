"""Generated historical envelope contracts; no original archives, keys or backend."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

import audit_observation_tests as vectors

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'eng/pilot'))
import historical_audit_observation as policy

H = policy.packet.digest
NONCE = vectors.NONCE
CANARY = 'PRIVATE_INPUT_CANARY'


class HistoricalObservationTests(unittest.TestCase):
    def setUp(self):
        self.strict, self.observed = vectors.dataset()
        self.source = dict(category='audit-history-expectations', schema='fleetory.audit-historical-expectations.v1',
            nonce=NONCE, snapshotSha256='a' * 64, knownEvents=copy.deepcopy(self.strict['knownEvents']), eventFields=10,
            inMemoryRequests=16, productionSinkSerializationUsed=True, profile=policy.PROFILE, nullContextMembersPreserved=1,
            productionPumpDeserializationUsed=True, historicalComparisonOnly=True)
        self.source.update({name: False for name in policy.FALSE_FLAGS})
        self.expected = self.build()
        self.observed.update(category='observation-history-read', schema=policy.OBSERVED, comparison=copy.deepcopy(self.expected['comparison']))

    def build(self):
        data = policy.core.canonical(self.source)
        return policy.build(data, H(data), NONCE, self.strict['point'], self.strict['producer'])

    def observe(self):
        expected = policy.core.canonical(self.expected)
        return policy.observe(expected, H(expected), policy.core.canonical(self.observed))

    def refused(self):
        with self.assertRaises((ValueError, TypeError, KeyError)):
            self.observe()

    def test_builder_preserves_source_binding_and_fixed_readonly_scope(self):
        scope = self.expected['comparison']
        self.assertEqual(scope['profile'], policy.PROFILE)
        self.assertEqual(scope['sourceExpectationSha256'], H(policy.core.canonical(self.source)))
        self.assertEqual(scope['knownValuesCommitment'], policy.commitment(self.source['knownEvents']))
        self.assertEqual(self.expected['knownEvents'], self.source['knownEvents'])
        self.assertFalse(scope['writerAdmissionVerified'])
        self.assertTrue(scope['historicalComparisonOnly'])

    def test_historical_receipt_preserves_scope_and_unreviewed_extra_entry(self):
        value = self.observe()
        self.assertEqual(value['schema'], policy.OBSERVED)
        self.assertEqual((value['knownEvents'], value['currentKvKeys'], value['nativeTransactions']), (4, 4, 5))
        self.assertEqual(value['unreviewedPrefixes'], {'1': 1})
        self.assertTrue(value['historicalComparisonOnly'])
        self.assertFalse(value['writerAdmissionVerified'])
        self.assertFalse(value['originalStrictExpectationsAccepted'])
        self.assertFalse(value['additionalStateReviewed'])
        self.assertFalse(value['wholeKeyspaceVerified'])
        self.assertEqual(value['comparison'], self.expected['comparison'])

    def test_strict_and_historical_protocols_do_not_accept_each_other(self):
        with self.assertRaises(ValueError):
            policy.core.expectation(self.expected)
        data = policy.core.canonical(self.expected)
        with self.assertRaises(ValueError):
            policy.core.observe(data, H(data), policy.core.canonical(self.observed))
        self.expected = self.strict
        self.refused()

    def test_nonhistorical_source_or_extra_fields_cannot_select_profile(self):
        for field, value in (('category', 'audit-expectations'), ('schema', 'fleetory.audit-event-expectations.v1'),
            ('profile', 'strict'), ('extra', CANARY), ('nullContextMembersPreserved', 0), ('nullContextMembersPreserved', 2)):
            self.setUp()
            self.source[field] = value
            with self.assertRaises(ValueError):
                self.build()

    def test_source_authority_flags_and_boolean_counters_refused(self):
        for name in policy.FALSE_FLAGS:
            self.source[name] = True
            with self.assertRaises(ValueError):
                self.build()
            self.source[name] = False
        for name in ('nullContextMembersPreserved', 'eventFields', 'inMemoryRequests'):
            self.source[name] = True
            with self.assertRaises(ValueError):
                self.build()
            self.setUp()

    def test_source_pin_nonce_json_duplicates_and_size_bounds(self):
        data = policy.core.canonical(self.source)
        for raw, pin in ((data, '0' * 64), (b'', H(b'')), (b'x' * (policy.core.MAX_EXPECTED + 1), '0' * 64)):
            with self.assertRaises(ValueError):
                policy.build(raw, pin, NONCE, self.strict['point'], self.strict['producer'])
        raw = data.replace(b'"category":', b'"category":"duplicate","category":', 1)
        with self.assertRaises(ValueError):
            policy.build(raw, H(raw), NONCE, self.strict['point'], self.strict['producer'])
        with self.assertRaises(ValueError):
            policy.build(data, H(data), 'invalid', self.strict['point'], self.strict['producer'])

    def test_comparison_flags_and_missing_scope_refused(self):
        for name in ('writerAdmissionVerified', 'stateMutationAuthorized', 'sourceOriginAuthenticated',
            'sourceIndependenceAuthenticated', 'executionAuthorized', 'fullSystemRecoveryVerified', 'phase7Complete'):
            self.expected['comparison'][name] = True
            self.refused()
            self.setUp()
        self.expected.pop('comparison')
        self.refused()

    def test_scope_cannot_be_dropped_or_changed_in_native_output(self):
        self.observed.pop('comparison')
        self.refused()
        self.setUp()
        self.observed['comparison']['sourceExpectationSha256'] = 'b' * 64
        self.refused()
        for field, value in (('writerAdmissionVerified', 0), ('historicalComparisonOnly', 1), ('nullContextMembersPreserved', True)):
            self.setUp()
            self.observed['comparison'][field] = value
            self.refused()

    def test_known_value_commitment_catches_relabelled_hashes_and_order(self):
        self.expected['knownEvents'][0]['valueSha256'] = 'b' * 64
        self.refused()
        self.setUp()
        self.expected['knownEvents'].reverse()
        self.expected['comparison']['knownValuesCommitment'] = policy.commitment(self.expected['knownEvents'])
        self.refused()

    def test_new_wellformed_wrong_source_hash_still_fails_data_witness(self):
        self.source['knownEvents'][0]['valueSha256'] = 'b' * 64
        self.expected = self.build()
        self.observed['comparison'] = copy.deepcopy(self.expected['comparison'])
        self.refused()

    def test_existing_point_nonce_and_producer_bindings_stay_required(self):
        for change in ('point', 'nonce', 'producer'):
            self.setUp()
            if change == 'point':
                self.expected['point']['txHash'] = vectors.B(b'x' * 32)
            elif change == 'nonce':
                self.observed['nonce'] = '00000000-0000-4000-8000-000000000002'
            else:
                self.observed['producer']['probeSha256'] = 'b' * 64
            self.refused()

    def test_native_revision_history_raw_kind_and_scan_bounds_stay_required(self):
        for change in ('revision', 'history', 'raw-kind', 'scan-limit'):
            self.setUp()
            if change == 'revision':
                self.observed['scan']['entries'][0]['revision'] = 2
            elif change == 'history':
                self.observed['scan']['entries'][0]['witness']['historyCount'] = 2
            elif change == 'raw-kind':
                self.observed['transactions'][0]['entries'][0]['prefix'] = 1
            else:
                self.observed['scan']['limit'] = 18
            self.refused()

    def test_builder_freezes_mutable_point_producer_and_source_buffers(self):
        before = copy.deepcopy(self.expected)
        self.strict['point']['txHash'] = 'changed'
        self.strict['producer']['probeSha256'] = 'changed'
        self.source['knownEvents'].clear()
        self.assertEqual(self.expected, before)

    def test_observer_freezes_both_buffers_before_first_parser_callback(self):
        expected = bytearray(policy.core.canonical(self.expected))
        observed = bytearray(policy.core.canonical(self.observed))
        pin = H(expected)
        parser = policy.packet.strict_json
        calls = []
        def mutate(data, bound):
            if not calls:
                expected[:] = b'changed'
                observed[:] = b'changed'
            calls.append(True)
            return parser(data, bound)
        with patch.object(policy.packet, 'strict_json', side_effect=mutate):
            report = policy.observe(expected, pin, observed)
        self.assertTrue(report['knownEventBindingsMatched'])

    def test_no_file_process_or_socket_api_used_by_pure_policy(self):
        with patch('builtins.open', side_effect=AssertionError('File forbidden')), \
             patch('subprocess.Popen', side_effect=AssertionError('Process forbidden')), \
             patch('socket.socket', side_effect=AssertionError('Socket forbidden')):
            self.build()
            self.assertTrue(self.observe()['historicalComparisonOnly'])

    def test_cli_refusal_does_not_echo_injected_text_or_accept_arity(self):
        for args in ([], ['restore'], ['build', 'extra']):
            result = subprocess.run([sys.executable, '-B', str(Path(policy.__file__)), *args], input=CANARY.encode(), capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 1)
            self.assertNotIn(CANARY.encode(), result.stdout + result.stderr)

    def test_packet_limits_and_stale_external_expected_pin_refused(self):
        expected = policy.core.canonical(self.expected)
        for first, pin, observed in ((expected, '0' * 64, b'{}'), (b'', H(b''), b'{}'),
            (expected, H(expected), b' ' * (policy.core.MAX_OBSERVED + 1))):
            with self.assertRaises(ValueError):
                policy.observe(first, pin, observed)

    def test_unknown_extra_key_and_prefix_are_never_promoted(self):
        _, observed = vectors.dataset(extra_prefix=0, extra_kv=True)
        self.observed = observed
        self.observed.update(category='observation-history-read', schema=policy.OBSERVED, comparison=copy.deepcopy(self.expected['comparison']))
        value = self.observe()
        self.assertEqual(value['unknownCurrentKvKeys'], 1)
        self.assertEqual(value['unreviewedRawEntries'], 1)
        self.assertFalse(value['additionalStateReviewed'])
        self.assertFalse(value['wholeKeyspaceVerified'])


if __name__ == '__main__':
    unittest.main()
