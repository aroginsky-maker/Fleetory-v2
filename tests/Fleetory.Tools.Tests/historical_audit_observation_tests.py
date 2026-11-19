"""Generated historical envelope contracts; no original archives, keys or backend."""
import copy
import io
import json
from pathlib import Path
import subprocess
import sys
import unittest
from types import SimpleNamespace
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

    def test_distinct_operation_nonce_preserves_source_identity_and_data_fingerprint(self):
        first = self.observe()
        source = policy.core.canonical(self.source)
        for operation in ('abcdefab-1234-4123-8123-000000000001', 'abcdefab-1234-4123-8123-000000000002'):
            self.expected = policy.build(source, H(source), operation, self.strict['point'], self.strict['producer'])
            self.observed['nonce'] = operation
            self.observed['comparison'] = copy.deepcopy(self.expected['comparison'])
            value = self.observe()
            self.assertEqual(self.expected['nonce'], operation)
            self.assertEqual(value['comparison']['sourceNonce'], NONCE)
            self.assertEqual(self.expected['knownEvents'], self.source['knownEvents'])
            self.assertEqual(value['comparison'], first['comparison'])
            self.assertEqual(value['observationSha256'], first['observationSha256'])
            self.assertNotEqual(value['expectedSha256'], first['expectedSha256'])
            self.assertFalse(value['executionAuthorized'])
        self.observed['nonce'] = NONCE
        self.refused()

    def test_independent_controller_refuses_unexpected_or_incomplete_frames(self):
        def frame(value):
            return len(value).to_bytes(4, 'big') + value

        expected = frame(policy.core.canonical(self.expected))
        other_nonce = 'abcdefab-1234-4123-8123-000000000001'
        cases = (
            (NONCE, expected + frame(b'unknown-operation')),
            (NONCE, expected + frame(b'replay') + frame(b'observation-without-refusal')),
            (NONCE, expected + (policy.core.MAX_BODY + 1).to_bytes(4, 'big')),
            (NONCE, expected + (6).to_bytes(4, 'big') + b'R{}'),
            (other_nonce, expected),
        )
        for nonce, wire in cases:
            with self.subTest(nonce=nonce, length=len(wire)):
                outcome = subprocess.run(
                    (sys.executable, '-I', '-S', '-B', policy.__file__, '--independent-controller', nonce),
                    input=wire, capture_output=True, timeout=8, check=False)
                self.assertEqual(outcome.returncode, 1)
                self.assertNotIn(b'observationSha256', outcome.stdout)
                self.assertEqual(outcome.stderr.strip(),
                    b'Historical observation refused; no paths, values or credentials logged.')

    def test_independent_history_sequence_and_attempt_binding(self):
        auth = dict(category='unexpected', errorType='InvalidOperationException', authenticationDenied=True, controlStatus=500)
        reader = dict(category='observation-reader-denial', readerWriteRefused=True)
        restarted = dict(stopped=True, ready=True)
        stages = (b'observe', b'authenticate', b'check-reader', b'restart', b'observe-after-restart')
        replies = (self.observed, auth, reader, restarted, self.observed)

        def execute(sequence, data, nonce=NONCE):
            original = policy._creator_frame(policy.core.canonical(self.expected))
            frames = (policy._creator_frame(b'R:' + stage + b':' + attempt.encode() + b'\n' + policy.core.canonical(reply))
                      for stage, attempt, reply in zip(sequence, (NONCE, nonce, NONCE, NONCE, NONCE), data))
            return subprocess.run((sys.executable, '-I', '-S', '-B', policy.__file__, '--independent-controller', NONCE),
                                  input=original + b''.join(frames), capture_output=True, timeout=8, check=False)

        accepted = execute(stages, replies)
        self.assertEqual(accepted.returncode, 0)
        self.assertFalse(accepted.stderr)
        output = io.BytesIO(accepted.stdout)
        self.assertEqual(policy._creator_read(output), policy.READY)
        self.assertEqual(tuple(policy._creator_read(output) for _ in stages), stages)
        decision = json.loads(policy._creator_read(output))
        self.assertTrue(decision['authenticationRefused'])
        self.assertTrue(decision['readerWriteRefused'])
        self.assertTrue(decision['restartPreservedObservation'])
        self.assertEqual(decision['before']['observationSha256'], decision['after']['observationSha256'])
        self.assertFalse(output.read(1))

        reused = 'abcdefab-1234-4123-8123-000000000001'
        rejected = [
            execute(stages, replies, reused),
            execute((stages[0], *stages[:4]), replies),
            execute(stages, (self.observed, dict(auth, controlStatus=500.0), reader, restarted, self.observed)),
            execute(stages, (self.observed, auth, dict(reader, readerWriteRefused=False), restarted, self.observed)),
            execute(stages, (self.observed, auth, reader, dict(restarted, ready=False), self.observed)),
        ]
        for result in rejected:
            self.assertEqual(result.returncode, 1)
            self.assertNotIn(b'observationSha256', result.stdout)

    def test_recovery_coordinator_frame_scope_and_attempt(self):
        nonce = NONCE.encode('ascii')
        projection = b'a' * 64
        frames = (b'admit:' + nonce, b'owned:' + projection, b'work:' + projection, b'completed')

        def execute(parts, trailing=b''):
            payload = b''.join(policy._creator_frame(part) for part in parts) + trailing
            return subprocess.run((sys.executable, '-I', '-S', '-B', policy.__file__, '--recovery-coordinator', NONCE),
                                  input=payload, capture_output=True, timeout=8, check=False)

        for outcome in (b'completed', b'refused'):
            result = execute((*frames[:3], outcome))
            self.assertEqual(result.returncode, 0)
            self.assertFalse(result.stderr)
            output = io.BytesIO(result.stdout)
            expected = (policy.READY, b'acquire:' + nonce, b'received:' + projection, b'run:' + projection, outcome)
            self.assertEqual(tuple(policy._creator_read(output) for _ in expected), expected)
            self.assertFalse(output.read(1))

        for mutated in ((b'admit:' + b'0' * 36, *frames[1:]),
                        (frames[0], b'owned:/var/run/docker.sock', *frames[2:]),
                        (frames[0], b'owned:' + b'a' * 97, *frames[2:]),
                        (*frames[:2], b'work:' + b'b' * 64, frames[3]),
                        (*frames[:2], frames[0], frames[3])):
            self.assertEqual(execute(mutated).returncode, 1)
        self.assertEqual(execute(frames, b'extra').returncode, 1)

    def test_recovery_coordinator_refuses_allocation_without_projection(self):
        nonce = NONCE.encode('ascii')
        frames = (b'admit:' + nonce, b'unavailable:' + nonce, policy.ALLOCATION_REFUSED)

        def execute(parts):
            payload = b''.join(policy._creator_frame(part) for part in parts)
            return subprocess.run((sys.executable, '-I', '-S', '-B', policy.__file__, '--recovery-coordinator', NONCE),
                                  input=payload, capture_output=True, timeout=8, check=False)

        result = execute(frames)
        self.assertEqual(result.returncode, 0)
        self.assertFalse(result.stderr)
        expected = (policy.READY, b'acquire:' + nonce, b'retry:' + nonce, policy.ALLOCATION_REFUSED)
        output = io.BytesIO(result.stdout)
        self.assertEqual(tuple(policy._creator_read(output) for _ in expected), expected)
        self.assertFalse(output.read(1))
        for invalid in ((frames[0], b'unavailable:' + b'0' * 36, frames[2]),
                        (*frames[:2], b'owned:' + b'a' * 64),
                        (*frames, b'work:' + b'a' * 64)):
            self.assertEqual(execute(invalid).returncode, 1)

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


class RecoveryAfterWorkTests(unittest.TestCase):
    def dialog(self, flow, frames):
        owner = iter(frames)
        application = iter((b'run:' + b'a' * 64, b'refused'))
        sent, output = [], io.BytesIO()
        link = SimpleNamespace(receive_owner=lambda maximum: next(owner),
            receive_application=lambda maximum: next(application), send_application=sent.append,
            live=lambda: None, child=SimpleNamespace(stdin=io.BytesIO()))
        with patch.object(policy, '_coordinator_handoff', return_value=(b'a' * 64, False)), \
             patch.object(policy.sys, 'stdout', SimpleNamespace(buffer=output)):
            report = policy._coordinator_dialog(link, flow, NONCE)
        return report, sent, output.getvalue()

    def test_after_work_exit_does_not_report_completed_application(self):
        report, sent, _ = self.dialog(policy.AFTER_WORK_EXIT, (b'work', b'terminate'))
        self.assertTrue(report[1])
        self.assertFalse(report[0]['lateRequestRefused'])
        self.assertEqual(sent, [b'work:' + b'a' * 64])
        with self.assertRaises(ValueError):
            self.dialog(policy.AFTER_WORK_EXIT, (b'work', b'completed'))

    def test_after_work_expiry_never_relays_second_work_request(self):
        report, sent, raw = self.dialog(policy.AFTER_WORK_LEASE, (b'work', b'status', b'work', b'refused'))
        self.assertFalse(report[1])
        self.assertTrue(report[0]['lateRequestRefused'])
        self.assertEqual(sent, [b'work:' + b'a' * 64, b'refused'])
        output = io.BytesIO(raw)
        self.assertEqual(tuple(policy._creator_read(output) for _ in range(3)),
                         (b'run:' + b'a' * 64, b'alive', b'late-work'))
        self.assertFalse(output.read(1))

    def test_after_work_expiry_refuses_wrong_phase_or_success_reply(self):
        for frames in ((b'work', b'completed'), (b'work', b'status', b'replay', b'refused'),
                       (b'work', b'status', b'work', b'completed')):
            with self.subTest(frames=frames), self.assertRaises(ValueError):
                self.dialog(policy.AFTER_WORK_LEASE, frames)


class RecoveryWorkStatusTests(unittest.TestCase):
    def decide(self, flow, frames, live=None):
        source = iter(frames)
        output = io.BytesIO()
        link = SimpleNamespace(receive_owner=lambda maximum: next(source), live=live or (lambda: None))
        with patch.object(policy.sys, 'stdout', SimpleNamespace(buffer=output)):
            value = policy._work_decision(link, flow, b'a' * 64)
        return value, output.getvalue()

    def test_status_acknowledgements_bind_projection_and_do_not_forward_work(self):
        value, raw = self.decide('complete', (b'work-status', b'work-status', b'completed'))
        self.assertEqual(value, b'completed')
        output = io.BytesIO(raw)
        self.assertEqual(tuple(policy._creator_read(output) for _ in range(2)), (b'alive:' + b'a' * 64,) * 2)
        self.assertFalse(output.read(1))

    def test_loss_at_second_lookup_confirmation_does_not_acknowledge_work(self):
        value, raw = self.decide(policy.INSPECTION_EXIT, (b'work-status', b'work-status'))
        self.assertIsNone(value)
        output = io.BytesIO(raw)
        self.assertEqual(policy._creator_read(output), b'alive:' + b'a' * 64)
        self.assertFalse(output.read(1))

    def test_request_bound_and_dead_held_identity_refuse_status(self):
        with self.assertRaises(ValueError):
            self.decide('complete', (b'work-status',) * (policy.MAX_WORK_STATUS + 1))
        def dead():
            raise ValueError('Held identity is no longer live')
        with self.assertRaises(ValueError):
            self.decide('complete', (b'work-status',), live=dead)


if __name__ == '__main__':
    unittest.main()
