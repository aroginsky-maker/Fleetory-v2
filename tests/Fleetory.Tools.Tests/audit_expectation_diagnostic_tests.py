"""Generated metadata-only diagnostics; no original fixtures, databases or private keys."""
import argparse
import base64
import copy
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

import audit_expectation_source_tests as fixtures
import audit_event_expectations_tests as vectors

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'eng/pilot'))
import audit_expectation_diagnostic as policy

H = policy.packet.digest
NONCE = vectors.NONCE
CANARY = 'PRIVATE_INPUT_CANARY'


def failure(kind='AuditExpectationInputException', location='Require', cause=None):
    return dict(category='unexpected', errorType=kind, causeType=cause, location=location,
        controlStatus=None, authenticationDenied=None, tlsFailure=None)


def success(snapshot, pin, nonce):
    value = dict(category='audit-expectations', schema='fleetory.audit-event-expectations.v1', nonce=nonce,
        snapshotSha256=pin, eventFields=10, inMemoryRequests=16, productionSinkSerializationUsed=True,
        knownEvents=[dict(eventId=row['event_id'], key=base64.b64encode(('fleetory/audit/v1/' + row['event_id'].replace('-', '')).encode()).decode(),
            revision=1, valueSha256=H(b'generated wire expectation')) for row in snapshot['events']])
    value.update({name: False for name in policy.FALSE_FLAGS})
    return value


class AuditExpectationDiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.snapshot = vectors.snapshot()
        self.calls = []

    def diagnose(self, value=None, exit_code=1, mutate=None):
        raw = policy.archive.canonical(self.snapshot)
        def invoke(data, pin, nonce):
            self.calls.append((data, pin, nonce))
            output = success(self.snapshot, pin, nonce) if value is None and exit_code == 0 else failure() if value is None else copy.deepcopy(value)
            if mutate:
                mutate(output)
            return policy.NativeResult(exit_code, json.dumps(output).encode(), b'')
        return policy.diagnose(raw, H(raw), NONCE, invoke)

    def fixture(self):
        case = fixtures.AuditExpectationSourceTests('test_exactly_one_source_open_and_no_native_or_broad_apis')
        case.setUp()
        self.addCleanup(case.doCleanups)
        return case

    def test_success_is_diagnostic_only_and_discards_known_values_and_ids(self):
        self.snapshot['events'][0]['action'] = CANARY
        for row in self.snapshot['events']:
            row['event_id'] = '1' + row['event_id'][1:]
        report = self.diagnose(exit_code=0)
        self.assertEqual(report['nativeOutcome'], 'NATIVE_ACCEPTED_DIAGNOSTIC_ONLY')
        self.assertTrue(report['diagnosticComplete'])
        self.assertFalse(report['originalExpectationsAccepted'])
        encoded = json.dumps(report)
        for text in (CANARY, H(b'generated wire expectation'), self.snapshot['events'][0]['event_id'], 'fleetory/audit/v1/'):
            self.assertNotIn(text, encoded)
        self.assertEqual(len(self.calls), 1)

    def test_distinct_native_refusals_are_not_confused(self):
        for kind, outcome in (('AuditExpectationInputException', 'INPUT_PROFILE_REFUSED'),
            ('AuditExpectationValueBoundException', 'SERIALIZED_VALUE_BOUND_REFUSED'),
            ('AuditExpectationCaptureException', 'CAPTURE_PROTOCOL_REFUSED')):
            with self.subTest(kind=kind):
                result = self.diagnose(failure(kind))
                self.assertEqual(result['nativeOutcome'], outcome)
                self.assertEqual(result['nativeErrorType'], kind)

    def test_operational_failure_is_not_treated_as_input_rejection(self):
        for kind, outcome in (('InvalidOperationException', 'NATIVE_OPERATION_FAILURE'),
            ('FormatException', 'NATIVE_FORMAT_FAILURE'), ('KeyNotFoundException', 'NATIVE_FIELD_ACCESS_FAILURE'),
            ('TaskCanceledException', 'NATIVE_DEADLINE_FAILURE')):
            result = self.diagnose(failure(kind, 'ExecuteAsync'))
            self.assertEqual(result['nativeOutcome'], outcome)
            self.assertFalse(result['originalExpectationsAccepted'])

    def test_unrecognized_native_names_are_never_echoed_or_promoted(self):
        report = self.diagnose(failure(CANARY, CANARY, CANARY))
        self.assertEqual(report['nativeOutcome'], 'UNCLASSIFIED_NATIVE_FAILURE')
        self.assertFalse(report['diagnosticComplete'])
        self.assertEqual((report['nativeErrorType'], report['nativeCauseType'], report['nativeLocation']), ('OTHER',) * 3)
        self.assertNotIn(CANARY, json.dumps(report))

    def test_result_exit_type_stderr_and_size_guards(self):
        data = policy.archive.canonical(self.snapshot)
        valid = json.dumps(failure()).encode()
        for result in (None, {}, policy.NativeResult(True, valid, b''), policy.NativeResult(2, valid, b''),
            policy.NativeResult(1, valid, CANARY.encode()), policy.NativeResult(1, bytearray(valid), b''),
            policy.NativeResult(1, b' ' * (policy.MAX_OUTPUT + 1), b'')):
            with self.subTest(type=type(result).__name__):
                with self.assertRaises(ValueError):
                    policy.diagnose(data, H(data), NONCE, lambda *_: result)

    def test_error_shape_backend_fields_and_duplicate_json_fail_closed(self):
        for field, content in (('category', 'audit-expectations'), ('controlStatus', 403), ('authenticationDenied', True),
            ('tlsFailure', CANARY), ('errorType', None), ('location', {}), ('causeType', 1), ('extra', CANARY)):
            value = failure()
            value[field] = content
            with self.subTest(field=field):
                with self.assertRaises(ValueError):
                    self.diagnose(value)
        data = policy.archive.canonical(self.snapshot)
        for output in (b'{', b'{"category":"x","category":"y"}', b'\xff'):
            with self.assertRaises(ValueError):
                policy.diagnose(data, H(data), NONCE, lambda *_: policy.NativeResult(1, output, b''))

    def test_success_binding_counter_identity_and_authority_mutations_refused(self):
        mutations = [lambda v: v.update(nonce='00000000-0000-4000-8000-000000000002'),
            lambda v: v.update(snapshotSha256='0' * 64), lambda v: v.update(eventFields=True),
            lambda v: v.update(inMemoryRequests=15), lambda v: v.update(productionSinkSerializationUsed=False),
            lambda v: v['knownEvents'].pop(), lambda v: v['knownEvents'][0].update(eventId=NONCE.replace('1', '2')),
            lambda v: v['knownEvents'][0].update(revision=True), lambda v: v['knownEvents'][0].update(valueSha256='x'),
            lambda v: v['knownEvents'][0].update(key=base64.b64encode(b'wrong-key').decode())]
        mutations.extend(lambda v, name=name: v.update({name: True}) for name in policy.FALSE_FLAGS)
        for mutate in mutations:
            with self.assertRaises(ValueError):
                self.diagnose(exit_code=0, mutate=mutate)

    def test_stale_pin_nonce_and_snapshot_bounds_block_native_invocation(self):
        data = policy.archive.canonical(self.snapshot)
        for raw, pin, nonce in ((data, '0' * 64, NONCE), (data, H(data), 'invalid'),
            (b'', H(b''), NONCE), (b' ' * (policy.source.MAX_SNAPSHOT + 1), '0' * 64, NONCE)):
            invoked = []
            with self.assertRaises(ValueError):
                policy.diagnose(raw, pin, nonce, lambda *_: invoked.append(True))
            self.assertFalse(invoked)

    def test_mutable_snapshot_frozen_before_caller_invocation(self):
        data = bytearray(policy.archive.canonical(self.snapshot))
        frozen_pin = H(data)
        def invoke(frozen, pin, nonce):
            data[:] = b'changed'
            self.assertIs(type(frozen), bytes)
            self.assertEqual(H(frozen), frozen_pin)
            return policy.NativeResult(1, json.dumps(failure()).encode(), b'')
        result = policy.diagnose(data, frozen_pin, NONCE, invoke)
        self.assertEqual(result['snapshotSha256'], frozen_pin)

    def test_callback_exception_is_sanitized(self):
        data = policy.archive.canonical(self.snapshot)
        def invoke(*_):
            raise RuntimeError(CANARY)
        with self.assertRaises(ValueError) as error:
            policy.diagnose(data, H(data), NONCE, invoke)
        self.assertNotIn(CANARY, str(error.exception))
        self.assertTrue(error.exception.__suppress_context__)

    def test_fixed_text_actor_identity_and_target_advisory_counts(self):
        rows = self.snapshot['events']
        rows[0].update(event_id='00000000-0000-0000-0000-000000000000', actor_kind=4, action=' ')
        rows[1].update(target_type='', target_id='')
        rows[2].update(target_id=None)
        rules = {r['code']: r['affectedRows'] for r in self.diagnose()['advisoryRules']}
        self.assertEqual(rules['EVENT_ID_PROFILE'], 1)
        self.assertEqual(rules['ACTOR_KIND_PROFILE'], 1)
        self.assertEqual(rules['REQUIRED_TEXT_PROFILE'], 1)
        self.assertEqual(rules['TARGET_TEXT_PROFILE'], 1)
        self.assertEqual(rules['TARGET_PAIR_PROFILE'], 1)

    def test_context_type_utf8_utf16_and_container_bounds_are_advisory(self):
        rows = self.snapshot['events']
        rows[0]['context_json'] = 'null'
        rows[1]['context_json'] = '{"A":1}'
        rows[2]['context_json'] = json.dumps({'A': '𐀀' * 513})
        rows[3]['context_json'] = json.dumps({str(i): 'v' for i in range(17)})
        report = self.diagnose()
        rules = {r['code']: r['affectedRows'] for r in report['advisoryRules']}
        self.assertEqual(rules['CONTEXT_TYPE_PROFILE'], 2)
        self.assertEqual(rules['CONTEXT_BOUND_PROFILE'], 3)
        self.assertFalse(report['advisoryRulesAreAuthoritative'])

    def test_valid_null_empty_and_unicode_context_has_no_advisory_failures(self):
        self.snapshot['events'][0].update(target_type=None, target_id=None, context_json=None)
        self.snapshot['events'][1]['context_json'] = '{}'
        self.snapshot['events'][2]['context_json'] = '{"A":""}'
        self.snapshot['events'][3]['context_json'] = json.dumps({'𐀀': '界'})
        self.assertTrue(all(r['affectedRows'] == 0 for r in self.diagnose(exit_code=0)['advisoryRules']))

    def test_generated_source_controller_opens_one_file_and_invokes_once(self):
        case = self.fixture()
        def invoke(data, pin, nonce):
            self.calls.append((pin, nonce))
            return policy.NativeResult(1, json.dumps(failure()).encode(), b'')
        with patch.object(policy.source.files, 'inspect_file', wraps=policy.source.files.inspect_file) as opened, \
             patch.object(policy.source.files, 'verify', side_effect=AssertionError('Broad verification forbidden')), \
             patch.object(policy.source.archive, 'capture', side_effect=AssertionError('Source host forbidden')):
            report = policy.capture_diagnostic(case.root, case.metadata, case.pins, NONCE, invoke)
        self.assertEqual(opened.call_count, 1)
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(report['source']['snapshotSha256'], report['diagnostic']['snapshotSha256'])
        self.assertEqual(report['source']['verifiedArtifacts'], 1)

    def test_bad_source_does_not_invoke_native_callback(self):
        case = self.fixture()
        case.path.write_bytes(b'changed')
        with self.assertRaises((ValueError, OSError)):
            policy.capture_diagnostic(case.root, case.metadata, case.pins, NONCE, lambda *_: self.calls.append(True))
        self.assertFalse(self.calls)

    def test_missing_native_callback_is_rejected_before_source_open(self):
        with patch.object(policy.source, 'capture', side_effect=AssertionError('Source must not open')) as opened:
            with self.assertRaises(ValueError):
                policy.capture_diagnostic(Path.cwd(), {}, {}, NONCE, None)
        opened.assert_not_called()

    def test_pure_policy_does_not_open_files_or_start_processes_or_sockets(self):
        with patch('builtins.open', side_effect=AssertionError('File forbidden')), \
             patch('subprocess.Popen', side_effect=AssertionError('Process forbidden')), \
             patch('socket.socket', side_effect=AssertionError('Socket forbidden')):
            report = self.diagnose()
        self.assertEqual(report['nativeInvocations'], 1)
        self.assertFalse(report['executionAuthorized'])

    def test_unknown_error_cause_and_location_cannot_echo_source_names(self):
        report = self.diagnose(failure('AuditExpectationInputException', CANARY, CANARY))
        self.assertEqual(report['nativeCauseType'], 'OTHER')
        self.assertEqual(report['nativeLocation'], 'OTHER')
        self.assertNotIn(CANARY, json.dumps(report))


def integration(probe):
    cases = (('valid', 'NATIVE_ACCEPTED_DIAGNOSTIC_ONLY'), ('whitespace', 'INPUT_PROFILE_REFUSED'),
        ('context-null-text', 'INPUT_PROFILE_REFUSED'), ('actor', 'INPUT_PROFILE_REFUSED'),
        ('value-bound', 'SERIALIZED_VALUE_BOUND_REFUSED'), ('target-pair', 'INPUT_PROFILE_REFUSED'),
        ('empty-target', 'INPUT_PROFILE_REFUSED'))
    for name, outcome in cases:
        case = fixtures.AuditExpectationSourceTests('test_exactly_one_source_open_and_no_native_or_broad_apis')
        case.setUp()
        root = case.root
        calls = []
        try:
            row = case.snapshot['events'][0]
            if name == 'whitespace':
                row['action'] = ' '
            elif name == 'context-null-text':
                row['context_json'] = 'null'
            elif name == 'actor':
                row['actor_kind'] = 4
            elif name == 'value-bound':
                row['context_json'] = json.dumps({str(i): 'x' * 1000 for i in range(9)})
            elif name == 'target-pair':
                row['target_id'] = None
            elif name == 'empty-target':
                row.update(target_type='', target_id='')
            case.republish()
            def invoke(data, pin, nonce):
                calls.append(True)
                native = subprocess.run(['dotnet', str(probe), 'audit-expectations', pin, nonce], input=data,
                    capture_output=True, timeout=25)
                return policy.NativeResult(native.returncode, native.stdout, native.stderr)
            result = policy.capture_diagnostic(root, case.metadata, case.pins, NONCE, invoke)
            case.assertEqual(len(calls), 1)
            case.assertEqual(result['diagnostic']['nativeOutcome'], outcome)
            case.assertTrue(result['diagnostic']['diagnosticComplete'])
            case.assertFalse(result['diagnostic']['originalExpectationsAccepted'])
            case.assertNotIn('knownEvents', result['diagnostic'])
        finally:
            case.doCleanups()
        case.assertFalse(root.exists())
    return dict(schema='fleetory.generated-expectation-diagnostic.v1', verified=True, nativeCases=len(cases),
        validDiagnosticCases=1, inputRefusalCases=5, valueBoundCases=1, cleanupVerified=True,
        originalInputsRead=False, realBackendContacted=False, nativeValuesDiscarded=True, originalExpectationsAccepted=False,
        sourceVpsAccessed=False, originalPkiOrProviderUsed=False, executionAuthorized=False,
        fullSystemRecoveryVerified=False, phase7Complete=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--integration-probe')
    arguments, remaining = parser.parse_known_args()
    if arguments.integration_probe:
        if remaining:
            raise SystemExit('Unexpected diagnostic integration arguments.')
        probe = Path(arguments.integration_probe).resolve(strict=True)
        if probe.name != 'ServerBackendProbe.dll':
            raise SystemExit('Unexpected diagnostic probe.')
        print(json.dumps(integration(probe), sort_keys=True))
    else:
        unittest.main(argv=[sys.argv[0], *remaining])
