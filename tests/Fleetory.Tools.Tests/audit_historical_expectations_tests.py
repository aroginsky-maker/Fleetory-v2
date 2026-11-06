"""Generated read-only historical comparison vectors; strict admission remains separate."""
import argparse
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

import audit_event_expectations_tests as strict
import audit_expectation_source_tests as fixtures

PROBE = None
NONCE = strict.NONCE
H = strict.H
CANARY = 'PRIVATE_INPUT_CANARY'
MODE = 'audit-history-expectations'


class HistoricalExpectationTests(unittest.TestCase):
    def setUp(self):
        self.snapshot = strict.snapshot()
        self.snapshot['events'][0]['context_json'] = '{"Optional":null,"Text":"value"}'

    def invoke(self, data=None, pin=None, nonce=NONCE, mode=MODE, environment=None):
        data = json.dumps(self.snapshot, ensure_ascii=True, separators=(',', ':')).encode() if data is None else data
        return subprocess.run(['dotnet', str(PROBE), mode, pin or H(data), nonce], input=data,
            capture_output=True, timeout=25, env=environment)

    def produce(self, **kwargs):
        result = self.invoke(**kwargs)
        self.assertEqual(result.returncode, 0, 'Generated historical producer failed.')
        self.assertEqual(result.stderr, b'')
        value = json.loads(result.stdout)
        self.assertEqual(value['category'], MODE)
        self.assertEqual(value['schema'], 'fleetory.audit-historical-expectations.v1')
        self.assertEqual(value['profile'], 'historical-one-null-member-readonly.v1')
        self.assertEqual(value['nonce'], kwargs.get('nonce', NONCE))
        self.assertEqual(value['nullContextMembersPreserved'], 1)
        self.assertEqual(value['eventFields'], 10)
        self.assertEqual(value['inMemoryRequests'], 16)
        for name in ('historicalComparisonOnly', 'productionPumpDeserializationUsed', 'productionSinkSerializationUsed'):
            self.assertIs(value[name], True)
        for name in ('strictContextValueTypesCompatible', 'writerAdmissionVerified', 'stateMutationAuthorized',
            'originalExpectationsAccepted', 'sourceOriginAuthenticated', 'sourceIndependenceAuthenticated', 'realBackendContacted',
            'sourceFileOpened', 'signaturesVerified', 'executionAuthorized', 'fullSystemRecoveryVerified', 'phase7Complete'):
            self.assertIs(value[name], False)
        return value

    def refused(self, kind='AuditExpectationInputException', **kwargs):
        result = self.invoke(**kwargs)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr, b'')
        value = json.loads(result.stdout)
        self.assertEqual(value['category'], 'unexpected')
        self.assertEqual(value['errorType'], kind)
        self.assertNotIn(CANARY.encode(), result.stdout)

    def test_exact_ascii_golden_preserves_literal_null_and_all_ten_fields(self):
        value = self.produce()
        self.assertEqual(len(value['knownEvents']), 4)
        for row, event in zip(self.snapshot['events'], value['knownEvents']):
            expected = json.dumps(strict.wire(row), separators=(',', ':'), ensure_ascii=True).encode()
            self.assertEqual(event, dict(eventId=row['event_id'], key=strict.B(('fleetory/audit/v1/' + row['event_id'].replace('-', '')).encode()),
                revision=1, valueSha256=H(expected)))

    def test_strict_default_still_rejects_same_null_member(self):
        self.refused(mode='audit-expectations')
        self.produce()
        self.refused(mode='audit-expectations')

    def test_historical_result_cannot_pass_strict_diagnostic_contract(self):
        import audit_expectation_diagnostic as diagnostic
        data = json.dumps(self.snapshot).encode()
        native = self.invoke(data=data)
        self.assertEqual(native.returncode, 0)
        with self.assertRaises(ValueError):
            diagnostic.diagnose(data, H(data), NONCE,
                lambda *_: diagnostic.NativeResult(native.returncode, native.stdout, native.stderr))

    def test_zero_or_multiple_null_members_are_not_this_fixed_profile(self):
        self.snapshot = strict.snapshot()
        self.refused()
        self.snapshot['events'][0]['context_json'] = '{"A":null,"B":null}'
        self.refused()
        self.snapshot['events'][0]['context_json'] = '{"A":null}'
        self.snapshot['events'][1]['context_json'] = '{"B":null}'
        self.refused()

    def test_null_is_not_coerced_to_empty_missing_or_literal_text(self):
        original = self.produce()['knownEvents'][0]['valueSha256']
        for context in ('{"Text":"value"}', '{"Optional":"","Text":"value"}', '{"Optional":"null","Text":"value"}'):
            self.snapshot['events'][0]['context_json'] = context
            self.snapshot['events'][1]['context_json'] = '{"RequiredProfileNull":null}'
            self.assertNotEqual(self.produce()['knownEvents'][0]['valueSha256'], original)

    def test_other_member_types_and_nonobject_context_roots_remain_refused(self):
        for item in (1, True, [], {}, 1.25):
            self.snapshot['events'][0]['context_json'] = json.dumps({'Optional': None, 'Other': item})
            self.refused()
        for text in ('null', '[]', '1', 'true', '"text"'):
            self.snapshot['events'][0]['context_json'] = text
            self.refused()

    def test_duplicate_names_keys_and_member_count_bounds_remain_refused(self):
        for text in ('{"Optional":null,"Optional":"value"}', '{" ":null}',
            json.dumps({'x' * 65: None}), json.dumps(dict(Optional=None, **{str(i): 'x' for i in range(16)}))):
            self.snapshot['events'][0]['context_json'] = text
            self.refused()

    def test_value_and_packet_bounds_remain_refused(self):
        self.snapshot['events'][0]['context_json'] = json.dumps(dict(Optional=None, A='x' * 1025))
        self.refused()
        self.snapshot['events'][0]['context_json'] = json.dumps(dict(Optional=None, **{str(i): 'x' * 1000 for i in range(9)}))
        self.refused(kind='AuditExpectationValueBoundException')
        self.refused(data=b' ' * (strict.MAXIMUM + 1))

    def test_actor_target_identity_pending_and_timestamp_guards_remain_strict(self):
        original = copy.deepcopy(self.snapshot)
        for name, value in (('actor_kind', 4), ('target_id', None), ('action', ' '),
            ('event_id', '00000000-0000-0000-0000-000000000000'), ('occurred_at', '1970-01-01T00:00:00Z')):
            self.snapshot = copy.deepcopy(original)
            self.snapshot['events'][0][name] = value
            self.refused()
        self.snapshot = original
        self.snapshot['pendingExportCount'] = 1
        self.refused()

    def test_snapshot_pin_nonce_and_attempted_profile_injection_are_rejected(self):
        self.refused(pin='0' * 64)
        self.refused(nonce='invalid')
        self.snapshot['profile'] = 'historical-one-null-member-readonly.v1'
        self.refused()

    def test_cli_arity_and_unrecognized_modes_cannot_fall_through(self):
        for args in ([MODE], [MODE, '0' * 64], [MODE, '0' * 64, NONCE, 'extra'],
            ['audit-expectations', '0' * 64, NONCE, '--historical'], [MODE + '-extra']):
            result = subprocess.run(['dotnet', str(PROBE), *args], input=CANARY.encode(), capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 64)
            self.assertEqual(result.stdout + result.stderr, b'')

    def test_context_order_unicode_and_whole_sql_null_are_preserved(self):
        self.snapshot['events'][0]['context_json'] = json.dumps({'Zulu': None, '\ue000': 'last', '𐀀': 'first'})
        self.snapshot['events'][1]['context_json'] = None
        first = self.produce()
        self.snapshot['events'][0]['context_json'] = json.dumps({'𐀀': 'first', '\ue000': 'last', 'Zulu': None})
        self.assertEqual(first['knownEvents'], self.produce()['knownEvents'])
        self.snapshot['events'][1]['context_json'] = '{}'
        self.assertNotEqual(first['knownEvents'][1], self.produce()['knownEvents'][1])

    def test_context_values_and_names_are_absent_from_metadata_output(self):
        self.snapshot['events'][0]['context_json'] = json.dumps({CANARY: None, 'Text': CANARY})
        result = self.invoke()
        self.assertEqual(result.returncode, 0)
        self.assertNotIn(CANARY.encode(), result.stdout + result.stderr)
        self.produce()

    def test_culture_timezone_and_exact_null_hash_remain_stable(self):
        first = self.produce()
        env = dict(os.environ, DOTNET_SYSTEM_GLOBALIZATION_INVARIANT='1', TZ='Pacific/Kiritimati')
        self.assertEqual(first['knownEvents'], self.produce(environment=env)['knownEvents'])

    def test_generated_scoped_source_integration_needs_one_file_and_cleanup(self):
        case = fixtures.AuditExpectationSourceTests('test_exactly_one_source_open_and_no_native_or_broad_apis')
        case.setUp()
        root = case.root
        try:
            case.snapshot['events'][0]['context_json'] = '{"Optional":null,"Text":"value"}'
            case.republish()
            captured = case.capture()
            value = self.produce(data=captured.snapshot)
            for row, event in zip(case.snapshot['events'], value['knownEvents']):
                expected = json.dumps(strict.wire(row), separators=(',', ':'), ensure_ascii=True).encode()
                self.assertEqual(event['valueSha256'], H(expected))
        finally:
            case.doCleanups()
        self.assertFalse(root.exists())


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--probe', required=True)
    args, remaining = parser.parse_known_args()
    PROBE = Path(args.probe).resolve(strict=True)
    if PROBE.name != 'ServerBackendProbe.dll':
        raise SystemExit('Unexpected historical probe.')
    unittest.main(argv=[sys.argv[0], *remaining])
