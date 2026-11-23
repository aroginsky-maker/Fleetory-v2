"""Generated PostgreSQL snapshots -> native production serialization; no real backend."""
import argparse
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

PROBE = None
NONCE = '00000000-0000-4000-8000-000000000001'
MAXIMUM = 128 * 1024
H = lambda data: hashlib.sha256(data).hexdigest()
B = lambda data: base64.b64encode(data).decode()


def snapshot():
    events = []
    for index in range(1, 5):
        events.append(dict(event_id=f'00000000-0000-4000-8000-{index:012d}', actor_subject_id='Actor' + str(index),
            actor_kind=index - 1, action='Action' + str(index), target_type='Device', target_id='Target' + str(index),
            correlation_id='Correlation' + str(index), occurred_at=f'1970-01-01T00:00:0{index}.000000Z',
            recorded_at=f'1970-01-01T00:00:1{index}.000000Z', context_json='{"Zulu":"last","Alpha":"first"}'))
    return dict(schema='fleetory.audit-snapshot.v1', pendingExportCount=0, events=events)


def wire(row):
    # Independent ASCII golden vector for exact field mapping/order, not a replacement serializer.
    return dict(eventId=row['event_id'].replace('-', ''), actorSubjectId=row['actor_subject_id'], actorKind=row['actor_kind'],
        Action=row['action'], targetType=row['target_type'], targetId=row['target_id'], correlationId=row['correlation_id'],
        occurredAt=row['occurred_at'].replace('.000000Z', '+00:00'), recordedAt=row['recorded_at'].replace('.000000Z', '+00:00'),
        context=None if row['context_json'] is None else dict(sorted(json.loads(row['context_json']).items())))


class AuditEventExpectationTests(unittest.TestCase):
    def setUp(self):
        self.source = snapshot()

    def invoke(self, data=None, pin=None, nonce=NONCE, environment=None):
        data = json.dumps(self.source, ensure_ascii=True, separators=(',', ':')).encode() if data is None else data
        return subprocess.run(['dotnet', str(PROBE), 'audit-expectations', pin or H(data), nonce], input=data,
            capture_output=True, timeout=25, env=environment)

    def produce(self, **kwargs):
        result = self.invoke(**kwargs)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stderr, b'')
        value = json.loads(result.stdout)
        self.assertEqual(value['category'], 'audit-expectations')
        self.assertEqual(value['schema'], 'fleetory.audit-event-expectations.v1')
        self.assertEqual(value['nonce'], kwargs.get('nonce', NONCE))
        self.assertEqual(value['inMemoryRequests'], 16)
        self.assertEqual(value['eventFields'], 10)
        self.assertIs(value['productionSinkSerializationUsed'], True)
        for name in ('sourceOriginAuthenticated', 'sourceIndependenceAuthenticated', 'realBackendContacted', 'sourceFileOpened',
                     'signaturesVerified', 'executionAuthorized', 'fullSystemRecoveryVerified', 'phase7Complete'):
            self.assertIs(value[name], False)
        return value

    def refused(self, expected_type='AuditExpectationInputException', **kwargs):
        result = self.invoke(**kwargs)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr, b'')
        failure = json.loads(result.stdout)
        self.assertEqual(failure['category'], 'unexpected')
        self.assertEqual(failure['errorType'], expected_type, 'Operational error cannot count as data refusal.')
        self.assertNotIn(b'PRIVATE_INPUT_CANARY', result.stdout)
        return result

    def test_exact_ascii_golden_serialization_for_all_ten_fields(self):
        value = self.produce()
        self.assertEqual(len(value['knownEvents']), 4)
        for row, known in zip(self.source['events'], value['knownEvents']):
            expected = json.dumps(wire(row), separators=(',', ':'), ensure_ascii=True).encode()
            self.assertEqual(known, dict(eventId=row['event_id'], key=B(('fleetory/audit/v1/' + row['event_id'].replace('-', '')).encode()),
                                         revision=1, valueSha256=H(expected)))

    def test_each_independent_field_changes_its_expected_value(self):
        baseline = self.produce()['knownEvents'][-1]['valueSha256']
        changes = dict(event_id='00000000-0000-4000-8000-000000000005', actor_subject_id='DifferentActor', actor_kind=1,
            action='DifferentAction', target_type='OtherType', target_id='OtherId', correlation_id='DifferentCorrelation',
            occurred_at='1970-01-01T00:00:04.000001Z', recorded_at='1970-01-01T00:00:14.123456Z', context_json='{"Changed":"yes"}')
        for name, value in changes.items():
            self.source = snapshot()
            self.source['events'][-1][name] = value
            with self.subTest(name=name):
                self.assertNotEqual(self.produce()['knownEvents'][-1]['valueSha256'], baseline)

    def test_context_order_does_not_change_production_value(self):
        first = self.produce()
        self.source['events'][0]['context_json'] = '{ "Alpha":"first", "Zulu":"last" }'
        second = self.produce()
        self.assertNotEqual(first['snapshotSha256'], second['snapshotSha256'])
        self.assertEqual(first['knownEvents'], second['knownEvents'])

    def test_unicode_ordinal_context_escaping_and_microseconds(self):
        self.source['events'][0].update(actor_subject_id='Пользователь𐀀', action='Чтение "quote" \\ slash <>&\' café',
            context_json=json.dumps({'\ue000': 'last', '𐀀': 'first', 'A': '\nline\tquote"\\'}),
            occurred_at='2026-01-02T03:04:05.000100Z', recorded_at='2026-01-02T03:04:06.123456Z')
        first = self.produce()
        self.source['events'][0]['context_json'] = json.dumps({'A': '\nline\tquote"\\', '𐀀': 'first', '\ue000': 'last'})
        self.assertEqual(self.produce()['knownEvents'], first['knownEvents'])

    def test_null_target_and_context_are_distinct_from_empty_context(self):
        self.source['events'][0].update(target_type=None, target_id=None, context_json=None)
        null = self.produce()['knownEvents'][0]['valueSha256']
        self.source['events'][0]['context_json'] = '{}'
        empty = self.produce()['knownEvents'][0]['valueSha256']
        self.assertNotEqual(null, empty)

    def test_stale_pin_and_mixed_snapshot_refused(self):
        pinned = json.dumps(self.source).encode()
        self.source['events'][0]['action'] = 'PRIVATE_INPUT_CANARY'
        self.refused(pin=H(pinned))
        first = self.produce()
        self.assertEqual(first['snapshotSha256'], H(json.dumps(self.source, ensure_ascii=True, separators=(',', ':')).encode()))
        # A new pin is a caller declaration, not authenticated capture provenance.
        self.assertIs(first['sourceOriginAuthenticated'], False)

    def test_wrong_missing_extra_and_duplicate_snapshot_fields(self):
        for change in ('schema', 'pending', 'extra', 'missing', 'events-type'):
            self.source = snapshot()
            if change == 'schema':
                self.source['schema'] = 'fleetory.audit-native-observation.v1'
            elif change == 'pending':
                self.source['pendingExportCount'] = 1
            elif change == 'extra':
                self.source['approved'] = True
            elif change == 'missing':
                self.source.pop('pendingExportCount')
            else:
                self.source['events'] = {}
            self.refused()
        self.refused(data=b'{"schema":"x","schema":"y","events":[],"pendingExportCount":0}')

    def test_uuid_duplicates_order_and_four_event_profile(self):
        for change in ('empty', 'upper', 'invalid', 'duplicate', 'reorder', 'missing', 'extra'):
            self.source = snapshot()
            rows = self.source['events']
            if change == 'empty':
                rows[0]['event_id'] = '00000000-0000-0000-0000-000000000000'
            elif change == 'upper':
                rows[-1]['event_id'] = 'FFFFFFFF-FFFF-4000-8000-000000000004'
            elif change == 'invalid':
                rows[0]['event_id'] = 'invalid'
            elif change == 'duplicate':
                rows[1] = copy.deepcopy(rows[0])
            elif change == 'reorder':
                rows.reverse()
            elif change == 'missing':
                rows.pop()
            else:
                rows.append(copy.deepcopy(rows[-1]))
            self.refused()

    def test_field_nullability_lengths_and_incomplete_target(self):
        for field, value in (('actor_subject_id', None), ('action', ''), ('action', ' '), ('action', 'x' * 129),
                            ('actor_subject_id', '𐀀' * 65), ('correlation_id', 'x' * 129), ('target_type', 'x' * 65),
                            ('target_id', 'x' * 129), ('target_id', None), ('target_type', None), ('action', 'a\0b')):
            self.source = snapshot()
            self.source['events'][0][field] = value
            with self.subTest(field=field):
                self.refused()

    def test_actor_and_pending_integer_type_confusion(self):
        for value in (True, -1, 4, 1.0, '1', None):
            self.source = snapshot()
            self.source['events'][0]['actor_kind'] = value
            self.refused()
        for value in (True, 0.0, '0', None, -1):
            self.source = snapshot()
            self.source['pendingExportCount'] = value
            self.refused()

    def test_context_duplicate_nested_nonstring_limits_and_null_values(self):
        for value in ('{"A":"x","A":"y"}', '[]', 'null', '{"A":1}', '{"A":true}', '{"A":null}', '{"A":{}}',
                      '{" ":"x"}', json.dumps({'x' * 65: 'v'}), json.dumps({'A': 'x' * 1025}),
                      json.dumps({str(i): 'v' for i in range(17)}), '{' + ' ' * 16384 + '}'):
            self.source = snapshot()
            self.source['events'][0]['context_json'] = value
            self.refused()

    def test_strict_utc_microsecond_profile_rejects_lossy_normalization(self):
        for value in ('2026-01-01T00:00:00Z', '2026-01-01T00:00:00.1234567Z', '2026-01-01T00:00:00.000000+00:00',
                      '2026-01-01T00:00:00.000000+03:00', '2026-02-30T00:00:00.000000Z', None):
            self.source = snapshot()
            self.source['events'][0]['occurred_at'] = value
            self.refused()

    def test_row_missing_extra_and_duplicate_fields(self):
        self.source['events'][0].pop('recorded_at')
        self.refused()
        self.source = snapshot()
        self.source['events'][0]['valueSha256'] = '0' * 64
        self.refused()
        self.source = snapshot()
        raw = json.dumps(self.source).replace('"event_id":', '"event_id":"duplicate", "event_id":', 1).encode()
        self.refused(data=raw)

    def test_empty_invalid_utf8_nonfinite_depth_and_packet_bounds(self):
        for raw in (b'', b'\xff', b'{', b'{"x":NaN}', b'[' * 20 + b']' * 20, b' ' * (MAXIMUM + 1)):
            self.refused(data=raw)

    def test_external_pin_nonce_and_no_input_contents_in_output(self):
        self.source['events'][0]['action'] = 'PRIVATE_INPUT_CANARY'
        for value in ('0' * 64, 'A' * 64, 'bad-pin'):
            self.refused(pin=value)
        for nonce in ('bad', '00000000-0000-0000-0000-000000000000'):
            self.refused(nonce=nonce)
        result = self.invoke()
        self.assertEqual(result.returncode, 0)
        self.assertNotIn(b'PRIVATE_INPUT_CANARY', result.stdout + result.stderr)

    def test_culture_timezone_and_wire_expectations_remain_stable(self):
        first = self.produce()
        environment = dict(os.environ, DOTNET_SYSTEM_GLOBALIZATION_INVARIANT='1', TZ='Pacific/Kiritimati')
        second = self.produce(environment=environment)
        self.assertEqual(first['knownEvents'], second['knownEvents'])

    def test_production_value_bound_matches_observer_profile(self):
        self.source['events'][0]['context_json'] = json.dumps({str(i): 'x' * 900 for i in range(7)})
        self.produce()
        self.source['events'][0]['context_json'] = json.dumps({str(i): 'x' * 1000 for i in range(9)})
        self.refused(expected_type='AuditExpectationValueBoundException')
        self.source['events'][0]['context_json'] = json.dumps({str(i): '界' * 512 for i in range(3)}, ensure_ascii=False)
        self.refused(expected_type='AuditExpectationValueBoundException')

    def test_observer_known_event_frame_compatible_without_native_read(self):
        sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'eng' / 'pilot'))
        import audit_observation
        value = self.produce()
        frame = dict(schema=audit_observation.EXPECTATION, nonce=NONCE,
            point=dict(database='fleetoryaudit', tx=5, txHash=B(b'x' * 32)), knownEvents=value['knownEvents'],
            producer=dict(containerId='a' * 64, imageId='sha256:' + 'b' * 64, probeSha256=H(PROBE.read_bytes())))
        self.assertEqual(len(audit_observation.expectation(frame)), 4)

    def test_cli_arity_cannot_fall_through_into_other_probe_modes(self):
        for args in (['audit-expectations'], ['audit-expectations', '0' * 64], ['audit-expectations', '0' * 64, NONCE, 'extra'], ['db-ready', 'extra']):
            result = subprocess.run(['dotnet', str(PROBE), *args], input=b'PRIVATE_INPUT_CANARY', capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 64)
            self.assertEqual(result.stdout + result.stderr, b'')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--probe', required=True)
    arguments, remaining = parser.parse_known_args()
    PROBE = Path(arguments.probe).resolve(strict=True)
    if PROBE.suffix != '.dll' or PROBE.name != 'ServerBackendProbe.dll':
        raise SystemExit('Unexpected expectation probe.')
    unittest.main(argv=[sys.argv[0], *remaining])
