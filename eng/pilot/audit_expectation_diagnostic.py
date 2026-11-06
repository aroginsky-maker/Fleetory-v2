"""Bounded, metadata-only diagnosis of the existing closed expectation producer."""
from dataclasses import dataclass
import json

import audit_archive as archive
import audit_expectation_source as source
import fresh_server_pair as packet

MAX_OUTPUT = 16 * 1024
ERROR_FIELDS = 'category errorType causeType location controlStatus authenticationDenied tlsFailure'
ERROR_TYPES = frozenset(('AuditExpectationInputException', 'AuditExpectationValueBoundException',
    'AuditExpectationCaptureException', 'InvalidOperationException', 'ArgumentException', 'FormatException',
    'KeyNotFoundException', 'JsonException', 'OverflowException', 'OperationCanceledException', 'TaskCanceledException'))
LOCATIONS = frozenset(('Require', 'Parse', 'ParseRow', 'Context', 'Time', 'CaptureAsync', 'RequireFields',
    'ExecuteAsync', 'SerializeAsync', 'ReadAsync', 'MoveNext'))
FALSE_FLAGS = ('sourceOriginAuthenticated sourceIndependenceAuthenticated realBackendContacted sourceFileOpened '
    'signaturesVerified executionAuthorized fullSystemRecoveryVerified phase7Complete').split()


@dataclass(frozen=True)
class NativeResult:
    exit_code: int
    stdout: bytes
    stderr: bytes


def text_profile(value, limit):
    return (type(value) is str and bool(value.strip()) and '\0' not in value
        and len(value.encode('utf-16-le')) // 2 <= limit)


def context_profiles(value):
    if value is None:
        return True, True
    context = json.loads(value)
    if type(context) is not dict:
        return False, len(value.encode('utf-8')) <= 16384
    types = all(type(item) is str for item in context.values())
    bounds = (len(value.encode('utf-8')) <= 16384 and len(context) <= 16
        and all(text_profile(name, 64) for name in context)
        and all(type(item) is str and '\0' not in item and len(item.encode('utf-16-le')) // 2 <= 1024
            for item in context.values()))
    return types, bounds


def row_profiles(row):
    context_type, context_bound = context_profiles(row['context_json'])
    return dict(
        EVENT_ID_PROFILE=row['event_id'] != '00000000-0000-0000-0000-000000000000',
        ACTOR_KIND_PROFILE=0 <= row['actor_kind'] <= 3,
        REQUIRED_TEXT_PROFILE=all(text_profile(row[name], 128) for name in ('actor_subject_id', 'action', 'correlation_id')),
        TARGET_TEXT_PROFILE=all(row[name] is None or text_profile(row[name], bound)
            for name, bound in (('target_type', 64), ('target_id', 128))),
        TARGET_PAIR_PROFILE=(row['target_type'] is None) == (row['target_id'] is None),
        CONTEXT_TYPE_PROFILE=context_type, CONTEXT_BOUND_PROFILE=context_bound)


def advisory_rules(snapshot):
    profiles = [row_profiles(row) for row in snapshot['events']]
    return [dict(code=code, affectedRows=sum(not profile[code] for profile in profiles)) for code in sorted(profiles[0])]


def accepted_result(value, snapshot, expected_pin, nonce):
    packet.keys(value, ('category schema nonce snapshotSha256 knownEvents eventFields inMemoryRequests '
        + ' '.join(FALSE_FLAGS) + ' productionSinkSerializationUsed'))
    packet.require(value['category'] == 'audit-expectations' and value['schema'] == 'fleetory.audit-event-expectations.v1')
    packet.require(value['snapshotSha256'] == expected_pin and value['nonce'] == nonce)
    packet.require(type(value['eventFields']) is int and value['eventFields'] == 10)
    packet.require(type(value['inMemoryRequests']) is int and value['inMemoryRequests'] == 16)
    packet.require(value['productionSinkSerializationUsed'] is True and all(value[name] is False for name in FALSE_FLAGS))
    known = value['knownEvents']
    packet.require(type(known) is list and len(known) == 4)
    for event, row in zip(known, snapshot['events']):
        packet.keys(event, 'eventId key revision valueSha256')
        packet.require(packet.identity(event['eventId']) == row['event_id'])
        packet.require(type(event['revision']) is int and event['revision'] == 1)
        packet.hex_value(event['valueSha256'])
        key = ('fleetory/audit/v1/' + row['event_id'].replace('-', '')).encode()
        packet.require(packet.decode(event['key'], 128) == key)
    # Values, event IDs and keys are intentionally absent from the returned diagnostic.
    return dict(outcome='NATIVE_ACCEPTED_DIAGNOSTIC_ONLY', errorType='NONE', causeType='NONE', location='NONE', complete=True)


def fixed_name(value, allowed, absent='OTHER'):
    if value is None:
        return absent
    return value if value in allowed else 'OTHER'


def refused_result(value):
    packet.keys(value, ERROR_FIELDS)
    packet.require(value['category'] == 'unexpected')
    packet.require(all(value[name] is None for name in ('controlStatus', 'authenticationDenied', 'tlsFailure')))
    packet.require(type(value['errorType']) is str and type(value['location']) in (str, type(None)))
    packet.require(type(value['causeType']) in (str, type(None)))
    kind = fixed_name(value['errorType'], ERROR_TYPES)
    cause = fixed_name(value['causeType'], ERROR_TYPES, 'NONE')
    location = fixed_name(value['location'], LOCATIONS)
    outcomes = dict(AuditExpectationInputException='INPUT_PROFILE_REFUSED',
        AuditExpectationValueBoundException='SERIALIZED_VALUE_BOUND_REFUSED', AuditExpectationCaptureException='CAPTURE_PROTOCOL_REFUSED',
        InvalidOperationException='NATIVE_OPERATION_FAILURE', ArgumentException='NATIVE_OPERATION_FAILURE',
        FormatException='NATIVE_FORMAT_FAILURE', JsonException='NATIVE_FORMAT_FAILURE', OverflowException='NATIVE_OPERATION_FAILURE',
        KeyNotFoundException='NATIVE_FIELD_ACCESS_FAILURE', OperationCanceledException='NATIVE_DEADLINE_FAILURE', TaskCanceledException='NATIVE_DEADLINE_FAILURE')
    return dict(outcome=outcomes.get(kind, 'UNCLASSIFIED_NATIVE_FAILURE'), errorType=kind,
        causeType=cause, location=location, complete=kind in outcomes)


def diagnose(snapshot_bytes, expected_pin, nonce, invoke):
    packet.require(type(snapshot_bytes) in (bytes, bytearray) and 0 < len(snapshot_bytes) <= source.MAX_SNAPSHOT)
    frozen = bytes(snapshot_bytes)
    pin = packet.hex_value(expected_pin)
    identity = packet.identity(nonce)
    packet.require(packet.digest(frozen) == pin and callable(invoke))
    snapshot = archive.parse(frozen, source.MAX_SNAPSHOT)
    packet.require(len(archive.event_map(snapshot)) == 4 and snapshot['pendingExportCount'] == 0)
    rules = advisory_rules(snapshot)
    # One caller-owned measured invocation; this module has no process, socket or native backend API.
    try:
        native = invoke(frozen, pin, identity)
    except Exception:
        raise packet.PairError('Native diagnostic invocation failed.') from None
    packet.require(type(native) is NativeResult and type(native.exit_code) is int and native.exit_code in (0, 1))
    packet.require(type(native.stdout) is bytes and type(native.stderr) is bytes and not native.stderr)
    value = packet.strict_json(native.stdout, MAX_OUTPUT)
    result = accepted_result(value, snapshot, pin, identity) if native.exit_code == 0 else refused_result(value)
    return dict(schema='fleetory.audit-expectation-diagnostic.v1', nonce=identity, snapshotSha256=pin,
        nativeOutcome=result['outcome'], nativeErrorType=result['errorType'], nativeCauseType=result['causeType'],
        nativeLocation=result['location'], diagnosticComplete=result['complete'], advisoryRules=rules,
        advisoryRulesAreAuthoritative=False, nativeInvocations=1, expectedEvents=4, expectedFieldsPerEvent=10,
        nativeValuesDiscarded=True, originalExpectationsAccepted=False, sourceOriginAuthenticated=False,
        sourceIndependenceAuthenticated=False, realBackendContacted=False, signaturesVerified=False,
        executionAuthorized=False, fullSystemRecoveryVerified=False, phase7Complete=False)


def capture_diagnostic(root, metadata, expected_pins, nonce, invoke):
    packet.require(callable(invoke))
    captured = source.capture(root, metadata, expected_pins, nonce)
    result = diagnose(captured.snapshot, packet.digest(captured.snapshot), captured.nonce, invoke)
    return dict(source=captured.report(), diagnostic=result)
