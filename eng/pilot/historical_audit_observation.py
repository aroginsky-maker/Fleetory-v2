"""Historical-only observation envelopes. No file, process, restore or connection API."""
import hashlib
import json
import sys

import audit_observation as core
import fresh_server_pair as packet

EXPECTED = 'fleetory.historical-audit-observation-expectation.v1'
OBSERVED = 'fleetory.historical-audit-native-observation.v1'
PROFILE = 'historical-one-null-member-readonly.v1'
FALSE_FLAGS = ('sourceOriginAuthenticated sourceIndependenceAuthenticated realBackendContacted sourceFileOpened signaturesVerified '
    'executionAuthorized fullSystemRecoveryVerified phase7Complete strictContextValueTypesCompatible writerAdmissionVerified '
    'stateMutationAuthorized originalExpectationsAccepted').split()
COMPARISON_FIELDS = ('profile sourceExpectationSha256 snapshotSha256 sourceNonce knownValuesCommitment '
    'nullContextMembersPreserved historicalComparisonOnly writerAdmissionVerified stateMutationAuthorized '
    'sourceOriginAuthenticated sourceIndependenceAuthenticated executionAuthorized fullSystemRecoveryVerified phase7Complete')


def commitment(events):
    lines = ['fleetory.historical.known-values.v1']
    for item in events:
        lines.extend((item['eventId'], item['key'], str(item['revision']), item['valueSha256']))
    return hashlib.sha256(('\n'.join(lines) + '\n').encode('ascii')).hexdigest()


def comparison(value, events):
    packet.keys(value, COMPARISON_FIELDS)
    packet.require(value['profile'] == PROFILE and value['historicalComparisonOnly'] is True)
    core.integer(value['nullContextMembersPreserved'], 1, 1)
    for name in ('sourceExpectationSha256', 'snapshotSha256', 'knownValuesCommitment'):
        packet.hex_value(value[name])
    packet.identity(value['sourceNonce'])
    packet.require(value['knownValuesCommitment'] == commitment(events))
    packet.require(all(value[name] is False for name in ('writerAdmissionVerified', 'stateMutationAuthorized', 'sourceOriginAuthenticated',
        'sourceIndependenceAuthenticated', 'executionAuthorized', 'fullSystemRecoveryVerified', 'phase7Complete')))
    ids = [item['eventId'] for item in events]
    packet.require(ids == sorted(ids))


def source_values(data, pin):
    packet.require(type(data) in (bytes, bytearray) and 0 < len(data) <= core.MAX_EXPECTED)
    frozen = bytes(data)
    digest = packet.hex_value(pin)
    packet.require(packet.digest(frozen) == digest)
    value = packet.strict_json(frozen, core.MAX_EXPECTED)
    packet.keys(value, ('category schema nonce snapshotSha256 knownEvents eventFields inMemoryRequests productionSinkSerializationUsed '
        'profile nullContextMembersPreserved productionPumpDeserializationUsed historicalComparisonOnly ' + ' '.join(FALSE_FLAGS)))
    packet.require(value['category'] == 'audit-history-expectations' and value['schema'] == 'fleetory.audit-historical-expectations.v1')
    packet.require(value['profile'] == PROFILE)
    packet.identity(value['nonce'])
    packet.hex_value(value['snapshotSha256'])
    for name, number in (('eventFields', 10), ('inMemoryRequests', 16), ('nullContextMembersPreserved', 1)):
        core.integer(value[name], number, number)
    packet.require(all(value[name] is True for name in ('productionSinkSerializationUsed', 'productionPumpDeserializationUsed', 'historicalComparisonOnly')))
    packet.require(all(value[name] is False for name in FALSE_FLAGS))
    return value, digest


def build(source_bytes, source_pin, nonce, point, producer):
    value, pin = source_values(source_bytes, source_pin)
    # Round-trip external objects once; no mutable caller object is retained.
    expected = json.loads(core.canonical(dict(schema=core.EXPECTATION, nonce=packet.identity(nonce),
        point=point, producer=producer, knownEvents=value['knownEvents'])))
    core.expectation(expected)
    expected['schema'] = EXPECTED
    expected['comparison'] = dict(profile=PROFILE, sourceExpectationSha256=pin, snapshotSha256=value['snapshotSha256'],
        sourceNonce=value['nonce'], knownValuesCommitment=commitment(expected['knownEvents']), nullContextMembersPreserved=1,
        historicalComparisonOnly=True, writerAdmissionVerified=False, stateMutationAuthorized=False,
        sourceOriginAuthenticated=False, sourceIndependenceAuthenticated=False, executionAuthorized=False,
        fullSystemRecoveryVerified=False, phase7Complete=False)
    expectation(expected)
    packet.require(len(core.canonical(expected)) <= core.MAX_EXPECTED)
    return expected


def expectation(value):
    packet.keys(value, 'schema nonce point knownEvents producer comparison')
    packet.require(value['schema'] == EXPECTED)
    projected = {name: item for name, item in value.items() if name != 'comparison'}
    projected['schema'] = core.EXPECTATION
    core.expectation(projected)
    comparison(value['comparison'], value['knownEvents'])
    return projected


def observe(expected_bytes, expected_pin, observed_bytes):
    packet.require(type(expected_bytes) in (bytes, bytearray) and 0 < len(expected_bytes) <= core.MAX_EXPECTED)
    packet.require(type(observed_bytes) in (bytes, bytearray) and 0 < len(observed_bytes) <= core.MAX_OBSERVED)
    pin, frozen_expected, frozen_observed = packet.hex_value(expected_pin), bytes(expected_bytes), bytes(observed_bytes)
    packet.require(packet.digest(frozen_expected) == pin)
    expected = packet.strict_json(frozen_expected, core.MAX_EXPECTED)
    observed = packet.strict_json(frozen_observed, core.MAX_OBSERVED)
    projected_expected = expectation(expected)
    packet.keys(observed, 'category schema nonce stateBefore stateAfter scan transactions executionAuthorized independentInclusionProofsVerified producer comparison')
    packet.require(observed['category'] == 'observation-history-read' and observed['schema'] == OBSERVED)
    comparison(observed['comparison'], expected['knownEvents'])
    packet.require(observed['comparison'] == expected['comparison'])
    projected_observed = {name: item for name, item in observed.items() if name != 'comparison'}
    projected_observed.update(category='observation-read', schema=core.SCHEMA)
    # Reuse bounded data witnesses internally; no strict receipt is exposed by this API.
    body = core.canonical(projected_expected)
    checked = core.observe(body, packet.digest(body), core.canonical(projected_observed))
    checked.update(schema=OBSERVED, expectedSha256=pin, comparison=dict(expected['comparison']),
        historicalComparisonOnly=True, writerAdmissionVerified=False, stateMutationAuthorized=False,
        originalStrictExpectationsAccepted=False, sourceOriginAuthenticated=False, sourceIndependenceAuthenticated=False)
    return checked


def run():
    packet.require(len(sys.argv) == 2 and sys.argv[1] in ('build', 'observe'))
    body = packet.strict_json(sys.stdin.buffer.read(core.MAX_BODY + 1), core.MAX_BODY)
    if sys.argv[1] == 'build':
        packet.keys(body, 'sourceBase64 sourceSha256 nonce point producer')
        return build(packet.decode(body['sourceBase64'], core.MAX_EXPECTED), body['sourceSha256'], body['nonce'], body['point'], body['producer'])
    packet.keys(body, 'expectedBase64 expectedSha256 observedBase64')
    return observe(packet.decode(body['expectedBase64'], core.MAX_EXPECTED), body['expectedSha256'], packet.decode(body['observedBase64'], core.MAX_OBSERVED))


if __name__ == '__main__':
    try:
        result = run()
    except Exception:
        print('Historical observation refused; no paths, values or credentials logged.', file=sys.stderr)
        sys.exit(1)
    # build emits hash/identity metadata for a private owning pipe; never log original packets.
    print(json.dumps(result, sort_keys=True))
