"""Bounded observation consistency; no I/O, signature verification or execution authority."""
import base64
import hashlib
import json
import sys

import fresh_server_pair as packet

SCHEMA = 'fleetory.audit-native-observation.v1'
EXPECTATION = 'fleetory.audit-observation-expectation.v1'
MAX_EXPECTED = 4096
MAX_OBSERVED = 128 * 1024
MAX_BODY = 180 * 1024


def integer(value, low, high):
    packet.require(type(value) is int and low <= value <= high)
    return value


def sequence(value, low, high):
    packet.require(type(value) is list and low <= len(value) <= high)
    return value


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def producer(value):
    packet.keys(value, 'containerId imageId probeSha256')
    packet.hex_value(value['containerId'])
    packet.hex_value(value['probeSha256'])
    packet.require(type(value['imageId']) is str and value['imageId'].startswith('sha256:'))
    packet.hex_value(value['imageId'][7:])


def expectation(value):
    packet.keys(value, 'schema nonce point knownEvents producer')
    packet.require(value['schema'] == EXPECTATION)
    packet.identity(value['nonce'])
    producer(value['producer'])
    point = value['point']
    packet.keys(point, 'database tx txHash')
    packet.require(point['database'] == 'fleetoryaudit' and integer(point['tx'], 5, 5) == 5)
    packet.require(len(packet.decode(point['txHash'], 32)) == 32)
    events = {}
    for event in sequence(value['knownEvents'], 4, 4):
        packet.keys(event, 'eventId key revision valueSha256')
        event_id = packet.identity(event['eventId']).replace('-', '')
        key = ('fleetory/audit/v1/' + event_id).encode()
        packet.require(base64.b64encode(key).decode() == event['key'])
        integer(event['revision'], 1, 1)
        packet.hex_value(event['valueSha256'])
        digest = packet.digest(key)
        packet.require(digest not in events)
        events[digest] = event
    return events


def state(value, point):
    packet.keys(value, 'db txId txHash signature precommittedTxId precommittedTxHash')
    packet.require(value['db'] == point['database'] and value['txId'] == '5' and value['precommittedTxId'] == '5')
    packet.require(value['txHash'] == point['txHash'] == value['precommittedTxHash'])
    packet.keys(value['signature'], 'publicKey signature')
    public_key = packet.decode(value['signature']['publicKey'], 65)
    packet.require(len(public_key) == 65 and public_key[0] == 4)
    packet.require(64 <= len(packet.decode(value['signature']['signature'], 80)) <= 80)


def transactions(value):
    records = {}
    for index, tx in enumerate(sequence(value, 5, 5), start=1):
        packet.keys(tx, 'id headerSha256 count entries')
        packet.require(integer(tx['id'], 1, 5) == index)
        packet.hex_value(tx['headerSha256'])
        rows = sequence(tx['entries'], 1, 16)
        packet.require(integer(tx['count'], 1, 16) == len(rows))
        seen = set()
        for row in rows:
            packet.keys(row, 'prefix keySha256 valueSha256 valueBytes metadataSha256')
            integer(row['prefix'], 0, 255)
            integer(row['valueBytes'], 0, 1048576)
            for name in ('keySha256', 'valueSha256', 'metadataSha256'):
                packet.hex_value(row[name])
            packet.require(row['keySha256'] not in seen)
            seen.add(row['keySha256'])
        records[index] = tx
    return records


def known_witness(entry, event, native):
    packet.require(entry['revision'] == 1 and entry['valueSha256'] == event['valueSha256'])
    expected_key = packet.digest(b'\x00' + packet.decode(event['key'], 512))
    packet.require(entry['storageKeySha256'] == expected_key)
    witness = entry['witness']
    packet.keys(witness, 'historyCount historyRevision historyTx historyValueSha256 resolvedTx resolvedValueSha256 headerSha256')
    for name in ('historyCount', 'historyRevision'):
        integer(witness[name], 1, 1)
    for name in ('historyTx', 'resolvedTx'):
        packet.require(integer(witness[name], 1, 5) == entry['tx'])
    packet.require(witness['historyValueSha256'] == witness['resolvedValueSha256'] == entry['valueSha256'])
    packet.require(witness['headerSha256'] == native[entry['tx']]['headerSha256'])
    matching = [(tx['id'], row) for tx in native.values() for row in tx['entries'] if row['keySha256'] == expected_key]
    packet.require(len(matching) == 1)
    tx_id, raw = matching[0]
    packet.require(tx_id == entry['tx'] and raw['prefix'] == 0 and raw['valueBytes'] == entry['valueBytes'] + 1)
    packet.require(raw['valueSha256'] == entry['storageValueSha256'] and raw['metadataSha256'] == packet.digest(b'null'))


def scan(value, events, native):
    packet.keys(value, 'prefix limit entries')
    packet.require(value['prefix'] == '' and integer(value['limit'], 17, 17) == 17)
    seen, storage = set(), set()
    entries = sequence(value['entries'], 4, 16)
    for entry in entries:
        packet.keys(entry, 'keySha256 storageKeySha256 tx revision valueSha256 valueBytes storageValueSha256 witness')
        for name in ('keySha256', 'storageKeySha256', 'valueSha256', 'storageValueSha256'):
            packet.hex_value(entry[name])
        integer(entry['tx'], 1, 5)
        integer(entry['revision'], 1, 5)
        integer(entry['valueBytes'], 0, 8192)
        key = entry['keySha256']
        packet.require(key not in seen and entry['storageKeySha256'] not in storage)
        seen.add(key)
        storage.add(entry['storageKeySha256'])
        if key in events:
            known_witness(entry, events[key], native)
        else:
            packet.require(entry['witness'] is None)
    packet.require(set(events).issubset(seen))
    return entries


def observe(expected_bytes, expected_pin, observed_bytes):
    # Freeze all external inputs before parsing caller-controlled objects.
    pin = packet.hex_value(expected_pin)
    frozen = []
    for data, bound in ((expected_bytes, MAX_EXPECTED), (observed_bytes, MAX_OBSERVED)):
        packet.require(type(data) in (bytes, bytearray) and 0 < len(data) <= bound)
        frozen.append(bytes(data))
    packet.require(packet.digest(frozen[0]) == pin)
    expected, observed = (packet.strict_json(data, bound) for data, bound in zip(frozen, (MAX_EXPECTED, MAX_OBSERVED)))
    events = expectation(expected)
    packet.keys(observed, 'category schema nonce stateBefore stateAfter scan transactions executionAuthorized independentInclusionProofsVerified producer')
    packet.require(observed['category'] == 'observation-read' and observed['schema'] == SCHEMA and observed['nonce'] == expected['nonce'])
    packet.require(observed['producer'] == expected['producer'])
    packet.require(observed['executionAuthorized'] is False and observed['independentInclusionProofsVerified'] is False)
    for name in ('stateBefore', 'stateAfter'):
        state(observed[name], expected['point'])
    native = transactions(observed['transactions'])
    entries = scan(observed['scan'], events, native)
    known_storage = {entry['storageKeySha256'] for entry in entries if entry['keySha256'] in events}
    extra = [row for tx in native.values() for row in tx['entries'] if row['keySha256'] not in known_storage]
    prefixes = {str(prefix): sum(row['prefix'] == prefix for row in extra) for prefix in sorted({row['prefix'] for row in extra})}
    fingerprint = packet.digest(canonical(dict(scan=sorted(entries, key=lambda item: item['keySha256']), transactions=list(native.values()))))
    return dict(schema=SCHEMA, knownEvents=4, currentKvKeys=len(entries), nativeTransactions=5,
                unknownCurrentKvKeys=len(entries) - 4, unreviewedRawEntries=len(extra), unreviewedPrefixes=prefixes,
                observationSha256=fingerprint, expectedSha256=pin, pointMatched=True, knownEventBindingsMatched=True,
                currentPlainKvScanBoundSatisfied=True, additionalStateReviewed=False, wholeKeyspaceVerified=False,
                signaturesVerified=False, producerMeasurementAuthenticated=False, independentInclusionProofsVerified=False,
                startupAuthorized=False, executionAuthorized=False, fullSystemRecoveryVerified=False, phase7Complete=False)


def run():
    packet.require(len(sys.argv) == 1)
    body = packet.strict_json(sys.stdin.buffer.read(MAX_BODY + 1), MAX_BODY)
    packet.keys(body, 'expectedBase64 expectedSha256 observedBase64')
    return observe(packet.decode(body['expectedBase64'], MAX_EXPECTED), body['expectedSha256'],
                   packet.decode(body['observedBase64'], MAX_OBSERVED))


if __name__ == '__main__':
    try:
        result = run()
    except Exception:
        print('Audit observation refused; no contents logged.', file=sys.stderr)
        sys.exit(1)
    print(json.dumps(result, sort_keys=True))
