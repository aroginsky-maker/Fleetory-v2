"""Generated bounded observation contracts; no native data or signing material."""
import base64
import copy
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'eng' / 'pilot'))
import audit_observation as policy

NONCE = '00000000-0000-4000-8000-000000000001'
H = policy.packet.digest
B = lambda value: base64.b64encode(value).decode()


def dataset(extra_prefix=1, extra_kv=False):
    point = dict(database='fleetoryaudit', tx=5, txHash=B(b't' * 32))
    producer = dict(containerId='c' * 64, imageId='sha256:' + 'd' * 64, probeSha256='e' * 64)
    expected = dict(schema=policy.EXPECTATION, nonce=NONCE, point=point, knownEvents=[], producer=producer)
    state = dict(db='fleetoryaudit', txId='5', txHash=point['txHash'], precommittedTxId='5',
                 precommittedTxHash=point['txHash'], signature=dict(publicKey=B(b'\x04' + b'p' * 64), signature=B(b's' * 70)))
    observed = dict(category='observation-read', schema=policy.SCHEMA, nonce=NONCE, stateBefore=state,
                    stateAfter=copy.deepcopy(state), producer=copy.deepcopy(producer),
                    scan=dict(prefix='', limit=17, entries=[]), transactions=[], executionAuthorized=False,
                    independentInclusionProofsVerified=False)
    for index in range(1, 6):
        header = H(str(index).encode())
        key = ('fleetory/audit/v1/' + f'{index:032x}').encode() if index < 5 else b'unreviewed'
        value = ('value-' + str(index)).encode()
        raw = dict(prefix=0 if index < 5 else extra_prefix, keySha256=H(b'\0' + key),
                   valueSha256=H(b'\0' + value), valueBytes=len(value) + 1, metadataSha256=H(b'null'))
        observed['transactions'].append(dict(id=index, headerSha256=header, count=1, entries=[raw]))
        if index < 5:
            event_id = str(policy.packet.uuid.UUID(hex=f'{index:032x}'))
            expected['knownEvents'].append(dict(eventId=event_id, key=B(key), revision=1, valueSha256=H(value)))
        if index < 5 or extra_kv:
            witness = dict(historyCount=1, historyRevision=1, historyTx=index, historyValueSha256=H(value),
                           resolvedTx=index, resolvedValueSha256=H(value), headerSha256=header) if index < 5 else None
            observed['scan']['entries'].append(dict(keySha256=H(key), storageKeySha256=H(b'\0' + key), tx=index,
                revision=1, valueSha256=H(value), valueBytes=len(value), storageValueSha256=H(b'\0' + value), witness=witness))
    return expected, observed


class ObservationTests(unittest.TestCase):
    def setUp(self):
        self.expected, self.observed = dataset()

    def observe(self):
        data = json.dumps(self.expected).encode()
        return policy.observe(data, H(data), json.dumps(self.observed).encode())

    def refused(self):
        with self.assertRaises((ValueError, TypeError, KeyError)):
            self.observe()

    def test_four_keys_five_transactions_does_not_invent_fifth_event(self):
        result = self.observe()
        self.assertEqual((result['currentKvKeys'], result['nativeTransactions'], result['knownEvents']), (4, 5, 4))
        self.assertEqual(result['unreviewedPrefixes'], {'1': 1})
        self.assertFalse(result['wholeKeyspaceVerified'])
        self.assertFalse(result['additionalStateReviewed'])

    def test_five_keys_five_transactions_retains_unknown_kv(self):
        self.expected, self.observed = dataset(extra_prefix=0, extra_kv=True)
        result = self.observe()
        self.assertEqual((result['currentKvKeys'], result['unknownCurrentKvKeys'], result['unreviewedRawEntries']), (5, 1, 1))
        self.assertEqual(result['unreviewedPrefixes'], {'0': 1})

    def test_unknown_sql_document_and_future_prefixes_remain_unreviewed(self):
        for prefix in (2, 3, 255):
            self.expected, self.observed = dataset(extra_prefix=prefix)
            result = self.observe()
            self.assertEqual(result['unreviewedPrefixes'], {str(prefix): 1})
            self.assertFalse(result['additionalStateReviewed'])

    def test_missing_extra_and_reordered_transactions(self):
        for change in ('missing', 'extra', 'order', 'count', 'duplicate-key'):
            self.setUp()
            tx = self.observed['transactions']
            if change == 'missing':
                tx.pop()
            elif change == 'extra':
                tx.append(copy.deepcopy(tx[-1]))
            elif change == 'order':
                tx.reverse()
            elif change == 'count':
                tx[0]['count'] = 2
            else:
                tx[0]['entries'] *= 2
                tx[0]['count'] = 2
            with self.subTest(change=change):
                self.refused()

    def test_known_revision_value_and_storage_binding_mutations(self):
        for name, value in (('revision', 2), ('valueSha256', 'a' * 64), ('storageKeySha256', 'b' * 64),
                            ('storageValueSha256', 'b' * 64), ('tx', 5), ('valueBytes', 1)):
            self.setUp()
            self.observed['scan']['entries'][0][name] = value
            with self.subTest(name=name):
                self.refused()

    def test_history_resolved_header_and_raw_native_digest_mutations(self):
        for name in ('historyCount', 'historyRevision', 'historyTx', 'historyValueSha256', 'resolvedTx', 'resolvedValueSha256', 'headerSha256'):
            self.setUp()
            witness = self.observed['scan']['entries'][0]['witness']
            witness[name] = 2 if type(witness[name]) is int else 'b' * 64
            with self.subTest(name=name):
                self.refused()
        for name, value in (('prefix', 1), ('valueSha256', 'b' * 64), ('valueBytes', 0), ('metadataSha256', 'b' * 64)):
            self.setUp()
            self.observed['transactions'][0]['entries'][0][name] = value
            with self.subTest(raw=name):
                self.refused()

    def test_missing_duplicate_and_extra_known_keys(self):
        for change in ('missing', 'duplicate', 'unknown-witness', 'duplicate-raw-known'):
            self.setUp()
            entries = self.observed['scan']['entries']
            if change == 'missing':
                entries.pop()
            elif change == 'duplicate':
                entries.append(copy.deepcopy(entries[0]))
            elif change == 'unknown-witness':
                self.expected, self.observed = dataset(extra_prefix=0, extra_kv=True)
                self.observed['scan']['entries'][-1]['witness'] = copy.deepcopy(self.observed['scan']['entries'][0]['witness'])
            else:
                self.observed['transactions'][-1]['entries'].append(copy.deepcopy(self.observed['transactions'][0]['entries'][0]))
                self.observed['transactions'][-1]['count'] = 2
            self.refused()

    def test_nonce_producer_authority_and_extra_fields(self):
        for change in ('nonce', 'producer', 'authority', 'proof', 'path'):
            self.setUp()
            if change == 'nonce':
                self.observed['nonce'] = '00000000-0000-4000-8000-000000000002'
            elif change == 'producer':
                self.observed['producer']['probeSha256'] = 'b' * 64
            elif change == 'authority':
                self.observed['executionAuthorized'] = True
            elif change == 'proof':
                self.observed['independentInclusionProofsVerified'] = True
            else:
                self.observed['path'] = 'do-not-open'
            self.refused()

    def test_stale_or_changed_before_after_point(self):
        for side in ('stateBefore', 'stateAfter'):
            for name, value in (('txId', '4'), ('txHash', B(b'x' * 32)), ('precommittedTxId', '6'),
                                ('precommittedTxHash', B(b'x' * 32)), ('db', 'defaultdb')):
                self.setUp()
                self.observed[side][name] = value
                with self.subTest(side=side, name=name):
                    self.refused()

    def test_bounds_and_boolean_numbers(self):
        for field, value in (('limit', 16), ('limit', True), ('prefix', 'fleetory/')):
            self.setUp()
            self.observed['scan'][field] = value
            self.refused()
        for field, value in (('revision', True), ('tx', 0), ('valueBytes', 8193)):
            self.setUp()
            self.observed['scan']['entries'][0][field] = value
            self.refused()
        self.setUp()
        self.observed['scan']['entries'] *= 5
        self.refused()
        self.setUp()
        self.observed['transactions'][0]['entries'] *= 17
        self.observed['transactions'][0]['count'] = 17
        self.refused()

    def test_expectation_types_event_keys_and_pin(self):
        for field, value in (('revision', True), ('eventId', NONCE.upper()), ('key', B(b'wrong')), ('valueSha256', 'B' * 64)):
            self.setUp()
            self.expected['knownEvents'][0][field] = value
            self.refused()
        self.setUp()
        expected = json.dumps(self.expected).encode()
        with self.assertRaises(policy.packet.PairError):
            policy.observe(expected, '0' * 64, json.dumps(self.observed).encode())

    def test_signatures_and_measurements_are_not_authenticated_by_decoder(self):
        result = self.observe()
        for name in ('signaturesVerified', 'producerMeasurementAuthenticated', 'startupAuthorized',
                     'executionAuthorized', 'independentInclusionProofsVerified', 'fullSystemRecoveryVerified', 'phase7Complete'):
            self.assertIs(result[name], False)
        self.observed['stateAfter']['signature']['signature'] = B(b'x' * 70)
        self.assertEqual(self.observe()['observationSha256'], result['observationSha256'])

    def test_freezes_buffers_before_parsing_and_has_no_io(self):
        expected = bytearray(json.dumps(self.expected).encode())
        observed = bytearray(json.dumps(self.observed).encode())
        pin, original = H(expected), policy.packet.strict_json
        def mutate(data, bound):
            expected[:] = b'replaced'
            observed[:] = b'replaced'
            return original(data, bound)
        with patch.object(policy.packet, 'strict_json', side_effect=mutate), patch('builtins.open', side_effect=AssertionError('I/O')):
            self.assertEqual(policy.observe(expected, pin, observed)['knownEvents'], 4)

    def test_json_duplicate_nonfinite_oversize_and_cli_sanitization(self):
        expected = json.dumps(self.expected).encode()
        for observed in (b'{"x":1,"x":2}', b'{"x":NaN}', b'x' * (policy.MAX_OBSERVED + 1)):
            with self.assertRaises(ValueError):
                policy.observe(expected, H(expected), observed)
        script = Path(policy.__file__)
        canary = 'PRIVATE_OBSERVATION_CANARY'
        r = subprocess.run([sys.executable, '-B', str(script)], input=canary.encode(), capture_output=True, timeout=10)
        self.assertEqual(r.returncode, 1)
        self.assertNotIn(canary.encode(), r.stdout + r.stderr)
        self.assertEqual(r.stdout, b'')
        self.assertIn(b'no contents logged', r.stderr)
        body = dict(expectedBase64=B(expected), expectedSha256=H(expected), observedBase64=B(json.dumps(self.observed).encode()))
        r = subprocess.run([sys.executable, '-B', str(script)], input=json.dumps(body).encode(), capture_output=True, timeout=10)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.loads(r.stdout)['currentKvKeys'], 4)


if __name__ == '__main__':
    unittest.main()
