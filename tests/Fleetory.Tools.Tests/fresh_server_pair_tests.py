"""Synthetic contract tests; native PostgreSQL/immudb provenance is exercised separately."""
import base64
import copy
import json
from pathlib import Path
import sys
import unittest
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'eng' / 'pilot'))
import fresh_server_pair as pair


def fixture():
    pg, audit = bytearray(b'PGDMP' + bytes(80)), bytearray(b'IMMUBACKUP' + bytes(80))
    point = dict(eventsSha256='a' * 64, auditTx=4, auditHash='B' * 64, auditKeyFingerprint='C' * 64,
                 tables=18, rows=23, queueRows=0, events=4, fields=10)
    value = dict(schema=pair.SCHEMA, scope=pair.SCOPE, fixture=str(uuid.uuid4()), probeSha256='d' * 64,
                 images=dict(postgres='sha256:' + 'e' * 64, audit='sha256:' + 'f' * 64),
                 sourceContainers=dict(postgres='1' * 64, audit='2' * 64), postgresInventorySha256='3' * 64,
                 point=point, capture=dict(before=copy.deepcopy(point), after=copy.deepcopy(point)),
                 artifacts={name: dict(bytes=len(packet), sha256=pair.digest(packet))
                            for name, packet in (('postgres', pg), ('audit', audit))})
    return value, pg, audit


class FreshPairTests(unittest.TestCase):
    def setUp(self):
        self.value, self.pg, self.audit = fixture()

    def load(self, value=None, pg=None, audit=None, pin=None, identity=None):
        value = self.value if value is None else value
        encoded = json.dumps(value).encode()
        return pair.admit(encoded, pin or pair.digest(encoded), identity or value['fixture'],
                          self.pg if pg is None else pg, self.audit if audit is None else audit)

    def test_captured_both_are_immutable(self):
        captured = self.load()
        expected_pg, expected_audit = bytes(self.pg), bytes(self.audit)
        self.pg[-1] = 1
        self.audit[-1] = 1
        self.assertEqual((captured.packet('postgres'), captured.packet('audit')), (expected_pg, expected_audit))
        with self.assertRaises(pair.PairError):
            self.load()

    def test_wrong_manifest_pin(self):
        with self.assertRaises(pair.PairError):
            self.load(pin='0' * 64)

    def test_wrong_fixture(self):
        with self.assertRaises(pair.PairError):
            self.load(identity=str(uuid.uuid4()))

    def test_native_magic_and_truncation(self):
        for pg, audit in ((self.audit, self.pg), (b'PGDMP', self.audit), (self.pg, b'IMMUBACKUP')):
            with self.subTest(pg_length=len(pg), audit_length=len(audit)), self.assertRaises(pair.PairError):
                self.load(pg=pg, audit=audit)

    def test_oversized_before_freeze(self):
        with self.assertRaises(pair.PairError):
            self.load(pg=bytearray(pair.MAX_ARTIFACT + 1))

    def test_digest_drift_each_input(self):
        for name in ('postgres', 'audit'):
            value = copy.deepcopy(self.value)
            value['artifacts'][name]['sha256'] = '0' * 64
            with self.subTest(name=name), self.assertRaises(pair.PairError):
                self.load(value=value)

    def test_scope_schema_and_unknown_fields(self):
        for field, bad in (('scope', 'original-approved'), ('schema', 'fleetory.original.v2'), ('extra', True)):
            value = copy.deepcopy(self.value)
            value[field] = bad
            with self.subTest(field=field), self.assertRaises(pair.PairError):
                self.load(value=value)

    def test_noncanonical_identity(self):
        for bad in ('../offline', '00000000-0000-0000-0000-000000000000', 'AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA'):
            value = copy.deepcopy(self.value)
            value['fixture'] = bad
            with self.subTest(value=bad), self.assertRaises((pair.PairError, ValueError)):
                self.load(value=value)

    def test_duplicate_source_and_bad_image(self):
        value = copy.deepcopy(self.value)
        value['sourceContainers']['audit'] = value['sourceContainers']['postgres']
        with self.assertRaises(pair.PairError):
            self.load(value=value)
        value = copy.deepcopy(self.value)
        value['images']['audit'] = 'latest'
        with self.assertRaises(pair.PairError):
            self.load(value=value)

    def test_point_all_numeric_types(self):
        for key in ('auditTx', 'tables', 'rows', 'queueRows', 'events', 'fields'):
            for bad in (True, 0.0, -1):
                value = copy.deepcopy(self.value)
                value['point'][key] = bad
                value['capture'] = dict(before=copy.deepcopy(value['point']), after=copy.deepcopy(value['point']))
                with self.subTest(key=key, bad=bad), self.assertRaises(pair.PairError):
                    self.load(value=value)

    def test_capture_drift(self):
        for when in ('before', 'after'):
            value = copy.deepcopy(self.value)
            value['capture'][when]['auditHash'] = 'D' * 64
            with self.subTest(when=when), self.assertRaises(pair.PairError):
                self.load(value=value)
        value = copy.deepcopy(self.value)
        value['capture']['before']['queueRows'] = False
        with self.assertRaises(pair.PairError):
            self.load(value=value)

    def test_artifact_type_and_length(self):
        for bad in (True, len(self.pg) + 1):
            value = copy.deepcopy(self.value)
            value['artifacts']['postgres']['bytes'] = bad
            with self.subTest(bad=bad), self.assertRaises(pair.PairError):
                self.load(value=value)

    def test_strict_json_boundaries(self):
        for encoded in (b'{"x":1,"x":2}', b'{"x":NaN}', b'\xff', b' ' * (pair.MAX_MANIFEST + 1)):
            with self.subTest(size=len(encoded)), self.assertRaises((pair.PairError, ValueError)):
                pair.strict_json(encoded, pair.MAX_MANIFEST)

    def test_canonical_b64(self):
        self.assertEqual(pair.decode(base64.b64encode(b'fixture').decode(), 32), b'fixture')
        for bad in ('!!!!', 'Zg===', 'Zg==\n', ''):
            with self.subTest(value=bad), self.assertRaises((pair.PairError, ValueError)):
                pair.decode(bad, 32)

    def test_unknown_artifact_accessor(self):
        captured = self.load()
        with self.assertRaises(pair.PairError):
            captured.packet('../original')


if __name__ == '__main__':
    unittest.main()
