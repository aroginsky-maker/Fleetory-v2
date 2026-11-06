"""Generated v2 transcripts, legacy encoding and supplemental role-boundary tests."""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'eng' / 'pilot'))
import pg_inventory_v2 as policy
from audit_archive_tests import snapshot
REFUSALS = (policy.audit.ArchiveError, ValueError, TypeError, KeyError)


def model(database='fleetory'):
    counts = policy.APPLICATION_COUNTS if database == 'fleetory' else policy.SIGNER_COUNTS
    records = [dict(schema=policy.SCHEMA, database=database, version=180006, readOnly='on',
                    tables=policy.tables(database), unsupported=[0] * 7)]
    roles = [[role, False, True, False, False, False, False] for role in sorted(policy.ROLES)]
    for label, _ in policy.queries(database):
        if label.startswith('rows:'):
            values = [hashlib.sha256((label + str(index)).encode()).hexdigest() for index in range(counts[label[5:]])]
            values.sort()
        else:
            value = roles if label == 'roles' else snapshot(4) if label == 'audit' else {'label': label}
            values = [json.dumps(value, ensure_ascii=False)]
        records.append(dict(label=label, values=values))
    extra = [role + [role[0] in ('fleetory_server', 'fleetory_signer'), -1, None] for role in roles]
    records.extend([dict(label='additional', roles=extra, memberships=[], settings=[]),
                    dict(label='end', tables=policy.tables(database))])
    return records


def encode(records):
    return b'\n'.join(json.dumps(record, ensure_ascii=False).encode('utf-8') for record in records) + b'\n'


class PgInventoryV2Tests(unittest.TestCase):
    def test_application_and_signer_profiles_and_scope(self):
        for database, total, count in (('fleetory', 24, 18), ('fleetory_signer', 5, 4)):
            result = policy.readback(encode(model(database)), database)
            self.assertEqual(result['inventory']['algorithm'], policy.ALGORITHM)
            self.assertEqual((result['inventory']['totalRows'], result['inventory']['tableCount']), (total, count))
            self.assertTrue(result['generatedRolePolicyAccepted'])
            for key in ('nativeMeasurementAuthenticated', 'originalInputsVerified', 'executionAuthorized', 'fullSystemRecoveryVerified'):
                self.assertIs(result[key], False)

    def test_exact_legacy_golden_hashes(self):
        # Fixed vectors include raw JSON spaces/Unicode, binary row digests and
        # eight-byte length framing. Values are not JSON-normalized before hash.
        result = policy.readback(encode(model()), 'fleetory')['inventory']
        self.assertEqual(result['inventorySha256'], 'b6664ce1784456108a7c8b8177a08513062bda5d23dccd708acc48263ae1fcfe')
        self.assertEqual(result['securitySha256'], '75a519d5ca14344a202e986c017682add9b9705215011cd37b543d7da631b0fc')

    def test_raw_text_encoding_is_not_json_normalized(self):
        records = model()
        before = policy.readback(encode(records), 'fleetory')['inventory']
        records[1]['values'][0] = json.dumps(json.loads(records[1]['values'][0]), separators=(',', ':'))
        after = policy.readback(encode(records), 'fleetory')['inventory']
        self.assertNotEqual(before['inventorySha256'], after['inventorySha256'])
        self.assertNotEqual(before['securitySha256'], after['securitySha256'])

    def test_same_count_row_tampering_changes_only_data_digest(self):
        records = model()
        before = policy.readback(encode(records), 'fleetory')['inventory']
        rows = next(record for record in records if record.get('label') == 'rows:platform.audit_events')
        rows['values'][0] = '0' * 64
        rows['values'].sort()
        after = policy.readback(encode(records), 'fleetory')['inventory']
        self.assertEqual(before['totalRows'], after['totalRows'])
        self.assertEqual(before['securitySha256'], after['securitySha256'])
        self.assertNotEqual(before['inventorySha256'], after['inventorySha256'])

    def test_missing_legacy_role_fields_are_covered_separately(self):
        for change in ('login', 'limit', 'config', 'outgoing', 'grantor', 'database-config'):
            with self.subTest(change=change):
                records = model()
                before = policy.readback(encode(records), 'fleetory')
                extra = records[-2]
                if change == 'login':
                    extra['roles'][0][7] = True
                elif change == 'limit':
                    extra['roles'][0][8] = 1
                elif change == 'config':
                    extra['roles'][0][9] = ['search_path=public']
                elif change == 'database-config':
                    extra['settings'] = [['fleetory', 'fleetory_server', ['statement_timeout=0']]]
                else:
                    extra['memberships'] = [['fleetory_server', 'fixture_extra', 'changed' if change == 'grantor' else 'postgres', False, True, True]]
                after = policy.readback(encode(records), 'fleetory')
                self.assertEqual(before['inventory'], after['inventory'])
                self.assertNotEqual(before['additionalSecuritySha256'], after['additionalSecuritySha256'])
                self.assertFalse(after['generatedRolePolicyAccepted'])

    def test_unknown_missing_duplicate_reordered_and_mixed_profiles_refused(self):
        for change in ('unknown', 'missing', 'duplicate', 'reorder', 'database', 'version', 'write', 'end', 'tables'):
            records = model()
            if change == 'unknown':
                records[1]['label'] = 'unknown'
            elif change == 'missing':
                records.pop(1)
            elif change == 'duplicate':
                records.insert(1, copy.deepcopy(records[1]))
            elif change == 'reorder':
                records[1], records[2] = records[2], records[1]
            elif change == 'database':
                records[0]['database'] = 'fleetory_signer'
            elif change == 'version':
                records[0]['version'] = True
            elif change == 'write':
                records[0]['readOnly'] = 'off'
            elif change == 'end':
                records[-1]['tables'] = []
            else:
                records[0]['tables'].append('public.hidden')
            with self.subTest(change=change), self.assertRaises(REFUSALS):
                policy.readback(encode(records), 'fleetory')

    def test_unsupported_objects_and_false_zero_refused(self):
        for index in range(7):
            for value in (1, False):
                records = model()
                records[0]['unsupported'][index] = value
                with self.assertRaises(policy.audit.ArchiveError):
                    policy.readback(encode(records), 'fleetory')

    def test_unsorted_invalid_hash_nonstring_and_scalar_cardinality_refused(self):
        for values in (['f' * 64, '0' * 64], ['g' * 64], [True]):
            records = model()
            next(record for record in records if record.get('label', '').startswith('rows:'))['values'] = values
            with self.assertRaises(policy.audit.ArchiveError):
                policy.readback(encode(records), 'fleetory')
        for values in ([], ['{}', '{}'], [False], ['not-json']):
            records = model()
            records[1]['values'] = values
            with self.assertRaises(REFUSALS):
                policy.readback(encode(records), 'fleetory')

    def test_audit_pending_missing_duplicate_event_refused(self):
        for change in ('pending', 'duplicate', 'malformed'):
            records = model()
            item = next(record for record in records if record.get('label') == 'audit')
            value = json.loads(item['values'][0])
            if change == 'pending':
                value['pendingExportCount'] = 1
            elif change == 'duplicate':
                value['events'][1] = value['events'][0]
            else:
                value['events'][0]['actor_kind'] = True
            item['values'] = [json.dumps(value)]
            with self.assertRaises(policy.audit.ArchiveError):
                policy.readback(encode(records), 'fleetory')

    def test_duplicate_nonfinite_invalid_utf8_oversize_and_foreign_database(self):
        for data in (b'{"x":1,"x":2}', b'{"x":NaN}', b'\xff', b' ' * (policy.MAX_PACKET + 1)):
            with self.assertRaises(REFUSALS):
                policy.readback(data, 'fleetory')
        with self.assertRaises(policy.audit.ArchiveError):
            policy.build_sql('keycloak')

    def test_parser_opens_no_file_process_or_socket(self):
        with patch('builtins.open', side_effect=AssertionError()), patch('subprocess.Popen', side_effect=AssertionError()), patch('socket.socket', side_effect=AssertionError()):
            self.assertTrue(policy.readback(encode(model()), 'fleetory')['generatedRolePolicyAccepted'])

    def test_cli_and_sql_are_bounded_and_canary_safe(self):
        command = [sys.executable, '-B', policy.__file__, 'readback', '--database', 'fleetory']
        result = subprocess.run(command, input=encode(model()), capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertFalse(json.loads(result.stdout)['executionAuthorized'])
        result = subprocess.run(command, input=b'{"CANARY_PRIVATE_TRANSCRIPT":NaN}', capture_output=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b'')
        self.assertEqual(result.stderr.splitlines(), [b'PostgreSQL v2 transcript refused; no contents logged.'])
        for database in policy.DATABASES:
            sql = policy.build_sql(database)
            self.assertLess(len(sql), 131072)
            self.assertIn('REPEATABLE READ READ ONLY;', sql)
            self.assertLess(sql.index('SELECT 1/0;'), sql.index("'values',coalesce(jsonb_agg(v)"))
            self.assertNotIn('pg_authid', sql)
            self.assertNotIn('rolpassword', sql)


if __name__ == '__main__':
    unittest.main()
