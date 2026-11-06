"""Generated retained-profile metadata and refusal cases; no original files or services."""
import base64
import copy
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'eng' / 'pilot'))
import recovery_composition_tests as fixtures
import retained_pair_review as policy


def encoded(value):
    return base64.b64encode(value).decode('ascii')


def model():
    source = fixtures.synthetic_reports()
    db, audit = source['database'], source['audit']
    for name, counts in (('fleetory', policy.APPLICATION_COUNTS), ('fleetory_signer', policy.SIGNER_COUNTS)):
        db['databaseInventories'][name].update(tableCounts=copy.deepcopy(counts), tableCount=len(counts),
                                             totalRows=sum(counts.values()), sequenceCount=0)
    audit.update(backupBytes=3342, backupSha256='1' * 64)
    state = dict(db='fleetoryaudit', txId='5', txHash=encoded(b'h' * 32),
                 signature=dict(publicKey=encoded(b'\x04' + b'p' * 64), signature=encoded(b's' * 70)),
                 precommittedTxId='5', precommittedTxHash=encoded(b'h' * 32))
    capture = dict(schema='fleetory.coherent-database-capture.v1', observedStableCaptureWindow=True,
                   sourceRolesPasswordsOrPoliciesModified=False, sourceRootRecoveryRepeated=False,
                   globalAtomicSnapshotClaimed=False, databases={}, postgresImage=IMAGE,
                   immudbBefore=copy.deepcopy(state), immudbAfter=copy.deepcopy(state))
    for name in policy.composition.DATABASES:
        capture['databases'][name] = dict(inventory=copy.deepcopy(db['databaseInventories'][name]),
                                         dumpSha256=db['dumpSha256'][name], dumpBytes=42000,
                                         singleMvccSnapshotForDumpAndInventory=True, dumpContainsOwnersAndAcls=True)
    events = []
    for number in range(1, 5):
        identity = '00000000-0000-4000-8000-' + str(number).zfill(12)
        events.append(dict(eventId=identity, key=encoded(('fleetory/audit/v1/' + identity.replace('-', '')).encode()),
                           revision=1, valueSha256=str(number) * 64))
    observation = dict(schema='fleetory.pilot-immudb-capture.v1', database='fleetoryaudit', transactionCount=5,
                       state=copy.deepcopy(state), knownEvents=events, sourceStateUnchanged=True,
                       sourceProcessesUnrestarted=True, sourcePrivateSigningKeyCopied=False,
                       sourceRootRecoveryRepeated=False, backupSha256=audit['backupSha256'], backupBytes=3342)
    return dict(database=db, audit=audit, capture=capture, observation=observation)


IMAGE = 'postgres:18.6@sha256:74935e72241653ca55e0414067e6d8763aceb8a810eb51b452253ec3dcfc4336'


class RetainedPairReviewTests(unittest.TestCase):
    def setUp(self):
        self.records = model()
        self.manifest = dict(schema=policy.SCHEMA, scope='metadata-only-no-execution-grant',
                             sourceApplicationCommit=fixtures.APP, sourceConfigurationCommit=fixtures.CONFIG,
                             postgresImage=IMAGE, reports={})
        self.pin()

    def pin(self):
        self.packets = {name: json.dumps(value).encode() for name, value in self.records.items()}
        self.manifest['reports'] = {name: dict(bytes=len(value), sha256=policy.packet.digest(value))
                                    for name, value in self.packets.items()}
        self.manifest_bytes = json.dumps(self.manifest).encode()
        self.expected = policy.packet.digest(self.manifest_bytes)

    def review(self):
        return policy.review(self.manifest_bytes, self.expected, self.packets)

    def refuse(self):
        with self.assertRaises((policy.composition.archive.ArchiveError, ValueError, KeyError, TypeError)):
            self.review()

    def test_reconciles_retained_shape_without_claiming_execution_or_native_validation(self):
        result = self.review()
        self.assertEqual((result['applicationRows'], result['auditTransactions']), (24, 5))
        for key in ('executionAuthorized', 'nativeV1Equivalent', 'originalInventoryV2Recomputed',
                    'loginCapabilitiesCoveredByV2', 'cryptographicVerificationRepeated',
                    'perEventTransactionBindingsVerified', 'completeAuditKeysetVerified',
                    'releaseSourceRevisionAuthenticated', 'originalServiceRecoveryVerified',
                    'fullSystemRecoveryVerified', 'phase7Complete'):
            self.assertIs(result[key], False)

    def test_native_v1_and_fresh_manifest_cannot_be_relabelled(self):
        for field, replacement in (('algorithm', 'fleetory.server-pg-roundtrip.v1'), ('totalRows', 23)):
            with self.subTest(field=field):
                self.setUp()
                self.records['database']['databaseInventories']['fleetory'][field] = replacement
                self.pin()
                self.refuse()
        self.manifest['schema'] = 'fleetory.fresh-native-server-pair.v1'
        self.pin()
        self.refuse()

    def test_mixed_inventory_security_dump_and_audit_snapshot(self):
        for field in ('inventorySha256', 'securitySha256', 'tableCounts', 'audit'):
            with self.subTest(field=field):
                self.setUp()
                value = self.records['capture']['databases']['fleetory']['inventory']
                value[field] = 'changed'
                self.pin()
                self.refuse()
        self.setUp()
        self.records['capture']['databases']['fleetory']['dumpSha256'] = '0' * 64
        self.pin()
        self.refuse()

    def test_table_rename_counts_sequences_and_type_confusion(self):
        for change in ('rename', 'boolean', 'sequence', 'signer'):
            with self.subTest(change=change):
                self.setUp()
                inv = self.records['database']['databaseInventories']['fleetory']
                if change == 'rename':
                    inv['tableCounts']['public.hidden'] = inv['tableCounts'].pop('core.devices')
                elif change == 'boolean':
                    inv['tableCounts']['core.devices'] = False
                elif change == 'sequence':
                    inv['sequenceCount'] = 1
                else:
                    self.records['database']['databaseInventories']['fleetory_signer']['totalRows'] = 4
                self.pin()
                self.refuse()

    def test_stale_mixed_transaction_hash_public_point_and_precommit(self):
        for field, value in (('txId', '4'), ('txId', 5), ('txHash', encoded(b'x' * 32)),
                             ('precommittedTxId', '6'), ('precommittedTxHash', encoded(b'x' * 32)),
                             ('db', 'defaultdb')):
            with self.subTest(field=field, value=value):
                self.setUp()
                self.records['capture']['immudbAfter'][field] = value
                self.pin()
                self.refuse()
        self.setUp()
        self.records['observation']['state']['signature']['publicKey'] = encoded(b'\x04' + b'q' * 64)
        self.pin()
        self.refuse()

    def test_missing_duplicate_changed_event_key_revision_and_value_hash(self):
        for change in ('missing', 'duplicate', 'id', 'key', 'revision', 'hash', 'payload'):
            with self.subTest(change=change):
                self.setUp()
                events = self.records['observation']['knownEvents']
                if change == 'missing':
                    events.pop()
                elif change == 'duplicate':
                    events[1] = copy.deepcopy(events[0])
                else:
                    field, value = {'id': ('eventId', '0' * 32), 'key': ('key', encoded(b'other')),
                                    'revision': ('revision', True), 'hash': ('valueSha256', 'wrong'),
                                    'payload': ('value', 'must-not-be-an-event-payload')}[change]
                    events[0][field] = value
                self.pin()
                self.refuse()

    def test_different_valid_signatures_at_same_point_are_not_a_fork(self):
        self.records['capture']['immudbAfter']['signature']['signature'] = encoded(b't' * 71)
        self.pin()
        self.assertIs(self.review()['verifiedMetadataOnly'], True)

    def test_bad_base64_public_point_hash_signature_and_counts(self):
        for field, value in (('txHash', '*'), ('txHash', encoded(b'h' * 31)),
                             ('signature', dict(publicKey=encoded(b'\x03' + b'p' * 64), signature=encoded(b's' * 70))),
                             ('signature', dict(publicKey=encoded(b'\x04' + b'p' * 64), signature=''))):
            with self.subTest(field=field):
                self.setUp()
                self.records['observation']['state'][field] = value
                self.pin()
                self.refuse()
        for field, value in (('backupBytes', True), ('backupSha256', 'f' * 64), ('transactionCount', 4)):
            self.setUp()
            self.records['observation'][field] = value
            self.pin()
            self.refuse()

    def test_invented_authority_full_recovery_and_global_atomicity_refused(self):
        for name in policy.KINDS.split():
            for flag in ('standingAuthorizationRemaining', 'phase7Complete', 'fullSystemRecoveryVerified',
                         'independentCustodyVerified', 'globalAtomicSnapshotClaimed'):
                with self.subTest(name=name, flag=flag):
                    self.setUp()
                    self.records[name][flag] = True
                    self.pin()
                    self.refuse()

    def test_declared_source_revision_mismatch_refused(self):
        for name in ('sourceApplicationCommit', 'sourceConfigurationCommit'):
            self.setUp()
            self.records['audit'][name] = 'd' * 40
            self.pin()
            self.refuse()

    def test_all_packets_frozen_before_any_report_is_parsed(self):
        original = copy.deepcopy(self.packets)
        self.packets = {name: bytearray(value) for name, value in self.packets.items()}
        strict = policy.packet.strict_json

        def mutate_after_freeze(data, bound):
            if bound == policy.MAX_REPORT:
                for buffer in self.packets.values():
                    buffer[:] = b'changed-after-freeze'
            return strict(data, bound)

        with patch.object(policy.packet, 'strict_json', side_effect=mutate_after_freeze):
            self.assertIs(self.review()['verifiedMetadataOnly'], True)
        self.packets = original
        self.assertIs(self.review()['verifiedMetadataOnly'], True)

    def test_stale_pin_length_mutation_missing_extra_and_oversize_inputs(self):
        for change in ('pin', 'bytes', 'missing', 'extra', 'oversize', 'manifest', 'manifest-bound'):
            self.setUp()
            if change == 'pin':
                self.expected = '0' * 64
            elif change == 'bytes':
                self.packets['audit'] += b' '
            elif change == 'missing':
                self.packets.pop('audit')
            elif change == 'extra':
                self.packets['key'] = b'forbidden'
            elif change == 'oversize':
                self.packets['audit'] = b' ' * (policy.MAX_REPORT + 1)
            elif change == 'manifest-bound':
                self.manifest_bytes = b' ' * (policy.packet.MAX_MANIFEST + 1)
                self.expected = policy.packet.digest(self.manifest_bytes)
            else:
                self.manifest['scope'] = 'execute-original-restore'
                self.pin()
            self.refuse()

    def test_duplicate_json_nonfinite_invalid_utf8_and_trailing_json(self):
        for data in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":"\xff"}', b'{}{}'):
            self.setUp()
            self.packets['database'] = data
            self.manifest['reports']['database'] = dict(bytes=len(data), sha256=policy.packet.digest(data))
            self.manifest_bytes = json.dumps(self.manifest).encode()
            self.expected = policy.packet.digest(self.manifest_bytes)
            self.refuse()

    def test_report_paths_not_followed_and_no_process_or_socket_created(self):
        self.records['audit']['backupPath'] = 'C:/not-opened/private.dump'
        self.records['capture']['outputDirectory'] = '/not-opened'
        self.pin()
        with patch('builtins.open', side_effect=AssertionError('file opened')), \
             patch('subprocess.Popen', side_effect=AssertionError('process started')), \
             patch('socket.socket', side_effect=AssertionError('socket created')):
            self.assertIs(self.review()['executionAuthorized'], False)

    def test_cli_success_and_failure_are_bounded_and_canary_safe(self):
        body = dict(manifestBase64=encoded(self.manifest_bytes),
                    reports={name: encoded(value) for name, value in self.packets.items()})
        command = [sys.executable, '-B', policy.__file__, '--pin', self.expected]
        result = subprocess.run(command, input=json.dumps(body).encode(), capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertIs(json.loads(result.stdout)['executionAuthorized'], False)
        self.assertEqual(result.stderr, b'')
        for data in (b'{"CANARY_PRIVATE_RECORD":NaN}', b' ' * (policy.MAX_BODY + 1)):
            result = subprocess.run(command, input=data, capture_output=True, timeout=5)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, b'')
            self.assertEqual(result.stderr.splitlines(), [b'Retained pair metadata refused; no report contents logged.'])


if __name__ == '__main__':
    unittest.main()
