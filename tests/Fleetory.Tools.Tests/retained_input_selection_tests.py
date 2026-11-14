"""Generated metadata vectors; never open original archives, keys or source APIs."""
import base64
import dataclasses
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'eng' / 'pilot'))
import retained_input_selection as policy
import retained_pair_review_tests as fixtures


class RetainedInputSelectionTests(unittest.TestCase):
    def setUp(self):
        records = fixtures.model()
        self.db, self.audit = records['database'], records['audit']
        paths = {
            'application-postgres': 'coherent-postgres-' + '1' * 32 + '/fleetory.dump',
            'signer-postgres': 'coherent-postgres-' + '1' * 32 + '/fleetory_signer.dump',
            'audit-immudb': 'immudb-restore-' + '2' * 32 + '/backup.bin',
            'audit-export': 'archive/export.json', 'identity-postgres': 'keycloak/database.dump',
            'provider-raft': 'openbao/snapshot.snap'}
        self.manifest = dict(schema=policy.FILES_SCHEMA, artifacts={kind: dict(path=paths[kind], bytes=100 + i,
            sha256=str(i + 1) * 64) for i, kind in enumerate(paths)})
        self.db['dumpSha256'] = dict(fleetory=self.manifest['artifacts']['application-postgres']['sha256'],
                                     fleetory_signer=self.manifest['artifacts']['signer-postgres']['sha256'])
        self.audit.update(backupSha256=self.manifest['artifacts']['audit-immudb']['sha256'], backupBytes=102,
                          alreadyLocalSigningMaterialUsed=True)
        self.pin()

    def pin(self):
        self.packets = {name: bytearray(json.dumps(value).encode()) for name, value in
                        dict(manifest=self.manifest, database=self.db, audit=self.audit).items()}
        self.pins = {name: policy.packet.digest(value) for name, value in self.packets.items()}

    def select(self):
        return policy.select(self.packets, self.pins)

    def refuse(self):
        with self.assertRaises((ValueError, KeyError, TypeError, policy.composition.archive.ArchiveError)):
            self.select()

    def test_exactly_three_native_references_without_other_paths(self):
        result = self.select().report()
        self.assertEqual([v['kind'] for v in result['selected']], list(policy.NATIVE))
        self.assertEqual(result['selectedBytes'], 303)
        self.assertEqual(result['excludedKinds'], ['audit-export', 'identity-postgres', 'provider-raft'])
        for value in ('keycloak/database.dump', 'openbao/snapshot.snap', 'archive/export.json'):
            self.assertNotIn(value, json.dumps(result))

    def test_frozen_selection_survives_all_caller_replacement(self):
        result = self.select()
        expected = result.report()
        for value in self.packets.values():
            value[:] = b'replaced'
        self.pins.clear()
        self.assertEqual(result.report(), expected)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            result.artifacts[0].sha256 = '0' * 64

    def test_external_pins_are_frozen_before_metadata_parsing(self):
        original = dict(self.pins)
        parser = policy.packet.strict_json

        def interleaved(data, bound):
            value = parser(data, bound)
            self.pins['manifest'] = '0' * 64
            return value

        with patch.object(policy.packet, 'strict_json', side_effect=interleaved):
            result = self.select().report()
        self.assertEqual(result['metadataPins'], original)
        self.assertEqual(self.pins['manifest'], '0' * 64)

    def test_historical_material_use_does_not_renew_permissions(self):
        result = self.select().report()
        for name in ('executionAuthorized', 'existingConsentExpanded', 'sourceSigningMaterialReuseAuthorized',
                     'providerRootOrTokenUseAuthorized', 'identityIssuerStartAuthorized', 'artifactBytesVerified',
                     'filesystemContainmentVerified', 'originalCompleteKeysetVerified',
                     'originalPerEventTransactionBindingsVerified', 'originalInventoryV2Recomputed',
                     'originalPrivateKeyRecoveryVerified', 'fullSystemRecoveryVerified', 'phase7Complete'):
            self.assertIs(result[name], False)

    def test_each_metadata_pin_and_replaced_packet_is_bound(self):
        for name in self.packets:
            self.setUp()
            self.packets[name][-1] ^= 1
            with self.subTest(name=name):
                self.refuse()

    def test_all_three_dump_digests_bound_to_accepted_report(self):
        for kind in policy.NATIVE:
            self.setUp()
            self.manifest['artifacts'][kind]['sha256'] = '0' * 64
            self.pin()
            with self.subTest(kind=kind):
                self.refuse()

    def test_sensitive_paths_cannot_be_swapped_under_native_labels(self):
        for kind, other in (('application-postgres', 'identity-postgres'), ('audit-immudb', 'provider-raft')):
            self.setUp()
            a, b = (self.manifest['artifacts'][key] for key in (kind, other))
            a['path'], b['path'] = b['path'], a['path']
            self.pin()
            self.refuse()

    def test_mixed_capture_directories_and_case_aliases_refused(self):
        for change in ('different-pg', 'case-alias', 'duplicate-hash'):
            self.setUp()
            a = self.manifest['artifacts']
            if change == 'different-pg':
                a['signer-postgres']['path'] = a['signer-postgres']['path'].replace('1' * 32, '2' * 32)
            elif change == 'case-alias':
                a['identity-postgres']['path'] = a['application-postgres']['path'].upper()
            else:
                a['provider-raft']['sha256'] = a['application-postgres']['sha256']
            self.pin()
            self.refuse()

    def test_malicious_paths_and_byte_type_confusion_refused(self):
        for path in ('../key.pem', 'C:/key.pem', 'a\\key.pem', 'a/CON', 'a/name.', 'a~1/file'):
            self.setUp()
            self.manifest['artifacts']['application-postgres']['path'] = path
            self.pin()
            self.refuse()
        self.setUp()
        self.manifest['artifacts']['audit-immudb']['bytes'] = True
        self.pin()
        self.refuse()

    def test_missing_extra_generated_or_complete_authority_claims_refused(self):
        for change in ('missing', 'extra', 'generated', 'complete', 'root'):
            self.setUp()
            if change == 'missing':
                self.manifest['artifacts'].pop('provider-raft')
            elif change == 'extra':
                self.manifest['approved'] = True
            elif change == 'generated':
                self.manifest['schema'] = 'fleetory.generated-v2-server-composition.v1'
            elif change == 'complete':
                self.db['fullSystemRecoveryVerified'] = True
            else:
                self.audit['sourceRootRecoveryRepeated'] = True
            self.pin()
            self.refuse()

    def test_unknown_history_and_legacy_algorithm_are_not_invented(self):
        result = self.select().report()
        self.assertIs(result['originalCompleteKeysetVerified'], False)
        self.assertIs(result['originalPerEventTransactionBindingsVerified'], False)
        self.db['databaseInventories']['fleetory']['algorithm'] = 'fresh-v1'
        self.pin()
        self.refuse()

    def test_metadata_size_duplicate_nonfinite_and_utf8_refused(self):
        for blob in (b'', b'x' * (policy.MAX_REPORT + 1), b'{"a":1,"a":2}', b'{"x":NaN}', b'\xff'):
            self.packets['manifest'] = blob
            self.pins['manifest'] = policy.packet.digest(blob)
            self.refuse()

    def test_no_file_process_or_socket_operations(self):
        with patch('builtins.open', side_effect=AssertionError()), patch.object(Path, 'open', side_effect=AssertionError()), \
             patch('os.open', side_effect=AssertionError()), patch('subprocess.Popen', side_effect=AssertionError()), patch('socket.socket', side_effect=AssertionError()):
            self.select()

    def test_cli_has_no_read_restore_or_permission_switch(self):
        body = dict(pins=self.pins, packets={name: base64.b64encode(data).decode() for name, data in self.packets.items()})
        command = [sys.executable, '-B', policy.__file__]
        result = subprocess.run(command, input=json.dumps(body).encode(), capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertIs(json.loads(result.stdout)['executionAuthorized'], False)
        for data, args in ((b'{"PRIVATE_CANARY":NaN}', ()), (json.dumps(body).encode(), ('--read',)),
                           (json.dumps(dict(body, approved=True)).encode(), ())):
            result = subprocess.run(command + list(args), input=data, capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stdout, b'')
            self.assertEqual(result.stderr.splitlines(), [b'Retained native input selection refused; no contents logged.'])


if __name__ == '__main__':
    unittest.main()
