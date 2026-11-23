"""Same original-inventory metadata contract on generated vectors; no artifact reads."""
import copy
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'eng/pilot'))
from historical import retained_expected_inventory as policy
import retained_input_selection_tests as fixtures


class ExpectedInventoryTests(unittest.TestCase):
    def setUp(self):
        self.source=fixtures.RetainedInputSelectionTests('runTest');self.source.setUp()
        self.capture=fixtures.fixtures.model()['capture']
        for name,kind,_ in policy.DATABASES:
            self.capture['databases'][name].update(inventory=copy.deepcopy(self.source.db['databaseInventories'][name]),
                dumpSha256=self.source.db['dumpSha256'][name],dumpBytes=self.source.manifest['artifacts'][kind]['bytes'])
        self.pin()

    def pin(self):
        self.source.pin()
        self.metadata=dict(selection=bytearray(policy.archive.canonical(self.source.select().report())),
                           capture=bytearray(policy.archive.canonical(self.capture)),database=self.source.packets['database'])
        self.pins={n:policy.packet.digest(v) for n,v in self.metadata.items()}

    def build(self):return json.loads(policy.build(self.metadata,self.pins))

    def refuse(self):
        with self.assertRaises((ValueError,KeyError,TypeError,policy.archive.ArchiveError)):self.build()

    def test_source_hashes_preserved_and_fresh_policy_explicit(self):
        result=self.build()
        for name,_,_ in policy.DATABASES:
            self.assertEqual(result['expected'][name]['inventory'],self.source.db['databaseInventories'][name])
            self.assertEqual(result['expected'][name]['additionalSecuritySha256'],policy.TARGET_POLICY_V1)
        self.assertEqual(result['additionalSecurityComparisonScope'],'fresh-target-role-policy-v1')
        for name in ('originalAdditionalSecurityMeasurementAvailable','targetPolicyIsOriginalSourceMeasurement',
                     'referencedArtifactBytesOpened','originalRawInputsOpened','originalSourceImageAuthenticated',
                     'consentAuthenticated','executionAuthorized','fullSystemRecoveryVerified','phase7Complete'):
            self.assertIs(result[name],False)

    def test_no_files_opened(self):
        with patch('builtins.open',side_effect=AssertionError('no file reads')),patch.object(Path,'open',side_effect=AssertionError('no path reads')):
            self.assertEqual(self.build()['schema'],policy.SCHEMA)

    def test_every_external_pin_and_payload_is_bound(self):
        for name in self.metadata:
            self.setUp();self.pins[name]='0'*64;self.refuse()
            self.setUp();self.metadata[name][-1]^=1;self.refuse()

    def test_provider_identity_root_or_permission_packets_rejected(self):
        for name in ('provider','identity','root','permission','callback'):
            self.setUp();self.metadata[name]=b'{}';self.pins[name]=policy.packet.digest(b'{}');self.refuse()

    def test_missing_source_measurement_cannot_be_invented(self):
        for destination in ('entry','inventory'):
            self.setUp();entry=self.capture['databases']['fleetory']
            (entry if destination=='entry' else entry['inventory'])['additionalSecuritySha256']=policy.TARGET_POLICY_V1
            self.pin();self.refuse()

    def test_mixed_source_data_security_or_snapshot_refused(self):
        for name in ('inventorySha256','securitySha256','audit'):
            self.setUp();self.capture['databases']['fleetory']['inventory'][name]='0'*64
            self.pin();self.refuse()

    def test_dump_hash_length_and_boolean_confusion_refused(self):
        for name,value in (('dumpSha256','0'*64),('dumpBytes',1),('dumpBytes',True)):
            self.setUp();self.capture['databases']['fleetory'][name]=value;self.pin();self.refuse()

    def test_changed_counts_and_names_refused(self):
        for name,value in (('tableCount',17),('totalRows',23),('sequenceCount',1)):
            self.setUp();self.capture['databases']['fleetory']['inventory'][name]=value;self.pin();self.refuse()

    def test_state_and_scope_changes_refused(self):
        for name,value in (('sourceRolesPasswordsOrPoliciesModified',True),('sourceRootRecoveryRepeated',True),('globalAtomicSnapshotClaimed',True)):
            self.setUp();self.capture[name]=value;self.pin();self.refuse()
        self.setUp();self.capture['immudbAfter']['txId']='4';self.pin();self.refuse()

    def test_caller_mutation_after_freeze_does_not_change_expectation(self):
        original=self.build();parser=policy.packet.strict_json
        def changed(raw,bound):
            for value in self.metadata.values():value[:]=b'replaced'
            self.pins.clear()
            return parser(raw,bound)
        with patch.object(policy.packet,'strict_json',side_effect=changed):self.assertEqual(self.build(),original)

    def test_source_capture_schema_and_revision_cannot_be_relabelled(self):
        self.capture['schema']='fleetory.generated-target-role-policy.v1';self.pin();self.refuse()
        self.setUp();database=json.loads(self.metadata['database']);database['sourceApplicationCommit']='not-a-commit'
        self.metadata['database']=bytearray(policy.archive.canonical(database))
        selected=json.loads(self.metadata['selection']);selected['metadataPins']['database']=policy.packet.digest(self.metadata['database'])
        self.metadata['selection']=bytearray(policy.archive.canonical(selected))
        self.pins={n:policy.packet.digest(v) for n,v in self.metadata.items()};self.refuse()

    def test_selection_cannot_be_rebound_to_another_database_report(self):
        value=json.loads(self.metadata['database']);value['sourceApplicationCommit']='0'*40
        self.metadata['database']=bytearray(policy.archive.canonical(value));self.pins['database']=policy.packet.digest(self.metadata['database'])
        self.refuse()


if __name__=='__main__':unittest.main()
