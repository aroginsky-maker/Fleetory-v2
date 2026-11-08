"""Public-copy grammar bounds and genuine native-fault classification contracts."""
import copy
import unittest
from unittest.mock import patch

import native_public_probe_faults as fixture


def row(name='src/Example.cs',mode='100644',kind='blob',oid='a'*40,size='12'):
    return (mode+' '+kind+' '+oid+' '+size+'\t'+name+'\0').encode()


def evidence(case='owner-exit'):
    false=('nativeOwnerResourceAcknowledged actualProbeNativeOwnerAcknowledged actualProbeNativeBuildCreateVerified '
        'operationalLeaseAuthorized runtimeContinuityVerified backendCreated backendNamespaceBound privateInputsAccepted '
        'backendControlAuthorized backendCleanupAuthorized originalInputsRead originalPrivatePkiUsed fullSystemRecoveryVerified phase7Complete').split()
    return dict(launchAttemptConsumed=True,processIdentityAuthenticated=True,fence=dict(noRunningMembersVerified=True),
        payload=dict(selectedSourceFilesPinned=45,emptyPayloadRemovedVerified=False,refusalStage='resources' if case=='bad-offer' else None,**{k:False for k in false}))


class PublicFaultContracts(unittest.TestCase):
    def test_regular_public_blob_modes_and_zero_length_are_supported(self):
        data=row()+row('eng/helper.sh','100755',size='0')
        result=fixture.public_tree(data)
        self.assertEqual(set(result),{'src/Example.cs','eng/helper.sh'})
        self.assertEqual(result['eng/helper.sh']['bytes'],0)

    def test_metadata_framing_size_and_row_count_are_bounded(self):
        for data in (b'',row()[:-1],b'\0',row()+b'\0',b'a'*(fixture.MAX_TREE+1)):
            with self.subTest(size=len(data)),self.assertRaises((ValueError,UnicodeError)):fixture.public_tree(data)
        with patch.object(fixture,'MAX_FILES',1):
            with self.assertRaises(ValueError):fixture.public_tree(row()+row('other.cs'))

    def test_links_submodules_unknown_types_oids_and_noncanonical_sizes_are_refused(self):
        for args in (dict(mode='120000'),dict(mode='160000',kind='commit'),dict(kind='tree'),dict(oid='A'*40),
                dict(oid='a'*39),dict(size='-1'),dict(size='01'),dict(size=str(fixture.MAX_FILE+1))):
            with self.subTest(args=args),self.assertRaises(ValueError):fixture.public_tree(row(**args))

    def test_public_paths_cannot_escape_or_enter_git_metadata_or_windows_aliases(self):
        for path in ('/escape.cs','../escape.cs','src/../escape.cs','C:/escape.cs','src\\escape.cs','.git/config',
                'src/.GIT/config','src/CON.cs','src/file.','src//a.cs','src/./a.cs','a/'*17+'x.cs'):
            with self.subTest(path=path),self.assertRaises(ValueError):fixture.public_tree(row(path))

    def test_duplicate_case_alias_directory_alias_and_file_parent_conflicts_are_refused(self):
        for data in (row()+row(),row()+row('SRC/example.cs'),row('src/a.cs')+row('SRC/b.cs'),row('src')+row('src/a.cs')):
            with self.subTest(data=data),self.assertRaises(ValueError):fixture.public_tree(data)

    def test_total_content_bound_is_enforced_independently_of_each_blob(self):
        with patch.object(fixture,'MAX_BYTES',20):
            with self.assertRaises(ValueError):fixture.public_tree(row()+row('b.cs'))

    def test_only_injected_authenticated_consumed_faults_with_no_members_are_classified(self):
        for case in fixture.CASES:
            report=fixture.classify_fault(evidence(case),case,True,case=='owner-exit')
            self.assertTrue(report['invalidOrInterruptedNativeAckNotAccepted'])
            self.assertEqual(report['case'],case)
        for case,reached in (('unknown',True),('owner-exit',False),('owner-exit',1)):
            with self.assertRaises(ValueError):fixture.classify_fault(evidence(),case,reached,case=='owner-exit')

    def test_startup_or_unverified_identity_exit_cannot_masquerade_as_expected_fault(self):
        base=evidence()
        for key in ('launchAttemptConsumed','processIdentityAuthenticated'):
            value=copy.deepcopy(base);value[key]=False
            with self.subTest(key=key),self.assertRaises(ValueError):fixture.classify_fault(value,'owner-exit',True,True)
        value=copy.deepcopy(base);value['fence']['noRunningMembersVerified']=False
        with self.assertRaises(ValueError):fixture.classify_fault(value,'owner-exit',True,True)

    def test_cleanup_acceptance_private_or_operational_claims_cannot_be_misclassified(self):
        base=evidence()
        for key in base['payload']:
            if base['payload'][key] is not False:continue
            value=copy.deepcopy(base);value['payload'][key]=True
            with self.subTest(key=key),self.assertRaises(ValueError):fixture.classify_fault(value,'owner-exit',True,True)
        for key,item in (('selectedSourceFilesPinned',40),('emptyPayloadRemovedVerified',True)):
            value=copy.deepcopy(base);value['payload'][key]=item
            with self.assertRaises(ValueError):fixture.classify_fault(value,'owner-exit',True,True)

    def test_owner_kill_must_be_observed_live_and_cannot_be_added_to_offer_refusal(self):
        with self.assertRaises(ValueError):fixture.classify_fault(evidence(),'owner-exit',True,False)
        with self.assertRaises(ValueError):fixture.classify_fault(evidence('bad-offer'),'bad-offer',True,True)

    def test_wrong_typed_refusal_stage_is_not_counted_as_bad_offer(self):
        value=evidence('bad-offer');value['payload']['refusalStage']='code'
        with self.assertRaises(ValueError):fixture.classify_fault(value,'bad-offer',True)


if __name__=='__main__':unittest.main()
