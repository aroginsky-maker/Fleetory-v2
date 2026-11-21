"""Public publication fault classification: an unreached failure or success is never fault evidence."""
import copy
import unittest

import native_publication_faults as fixture
import publication_child_observer as observer

policy,packet=fixture.policy,fixture.packet


def evidence():
    fields=('actualNativePublicationVerified namespaceHandoffVerified nativeReadinessBound dotnetExecutablePinned '
        'compilerClosureAuthenticated namespaceRemoved privateInputsAccepted backendCreated backendCleanupAuthorized '
        'operationalLeaseAuthorized originalInputsRead originalPrivatePkiUsed sourceVpsAccessed fullSystemRecoveryVerified phase7Complete').split()
    return dict(profile='native-publication',launchAttemptConsumed=True,processIdentityAuthenticated=True,entrypointPinsMatched=True,
        fence=dict(noRunningMembersVerified=True),payload=dict(selectedSourceFilesPinned=36,refusalStage=None,**dict.fromkeys(fields,False)))


def facts(case):
    return dict(reached=True,ownerKilled=case!='corrupt-receipt',liveOwnerObserved=True,
        compilerObserved=case=='owner-during-publish',compilerExited=case=='owner-during-publish',
        nativeBytesObserved=case=='corrupt-receipt',receiptCorrupted=case=='corrupt-receipt',fileBindingPresent=case=='corrupt-receipt')


class PublicationFaultContracts(unittest.TestCase):
    def test_three_reached_faults_only(self):
        for case in fixture.CASES:
            result=fixture.classify_fault(evidence(),case,facts(case))
            self.assertTrue(result['interruptedPublicationNotAccepted']);self.assertTrue(result['controllerAckAndReleaseAbsent'])
            self.assertFalse(result['controllerDeathCleanupVerified'])

    def test_unknown_case_or_extra_fact_refused(self):
        with self.assertRaises(ValueError):fixture.classify_fault(evidence(),'timeout',facts('corrupt-receipt'))
        value=facts('corrupt-receipt');value['cleanupRoot']='/unrelated'
        with self.assertRaises(ValueError):fixture.classify_fault(evidence(),'corrupt-receipt',value)

    def test_unreached_startup_or_timeout_is_not_injected_fault(self):
        for case in fixture.CASES:
            for key in ('reached','liveOwnerObserved'):
                value=facts(case);value[key]=False
                with self.subTest(case=case,key=key),self.assertRaises(ValueError):fixture.classify_fault(evidence(),case,value)

    def test_boolean_aliases_are_not_evidence(self):
        for case in fixture.CASES:
            for key,value in facts(case).items():
                changed=facts(case);changed[key]=int(value)
                with self.subTest(case=case,key=key),self.assertRaises(ValueError):fixture.classify_fault(evidence(),case,changed)

    def test_live_compiler_and_process_object_exit_both_required(self):
        for key in ('compilerObserved','compilerExited','ownerKilled'):
            value=facts('owner-during-publish');value[key]=False
            with self.subTest(key=key),self.assertRaises(ValueError):fixture.classify_fault(evidence(),'owner-during-publish',value)

    def test_pre_receipt_requires_real_bytes_and_independent_file_binding(self):
        for key in ('nativeBytesObserved','receiptCorrupted','fileBindingPresent'):
            value=facts('corrupt-receipt');value[key]=False
            with self.subTest(key=key),self.assertRaises(ValueError):fixture.classify_fault(evidence(),'corrupt-receipt',value)

    def test_launch_identity_pins_and_complete_fence_cleanup_required(self):
        for key in ('launchAttemptConsumed','processIdentityAuthenticated','entrypointPinsMatched'):
            value=evidence();value[key]=False
            with self.subTest(key=key),self.assertRaises(ValueError):fixture.classify_fault(value,'corrupt-receipt',facts('corrupt-receipt'))
        value=evidence();value['fence']['noRunningMembersVerified']=False
        with self.assertRaises(ValueError):fixture.classify_fault(value,'corrupt-receipt',facts('corrupt-receipt'))

    def test_success_private_or_operational_flags_cannot_be_relabelled_as_fault(self):
        for key,value in evidence()['payload'].items():
            if value is not False:continue
            changed=evidence();changed['payload'][key]=True
            with self.subTest(key=key),self.assertRaises(ValueError):fixture.classify_fault(changed,'corrupt-receipt',facts('corrupt-receipt'))

    def test_wrong_profile_inventory_or_native_refusal_is_not_host_injection(self):
        for key,value in (('selectedSourceFilesPinned',35),('selectedSourceFilesPinned',True),('refusalStage','sdk')):
            changed=evidence();changed['payload'][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):fixture.classify_fault(changed,'corrupt-receipt',facts('corrupt-receipt'))
        changed=evidence();changed['profile']='native-probe-create'
        with self.assertRaises(ValueError):fixture.classify_fault(changed,'corrupt-receipt',facts('corrupt-receipt'))

    def test_only_bounded_distinct_positive_pid_members(self):
        self.assertEqual(observer.pid_list([1,2]),[1,2])
        for values in ([],[0],[True],[0x100000000],[1,1],list(range(1,258))):
            with self.subTest(values=values[:3]),self.assertRaises(ValueError):observer.pid_list(values)

    def test_no_signal_or_command_line_environment_reader_in_observer(self):
        from pathlib import Path
        source=Path(observer.__file__).read_text()
        for forbidden in ('os.kill','TerminateProcess','cmdline','environ','Win32_Process'):
            self.assertNotIn(forbidden,source)
        self.assertIn('QueryInformationJobObject',source);self.assertIn('pidfd_open',source)

    def test_old_profile_and_deadline_remain_fixed(self):
        self.assertEqual(len(policy.SOURCES),36)
        self.assertEqual(policy._NativePublicationPumps.max_frames,4)
        self.assertEqual(policy._NativePublicationPumps.profile,'native-publication')
        self.assertEqual(set(fixture.FORBIDDEN),{'publication-owner-ack.json','native-publication-receipt.json','publication-release.json','native-close.json'})


if __name__=='__main__':unittest.main()
