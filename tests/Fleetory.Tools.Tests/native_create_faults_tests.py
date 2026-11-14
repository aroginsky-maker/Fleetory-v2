"""Native-create fault classification and receipt-only fixture cleanup ownership contracts."""
import copy
import json
import unittest
import uuid
from unittest.mock import patch

import native_public_create_faults as fixture
import audit_native_create_tests as contracts

unbound_pair=contracts.unbound_pair

policy,packet,runtime=fixture.policy,fixture.packet,fixture.runtime


def evidence(case='owner-exit'):
    false=('nativeOwnerResourceAcknowledged actualProbeNativeOwnerAcknowledged actualNativeContainerCreateVerified '
        'actualProbeNativeBuildCreateVerified nativePublicationBuildVerified nativeCreatePreReceiptCrashGapVerified '
        'controllerDeathCleanupVerified operationalLeaseAuthorized runtimeContinuityVerified backendCreated backendNamespaceBound '
        'privateInputsAccepted backendControlAuthorized backendCleanupAuthorized originalInputsRead originalPrivatePkiUsed '
        'fullSystemRecoveryVerified phase7Complete').split()
    return dict(launchAttemptConsumed=True,processIdentityAuthenticated=True,fence=dict(noRunningMembersVerified=True),
        payload=dict(selectedSourceFilesPinned=46,emptyReservationObserved=True,emptyPayloadRemovedVerified=False,
            refusalStage='create' if case=='bad-create' else None,**{k:False for k in false}))


class NativeCreateFaultContracts(unittest.TestCase):
    setUp=contracts.NativeCreateTests.setUp
    session=contracts.NativeCreateTests.session

    def test_only_two_reached_authenticated_faults_with_correct_receipt_barrier_are_accepted(self):
        for case in fixture.CASES:
            value=fixture.classify_fault(evidence(case),case,True,case=='owner-exit',case=='owner-exit')
            self.assertEqual(value['case'],case)
            self.assertTrue(value['invalidOrInterruptedNativeResultNotAccepted'])
            self.assertTrue(value['nativeReceiptAckAbsent'])
        for case,reached in (('unknown',True),('owner-exit',False),('owner-exit',1)):
            with self.assertRaises(ValueError):fixture.classify_fault(evidence(),case,reached,True,True)

    def test_startup_timeout_unconsumed_or_unverified_fence_cannot_masquerade_as_injection(self):
        for key in ('launchAttemptConsumed','processIdentityAuthenticated'):
            value=evidence();value[key]=False
            with self.subTest(key=key),self.assertRaises(ValueError):fixture.classify_fault(value,'owner-exit',True,True,True)
        value=evidence();value['fence']['noRunningMembersVerified']=False
        with self.assertRaises(ValueError):fixture.classify_fault(value,'owner-exit',True,True,True)

    def test_live_owner_kill_and_durable_receipt_are_both_required(self):
        for live,receipt in ((False,True),(True,False),(1,True),(True,1)):
            with self.subTest(live=live,receipt=receipt),self.assertRaises(ValueError):fixture.classify_fault(evidence(),'owner-exit',True,live,receipt)
        for live,receipt in ((True,False),(False,True)):
            with self.assertRaises(ValueError):fixture.classify_fault(evidence('bad-create'),'bad-create',True,live,receipt)

    def test_no_private_operational_or_successful_final_result_can_be_relabelled_as_fault(self):
        base=evidence()
        for key,item in base['payload'].items():
            if item is not False:continue
            value=copy.deepcopy(base);value['payload'][key]=True
            with self.subTest(key=key),self.assertRaises(ValueError):fixture.classify_fault(value,'owner-exit',True,True,True)

    def test_create_stage_cannot_be_replaced_by_header_or_resource_refusal(self):
        for case,stage in (('bad-create','header'),('bad-create','resources'),('owner-exit','create')):
            value=evidence(case);value['payload']['refusalStage']=stage
            with self.subTest(case=case,stage=stage),self.assertRaises(ValueError):fixture.classify_fault(value,case,True,case=='owner-exit',case=='owner-exit')

    def test_old45_profile_or_unobserved_empty_reservation_cannot_be_accepted(self):
        for key,item in (('selectedSourceFilesPinned',45),('selectedSourceFilesPinned',True),('emptyReservationObserved',False),('emptyPayloadRemovedVerified',True)):
            value=evidence();value['payload'][key]=item
            with self.subTest(key=key),self.assertRaises(ValueError):fixture.classify_fault(value,'owner-exit',True,True,True)

    def records(self,session,target,mutation=None):
        target.bind(runtime.container.canonical(contracts.fixture.model.observed(target.intent)),'b'*64)
        owner=dict(pid=12345,imageSha256=session._plan['runtimes']['powershell'],birthKind='linux-proc-start-ticks',birthToken='1234',ownedPidfd=True,actualImageMatched=True)
        intent=dict(schema='fleetory.native-probe-create-intent.v1',nonce=session._plan['nonce'],headerSha256='a'*64,actualOwnedProcess=owner,
            runtimeIntentSha256=packet.digest(target._intent_bytes),dockerSha256='d'*64,privateInputsAccepted=False)
        receipt=policy.created(dict(nonce=intent['nonce'],headerSha256=intent['headerSha256']),'c'*64,
            dict(ownerSha256='d'*64,payloadDirectorySha256='e'*64),intent['runtimeIntentSha256'],'b'*64,12345)
        session._write_once('native-probe-create-intent.json',intent)
        saved=dict(schema='fleetory.native-probe-create-binding.v1',nonce=intent['nonce'],actualOwnedProcess=owner,receipt=receipt,
            createIntentSha256=packet.digest(session._records['native-probe-create-intent.json'][1]),receiptSha256='f'*64,
            backendBindingSha256=packet.digest(session._records['backend-binding.json'][1]))
        if mutation:mutation(saved)
        session._write_once('native-probe-create-binding.json',saved)
        return saved

    def public_root(self):
        root=self.root/uuid.uuid4().hex;root.mkdir(mode=0o700);return root

    def test_only_complete_matching_native_receipt_transfers_cleanup_ownership(self):
        with self.session() as session,unbound_pair(session,self.public_root()) as pair:
            saved=self.records(session,pair[1]);self.assertEqual(fixture.native_create_receipt(session,pair[1]),saved)

    def test_foreign_partial_id_or_wrong_header_record_binding_and_nonce_are_refused(self):
        changes=(lambda v:v.update(schema='foreign'),lambda v:v.update(nonce=str(uuid.uuid4())),
            lambda v:v.update(createIntentSha256='f'*64),lambda v:v.update(backendBindingSha256='f'*64),
            lambda v:v['receipt'].update(containerId='b'*12),lambda v:v['receipt'].update(containerId='c'*64),
            lambda v:v['receipt'].update(headerSha256='f'*64),lambda v:v['receipt'].update(runtimeIntentSha256='f'*64),
            lambda v:v['receipt'].update(pid=True),lambda v:v.update(cleanupRoot='/unrelated'))
        for index,change in enumerate(changes):
            with self.subTest(index=index),self.session() as session,unbound_pair(session,self.public_root()) as pair:
                self.records(session,pair[1],change)
                with self.assertRaises(ValueError):fixture.native_create_receipt(session,pair[1])

    def test_private_service_and_unverified_owner_flags_cannot_transfer_ownership(self):
        for mutate in (lambda v:v['receipt'].update(privateInputsAccepted=True),lambda v:v['receipt'].update(backendServiceStarted=True),
                lambda v:v['actualOwnedProcess'].update(actualImageMatched=False),lambda v:v['actualOwnedProcess'].update(imageSha256='f'*64),
                lambda v:v['actualOwnedProcess'].update(birthKind='claimed'),lambda v:v['actualOwnedProcess'].update(birthToken='invalid')):
            with self.session() as session,unbound_pair(session,self.public_root()) as pair:
                self.records(session,pair[1],mutate)
                with self.assertRaises(ValueError):fixture.native_create_receipt(session,pair[1])

    def test_labels_and_unbound_intent_without_receipt_never_grant_cleanup(self):
        with self.session() as session,unbound_pair(session,self.public_root()) as pair:
            with self.assertRaises(KeyError):fixture.native_create_receipt(session,pair[1])
        client=object.__new__(fixture.NativeCreateFaultFixture)
        for name in ('foreign','fleetory-probe-runtime-'+'a'*12,'fleetory-probe-runtime-'+'a'*32+';rm'):
            with patch.object(client,'call') as call:
                with self.assertRaises(ValueError):client.by_name(name)
                call.assert_not_called()

    def test_shared_runner_requires_exactly_two_distinct_cases_before_docker(self):
        for cases in ([],(),('owner-exit',),('owner-exit','owner-exit'),('a','b','c')):
            with self.subTest(cases=cases),patch('native_public_probe_faults.StoppedSentinel') as sentinel:
                with self.assertRaises(ValueError):fixture.shared_run(fixture.NativeCreateFaultFixture,cases)
                sentinel.assert_not_called()


if __name__=='__main__':unittest.main()
