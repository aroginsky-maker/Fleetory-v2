"""Generated asserted identities and receipts only. These tests never execute cleanup or prove OS ownership."""
import copy
import json
from pathlib import Path
import sys
import time
import unittest
import uuid
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'eng/pilot'))
import audit_cleanup_protocol as policy

C,H=policy.C,policy.packet.digest


class CleanupProtocolContracts(unittest.TestCase):
    def setUp(self):
        self.now,self.mono=time.time_ns(),1_000_000_000
        self.value=dict(schema=policy.SCHEMA,purpose=policy.PURPOSE,nonce=str(uuid.uuid4()),supervisorNonce=str(uuid.uuid4()),
            controller=dict(pid=1111,birthKind='linux-proc-start-ticks',birthToken='123',executableSha256='a'*64),
            supervisor=dict(pid=2222,birthKind='linux-proc-start-ticks',birthToken='456',executableSha256='a'*64),
            imageId='sha256:'+'b'*64,containerId='c'*64,openedNs=self.now-10_000_000_000,createdNs=self.now-5_000_000_000,
            admissionExpiresNs=self.now+50_000_000_000,cleanupExpiresNs=self.now+60_000_000_000,commandLifetimeSeconds=660,
            runtimeProfileSha256=policy.runtime.runtime.PROFILE_SHA256)
        self.value.update({name:H(name.encode('ascii')) for name in policy.HASHES})
        self.value['containerName']=policy.runtime.runtime.name(self.value['nonce'])
        names={'nonce':'nonce','reservation':'reservationSha256','image.binding':'imageBindingSha256',
            'publication':'publicationContinuationSha256','runtime.code':'runtimeCodeSha256',
            'probe.bundle':'bundleManifestSha256','runtime.profile':'runtimeProfileSha256'}
        labels={'fleetory.audit.control.'+label:self.value[key] for label,key in names.items()}
        labels['fleetory.audit.control.profile']=policy.runtime.PURPOSE
        self.resource=dict(schema=policy.RESOURCE_SCHEMA,id=self.value['containerId'],name='/'+self.value['containerName'],imageId=self.value['imageId'],labels=labels)
        self.receipt=dict(self.resource,schema=policy.CREATE_SCHEMA,nonce=self.value['nonce'],reservationSha256=self.value['reservationSha256'],createdNs=self.value['createdNs'],runtimeIntentSha256=self.value['runtimeIntentSha256'])
        self.value['labelsSha256']=H(C(labels));self.value['createReceiptSha256']=H(C(self.receipt))

    def model(self, value=None, raw=None, pin=None):
        value=self.value if value is None else value;data=C(value) if raw is None else raw
        with patch.object(policy.time,'time_ns',return_value=self.now),patch.object(policy.time,'monotonic_ns',return_value=self.mono):
            return policy.CleanupProtocolModel(data,H(data) if pin is None else pin)

    def process(self, role, state='live'):
        return dict(schema=policy.PROCESS_SCHEMA,identity=copy.deepcopy(self.value[role]),state=state)

    def evaluate(self, model, *, controller=None, supervisor=None, receipt=None, resource=None, now=None, mono=None):
        args=[self.process('controller') if controller is None else controller,self.process('supervisor') if supervisor is None else supervisor,
            self.receipt if receipt is None else receipt,self.resource if resource is None else resource]
        with patch.object(policy.time,'time_ns',return_value=self.now+1_000_000_000 if now is None else now),patch.object(policy.time,'monotonic_ns',return_value=self.mono+1_000_000_000 if mono is None else mono):
            return model.evaluate(*(C(arg) for arg in args))

    def no_authority(self, report):
        for key in ('actualProcessIdentityVerified','createReceiptOriginAuthenticated','durableAttemptStoreVerified','actualCleanupExecuted',
            'independentExpiryEnforcementVerified','controllerDeathCleanupVerified','supervisorDeathCleanupVerified','operationalLeaseAuthorized',
            'backendCleanupAuthorized','originalInputsRead','originalPrivatePkiUsed','sourceVpsAccessed','fullSystemRecoveryVerified','phase7Complete'):
            self.assertIs(report[key],False,key)

    def refused(self, **kwargs):
        model=self.model()
        with self.assertRaises(ValueError):self.evaluate(model,**kwargs)
        self.assertEqual(model.report()['state'],'refused');self.assertTrue(model.report()['attemptConsumed'])
        self.no_authority(model.report())
        with self.assertRaises(ValueError):self.evaluate(model)

    def test_matching_live_metadata_waits_without_consuming(self):
        model=self.model()
        for _ in range(3):
            report=self.evaluate(model);self.assertEqual(report['decision'],'await-model-trigger');self.assertFalse(report['attemptConsumed']);self.no_authority(report)

    def test_asserted_controller_exit_only_requests_a_trusted_enforcer(self):
        model=self.model();report=self.evaluate(model,controller=self.process('controller','exited'))
        self.assertEqual(report['decision'],'trusted-enforcer-required');self.assertTrue(report['attemptConsumed'])
        self.assertEqual(report['candidate']['reason'],'asserted-controller-exit');self.assertFalse(report['candidate']['cleanupAuthorized'])
        self.assertEqual(report['candidate']['containerId'],self.value['containerId']);self.assertNotIn('containerName',report['candidate'])
        self.no_authority(report)

    def test_admission_expiry_also_never_authorizes_an_operation(self):
        report=self.evaluate(self.model(),now=self.value['admissionExpiresNs'],mono=self.mono+50_000_000_000)
        self.assertEqual(report['candidate']['reason'],'model-admission-expired');self.no_authority(report)

    def test_candidate_binds_all_four_input_assertion_bytes(self):
        report=self.evaluate(self.model(),controller=self.process('controller','exited'));v=report['candidate']
        self.assertEqual(v['createReceiptSha256'],H(C(self.receipt)));self.assertEqual(v['resourceAssertionSha256'],H(C(self.resource)))
        self.assertEqual(v['controllerAssertionSha256'],H(C(self.process('controller','exited'))));self.assertEqual(v['supervisorAssertionSha256'],H(C(self.process('supervisor'))))

    def test_consumed_candidate_cannot_be_replayed(self):
        model=self.model();self.evaluate(model,controller=self.process('controller','exited'))
        with self.assertRaises(ValueError):self.evaluate(model,controller=self.process('controller','exited'))
        self.no_authority(model.report())

    def test_fresh_model_is_not_claimed_as_durable_restart_protection(self):
        for _ in range(2):
            report=self.evaluate(self.model(),controller=self.process('controller','exited'));self.assertFalse(report['durableAttemptStoreVerified']);self.no_authority(report)

    def test_constructor_rejects_bad_pin_duplicate_and_oversized_frames(self):
        raw=C(self.value)
        for data,pin in ((raw,'f'*64),(raw[:-1]+b',"schema":"duplicate"}',None),(raw+b' '*policy.MAX_FRAME,None),(b'',None)):
            with self.subTest(size=len(data)),self.assertRaises(ValueError):self.model(raw=data,pin=pin)

    def test_schema_purpose_profile_command_and_unknown_execution_fields_refused(self):
        for key,value in (('schema','old'),('purpose','delete'),('runtimeProfileSha256','f'*64),('commandLifetimeSeconds',True),
                ('commandLifetimeSeconds',3300),('argv',['docker','rm','-f','foreign']),('root','/'),('dockerEndpoint','tcp://foreign'),('cleanupAuthorized',True)):
            v=copy.deepcopy(self.value);v[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):self.model(v)

    def test_same_controller_and_supervisor_pid_or_nonce_refused(self):
        for kind in ('pid','nonce','birthKind'):
            v=copy.deepcopy(self.value)
            if kind=='pid':v['supervisor']['pid']=v['controller']['pid']
            elif kind=='nonce':v['supervisorNonce']=v['nonce']
            else:v['supervisor']['birthKind']='windows-filetime'
            with self.subTest(kind=kind),self.assertRaises(ValueError):self.model(v)

    def test_process_identity_types_ranges_birth_and_pins_are_closed(self):
        changes=[('pid',True),('pid',0),('pid',0x100000000),('pid',1.0),('birthKind','pid-only'),('birthToken','0'),
            ('birthToken','0123'),('birthToken','1'*21),('birthToken','١٢٣'),('executableSha256','A'*64),('verified',True)]
        for role in ('controller','supervisor'):
            for key,value in changes:
                v=copy.deepcopy(self.value);v[role][key]=value
                with self.subTest(role=role,key=key),self.assertRaises(ValueError):self.model(v)

    def test_windows_birth_tokens_remain_distinct_from_linux_assertions(self):
        v=copy.deepcopy(self.value)
        for role in ('controller','supervisor'):v[role]['birthKind']='windows-filetime'
        controller=self.process('controller');supervisor=self.process('supervisor')
        supervisor['identity']['birthKind']='windows-filetime'
        refused=self.model(v)
        with self.assertRaises(ValueError):self.evaluate(refused,controller=controller,supervisor=supervisor)
        self.no_authority(refused.report())
        controller['identity']['birthKind']='windows-filetime'
        report=self.evaluate(self.model(v),controller=controller,supervisor=supervisor);self.no_authority(report)

    def test_container_is_one_immutable_id_and_fixed_name(self):
        for key,value in (('containerId',True),('containerId','short'),('imageId','mutable:tag'),('containerName','foreign'),('containerName','../../TUX')):
            v=copy.deepcopy(self.value);v[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):self.model(v)

    def test_every_opaque_pin_is_required_and_strict(self):
        for key in policy.HASHES:
            v=copy.deepcopy(self.value);v[key]=True
            with self.subTest(key=key),self.assertRaises(ValueError):self.model(v)

    def test_deadline_types_ranges_and_grace_cannot_be_extended(self):
        changes=[('openedNs',True),('createdNs',False),('admissionExpiresNs',1.0),('cleanupExpiresNs',True),
            ('openedNs',0),('createdNs',self.value['openedNs']-1),('createdNs',self.value['admissionExpiresNs']),
            ('admissionExpiresNs',self.value['admissionExpiresNs']+1),('cleanupExpiresNs',self.value['cleanupExpiresNs']+1)]
        for key,value in changes:
            v=copy.deepcopy(self.value);v[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):self.model(v)

    def test_supervisor_must_match_and_still_be_asserted_live(self):
        for kind in ('pid','birthToken','executableSha256','state'):
            frame=self.process('supervisor')
            if kind=='state':frame['state']='exited'
            else:frame['identity'][kind]={'pid':3333,'birthToken':'789','executableSha256':'f'*64}[kind]
            with self.subTest(kind=kind):self.refused(supervisor=frame)

    def test_pid_reuse_and_unknown_controller_are_not_proof_of_death(self):
        for kind in ('pid','birthToken','state'):
            frame=self.process('controller','exited')
            if kind=='state':frame['state']='unknown'
            else:frame['identity'][kind]={'pid':3333,'birthToken':'789'}[kind]
            with self.subTest(kind=kind):self.refused(controller=frame)
        self.refused(controller={})

    def test_foreign_container_cannot_be_adopted_by_matching_name(self):
        resource=copy.deepcopy(self.resource);resource['id']='f'*64
        self.refused(resource=resource)

    def test_name_image_labels_and_unknown_observation_fields_are_closed(self):
        for key,value in (('name','/foreign'),('imageId','sha256:'+'f'*64),('labels',{}),('exists',False),('cleanupAuthorized',True)):
            frame=copy.deepcopy(self.resource);frame[key]=value
            with self.subTest(key=key):self.refused(resource=frame)

    def test_malformed_or_excessive_labels_are_not_accepted(self):
        for kind in ('newline','oversized','many','alias'):
            frame=copy.deepcopy(self.resource)
            if kind=='newline':frame['labels']['extra']='line\n'
            elif kind=='oversized':frame['labels']['extra']='x'*1025
            elif kind=='many':frame['labels'].update({str(n):'x' for n in range(17)})
            else:frame['labels']['fleetory.audit.control.nonce']=True
            with self.subTest(kind=kind):self.refused(resource=frame)

    def test_full_create_receipt_hash_and_fields_must_match(self):
        for key,value in (('id','f'*64),('createdNs',True),('nonce',str(uuid.uuid4())),('runtimeIntentSha256','f'*64),('originAuthenticated',True)):
            receipt=copy.deepcopy(self.receipt);receipt[key]=value
            v=copy.deepcopy(self.value);v['createReceiptSha256']=H(C(receipt))
            model=self.model(v)
            with self.subTest(key=key),self.assertRaises(ValueError):self.evaluate(model,receipt=receipt)
            self.no_authority(model.report())
        self.refused(receipt={})

    def test_resource_after_create_must_keep_identical_labels(self):
        frame=copy.deepcopy(self.resource);frame['labels']['org.opencontainers.image.version']='changed'
        self.refused(resource=frame)

    def test_missing_or_aliased_process_metadata_is_terminal(self):
        for key,value in (('schema','old'),('state',True),('verified',True)):
            frame=self.process('controller');frame[key]=value
            with self.subTest(key=key):self.refused(controller=frame)

    def test_cleanup_deadline_boundary_is_terminal_without_a_candidate(self):
        model=self.model()
        with self.assertRaises(ValueError):self.evaluate(model,now=self.value['cleanupExpiresNs'],mono=self.mono+60_000_000_000)
        self.assertIsNone(model.report()['candidate']);self.no_authority(model.report())

    def test_monotonic_hard_deadline_prevents_wall_clock_extension(self):
        model=self.model()
        with self.assertRaises(ValueError):self.evaluate(model,now=self.now+1,mono=self.mono+60_000_000_000)
        self.no_authority(model.report())

    def test_clock_rollback_after_a_valid_poll_is_terminal(self):
        for clock in ('wall','monotonic'):
            model=self.model();self.evaluate(model,now=self.now+2,mono=self.mono+2)
            with self.subTest(clock=clock),self.assertRaises(ValueError):self.evaluate(model,now=self.now+1 if clock=='wall' else self.now+3,mono=self.mono+1 if clock=='monotonic' else self.mono+3)
            self.no_authority(model.report())

    def test_model_cannot_be_created_after_admission_expiry(self):
        v=copy.deepcopy(self.value);shift=60_000_000_000
        for key in ('openedNs','createdNs','admissionExpiresNs','cleanupExpiresNs'):v[key]-=shift
        with self.assertRaises(ValueError):self.model(v)

    def test_mutating_caller_bytearray_does_not_change_frozen_ticket(self):
        raw=bytearray(C(self.value));model=self.model(raw=raw);raw[-1]=0
        self.assertEqual(self.evaluate(model)['state'],'armed')

    def test_mutating_internal_ticket_is_detected_before_a_proposal(self):
        model=self.model();model._value['containerId']='f'*64
        with self.assertRaises(ValueError):self.evaluate(model,controller=self.process('controller','exited'))
        self.assertIsNone(model.report()['candidate'])

    def test_mutating_returned_candidate_does_not_change_model_record(self):
        model=self.model();report=self.evaluate(model,controller=self.process('controller','exited'));report['candidate']['cleanupAuthorized']=True
        self.assertFalse(model.report()['candidate']['cleanupAuthorized']);self.no_authority(model.report())


if __name__=='__main__':
    result=unittest.main(exit=False).result
    if not result.wasSuccessful() or result.skipped:raise SystemExit(1)
    print('CLEANUP PROTOCOL CONTRACT PASS: '+json.dumps(dict(schema='fleetory.cleanup-protocol-contract-proof.v1',
        tests=result.testsRun,skipped=0,protocolSourceSha256=H(Path(policy.__file__).read_bytes()),modelOnly=True,
        actualProcessIdentityVerified=False,actualCleanupExecuted=False,independentExpiryEnforcementVerified=False,
        controllerDeathCleanupVerified=False,operationalLeaseAuthorized=False,fullSystemRecoveryVerified=False,phase7Complete=False),sort_keys=True))
