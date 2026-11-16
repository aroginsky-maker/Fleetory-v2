"""Generated handoff/own-receipt/consumption contracts; no actual compiler or Docker proof."""
from contextlib import ExitStack
import copy
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import time
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import retained_runtime_tests as vectors
import audit_probe_image_tests as images
from historical_audit_restore_tests import fixture as native_fixture
import audit_retained_cleanup_guard as policy

P,C,H=policy.protocol,policy.C,policy.H
ROOT=Path(__file__).resolve().parents[2]
REFUSED=(OSError,ValueError,policy.guard.attempts.files.archive.ArchiveError,tarfile.TarError)


class RetainedCleanupContracts(unittest.TestCase):
    def setUp(self):
        self.held=ExitStack();self.fixture=vectors.RetainedRuntimeContracts()
        # Close retained capabilities while their checked source directories still exist.
        self.addCleanup(self.fixture.doCleanups);self.addCleanup(self.held.close)
        self.fixture.setUp()
        self.opened=time.time_ns();self.source,self.image=self.fixture.source()
        self.repo=self.fixture.fixture.repo;self.root=self.fixture.fixture.root
        for name in policy.context.SOURCES:
            path=self.repo/name;path.parent.mkdir(exist_ok=True,parents=True)
            if not path.exists():path.write_bytes((ROOT/('eng/global.ci.json' if name=='global.json' else name)).read_bytes())
        self.pins={n:H((self.repo/n).read_bytes()) for n in policy.context.SOURCES}
        self.reference=self.held.enter_context(policy.context.bundle.HeldProbeBundle(self.fixture.fixture.source,
            self.fixture.fixture.manifest,H(self.fixture.fixture.manifest)))
        self.target=self.fixture.target(self.image)
        self.operator=self.root/'operator';self.operator.mkdir(mode=0o700)
        self.python=Path(sys.executable).resolve(strict=True)
        self.docker=self.root/('docker.exe' if os.name=='nt' else 'docker');self.docker.write_bytes(b'public fake Docker');self.docker.chmod(0o700)
        self.prepared=self.held.enter_context(policy.retained.RetainedGuardPreparation(self.image.session,self.target,self.operator,
            python_path=self.python,python_sha256=H(self.python.read_bytes()),docker_path=self.docker,
            docker_sha256=H(self.docker.read_bytes()),source_pins={n:self.pins[n] for n in policy.guard.SOURCES}))
        self.preparation=self.prepared.report()
        plan,_=native_fixture();session=self.image.session
        plan.update(nonce=session._plan['nonce'],revision=session._plan['revision'],codeSha256=session._plan['codeSha256'],
            probeSha256=session._plan['probeSha256'],probeBundleSha256=self.reference.value['sha256'])
        self.plan=plan
        identity=self.preparation['controller'];parent=dict(identity,pid=identity['pid']+1)
        self.header=C(dict(schema=P.HEADER,parent=parent,controller=identity,runtimes=dict(python=H(self.python.read_bytes()),
            powershell='a'*64,git='b'*64,dotnet='c'*64,docker=H(self.docker.read_bytes())),sourcePins=self.pins,
            nativePlanBase64=policy.context.encode(C(plan)),nativePlanSha256=H(C(plan)),manifestBase64=policy.context.encode(self.reference.raw),
            manifestSha256=self.reference.pin,bases=copy.deepcopy(images.BASE_VALUES)))
        report=self.source.report()
        self.offer=dict(nonce=plan['nonce'],contextSha256=self.image.intent['contextSha256'],
            imageIntentBase64=policy.context.encode(C(self.image.intent)),publicationBindingSha256=report['bindingSha256'],
            publicationDescriptorsHeld=report['fileDescriptorsHeld'],heldDescriptorsSha256=report['heldDescriptorsSha256'],
            retainedExpiresNs=self.source.expires,reservationSha256=session.report()['reservationSha256'])
        self.facts=dict(imageId=images.BUILT,imageObservation=C(images.observed(self.image.intent)),imageObservedNs=self.opened,
            copyId='e'*64,copyProjection=C(self.fixture.fixture.observation(self.source,self.image)),
            readback=images.readback(self.fixture.fixture.source))
        self.reply=dict(P._tag('fleetory.retained-guardian-runtime.v1',self.header,self.offer),
            runtimeIntentBase64=policy.context.encode(C(self.target.intent)),imageBindingBase64=policy.context.encode(session._records['image-binding.json'][1]),
            readbackBase64=policy.context.encode(session._records['publication-continuation-readback.json'][1]),preparation=self.preparation,
            publicationDescriptorsHeld=report['fileDescriptorsHeld'],heldDescriptorsSha256=report['heldDescriptorsSha256'],childDockerOperationsPerformed=0)

    def admit(self,value=None,**changes):
        args=dict(header=self.header,offer=self.offer,facts=self.facts,reference=self.reference,now=time.time_ns());args.update(changes)
        return P.admit_runtime(C(self.reply if value is None else value),**args)

    def bound(self):
        self.prepared.close();observation=self.fixture.observation(self.target);raw=C(observation)
        self.target.bind(raw,'b'*64)
        resource=dict(id='b'*64,observation=raw,finishedNs=self.target.intent['openedNs']+1)
        report=self.source.report()
        reply=dict(P._tag('fleetory.retained-guardian-bound.v1',self.header,self.offer),
            backendBindingBase64=policy.context.encode(self.image.session._records['backend-binding.json'][1]),
            publicationDescriptorsHeld=report['fileDescriptorsHeld'],heldDescriptorsSha256=report['heldDescriptorsSha256'],
            preparationHeldThroughCreateReply=True,preparationClosedBeforeObservation=True,childDockerOperationsPerformed=0)
        return reply,resource

    def owner_resource(self):
        owner=object.__new__(policy.RetainedCleanupGuard)
        owner._root=self.root/'own-receipts';owner._root.mkdir(mode=0o700)
        owner._nonce=self.plan['nonce'];owner._records={};owner._held=self.held;owner._closed=False;owner._caller=os.getpid()
        owner._source_pin=H(C(self.pins));owner._transport=SimpleNamespace(_offer=self.offer,
            _controller=json.loads(self.header)['controller'],_parent=json.loads(self.header)['parent'])
        client=object.__new__(policy._Docker);calls=[]
        incoming=self.fixture.observation(self.target);raw=C(incoming)
        client.inspect=lambda *_:raw
        def call(args):
            calls.append(args)
            return b'' if args[:2]==['container','ls'] else ('b'*64+'\n').encode()
        client._call=call;owner._docker=client
        def check():
            self.assertEqual(os.getpid(),owner._caller)
            for value in owner._records.values():value.check()
        owner._check_owned=check
        reply=policy._Reply(policy._TOKEN,client,'runtime',('b'*64+'\n').encode(),'b'*64,
            self.target.intent['openedNs'],self.target.intent['openedNs']+2,H(C(self.target.intent)))
        resource=policy._Resource(owner,reply,self.target.intent,raw)
        return owner,resource,client,calls

    def test_actual_typed_generated_bindings_match_independent_parent_facts(self):
        self.assertEqual(self.admit(),self.target.intent)

    def test_each_handoff_field_is_checked(self):
        for key in self.reply:
            with self.subTest(key=key),self.assertRaises(REFUSED):self.admit(dict(self.reply,**{key:'foreign'}))

    def test_unknown_commands_ids_roots_and_cleanup_authority_are_refused(self):
        for key in ('command','imageId','containerId','operatorRoot','cleanupAuthorized','rootToken'):
            with self.assertRaises(REFUSED):self.admit(dict(self.reply,**{key:'foreign'}))

    def test_each_runtime_intent_field_is_checked_against_parent_creator_facts(self):
        for key in self.target.intent:
            value=dict(self.target.intent,**{key:'foreign'})
            with self.subTest(key=key),self.assertRaises(REFUSED):self.admit(dict(self.reply,runtimeIntentBase64=policy.context.encode(C(value))))

    def test_each_preparation_fact_is_checked(self):
        for key in self.preparation:
            with self.subTest(key=key),self.assertRaises(REFUSED):self.admit(dict(self.reply,preparation=dict(self.preparation,**{key:'foreign'})))

    def test_foreign_own_build_id_copy_id_or_observation_is_refused(self):
        for key in ('imageId','copyId','imageObservation','copyProjection','readback'):
            facts=dict(self.facts,**{key:'f'*64 if key.endswith('Id') else b'foreign'})
            with self.assertRaises(REFUSED):self.admit(facts=facts)

    def test_coordinated_wire_image_and_readback_record_forgery_is_refused(self):
        for field in ('imageBindingBase64','readbackBase64'):
            value=json.loads(policy.packet.decode(self.reply[field],8192));value['imageId']='sha256:'+'f'*64
            with self.assertRaises(REFUSED):self.admit(dict(self.reply,**{field:policy.context.encode(C(value))}))

    def test_expired_source_or_extended_runtime_expiry_is_refused(self):
        with self.assertRaises(REFUSED):self.admit(now=self.target.intent['expiresNs'])
        changed=dict(self.target.intent,expiresNs=self.target.intent['expiresNs']+1)
        with self.assertRaises(REFUSED):self.admit(dict(self.reply,runtimeIntentBase64=policy.context.encode(C(changed))))

    def test_duplicate_or_oversized_wire_metadata_is_refused(self):
        for raw in (C(self.reply)[:-1]+b',"schema":"duplicate"}',C(self.reply)+b' '*P.MAX_FRAME):
            with self.assertRaises(REFUSED):P.admit_runtime(raw,self.header,self.offer,self.facts,self.reference,time.time_ns())

    def test_typed_backend_binding_matches_parent_own_worker_reply(self):
        reply,resource=self.bound()
        actual=P.admit_bound(C(reply),self.header,self.offer,self.target.intent,resource,time.time_ns())
        self.assertEqual(actual,H(self.image.session._records['backend-binding.json'][1]))

    def test_each_backend_reply_field_is_checked(self):
        reply,resource=self.bound()
        for key in reply:
            with self.subTest(key=key),self.assertRaises(REFUSED):P.admit_bound(C(dict(reply,**{key:'foreign'})),
                self.header,self.offer,self.target.intent,resource,time.time_ns())

    def test_foreign_worker_id_observation_and_receipt_time_are_refused(self):
        reply,resource=self.bound()
        for changed in (dict(resource,id='f'*64),dict(resource,observation=b'{}'),dict(resource,finishedNs=time.time_ns()+1000000000)):
            with self.assertRaises(REFUSED):P.admit_bound(C(reply),self.header,self.offer,self.target.intent,changed,time.time_ns())

    def test_ordinary_dict_or_unbranded_reply_cannot_become_resource_authority(self):
        owner,_,client,calls=self.owner_resource()
        for reply in ({'identifier':'b'*64},policy._Reply(object(),client,'runtime',b'', 'b'*64,1,2,'a'*64)):
            with self.assertRaises(REFUSED):policy._Resource(owner,reply,self.target.intent,b'{}')
        self.assertEqual(calls,[])


    def test_own_worker_cleanup_does_not_recheck_expired_child_admission(self):
        _,resource,_,calls=self.owner_resource()
        with patch.object(policy.time,'time_ns',return_value=self.target.intent['expiresNs']+1):resource.dispose()
        self.assertTrue(resource._closed);self.assertEqual(calls[0],['container','rm','--force','b'*64])

    def test_foreign_fresh_immutable_id_prevents_any_deletion(self):
        _,resource,client,calls=self.owner_resource();value=self.fixture.observation(self.target);value['id']='f'*64
        client.inspect=lambda *_:C(value)
        with self.assertRaises(REFUSED):resource.dispose()
        self.assertEqual(calls,[])

    def test_sandbox_state_limits_labels_and_boolean_types_remain_exact_on_fresh_inspection(self):
        _,resource,client,calls=self.owner_resource();original=self.fixture.observation(self.target)
        for key,value in (('running',1),('privileged',True),('memory',True),('paused',True),('labels',{}),('mounts',[{}]),('command',['-c','evil'])):
            client.inspect=lambda *_,v=dict(original,**{key:value}):C(v)
            with self.assertRaises(REFUSED):resource.dispose()
        self.assertEqual(calls,[])

    def test_changed_in_memory_receipt_or_observation_cannot_replace_persisted_creator_fact(self):
        _,resource,_,calls=self.owner_resource();resource.intent=C(dict(self.target.intent,imageId='sha256:'+'f'*64))
        with self.assertRaises(REFUSED):resource.dispose()
        self.assertEqual(calls,[])

    def test_returned_facts_are_copies_and_closed_resource_refuses_replay(self):
        _,resource,_,calls=self.owner_resource();facts=resource.facts();facts['id']='f'*64
        resource.dispose();before=list(calls)
        with self.assertRaises(REFUSED):resource.dispose()
        self.assertEqual(calls,before)

    def test_failed_create_has_unknown_outcome_and_cannot_report_empty_cleanup_success(self):
        owner,_,client,_=self.owner_resource();owner._unknown=False;owner._failed=True;owner._prepared=False
        owner._cleanup_started=False;owner._resources={};owner._result=None;owner._bases=copy.deepcopy(images.BASE_VALUES)
        owner._state=lambda:'exited';client.base=lambda ref:next(v for v in owner._bases if v['reference']==ref)
        def failed():raise OSError('Generated lost reply')
        with self.assertRaises(OSError):owner._create('runtime',self.target.intent,failed)
        self.assertTrue(owner._unknown)
        with self.assertRaises(REFUSED):owner.cleanup()
        self.assertIsNone(owner._result);self.assertNotIn('result',owner._records)
        with self.assertRaises(REFUSED):owner.cleanup()

    def test_start_failure_consumes_nonce_before_docker_or_child_dispatch(self):
        root=self.root/'start-failure';root.mkdir(mode=0o700)
        paths={n:self.python if n=='python' else self.docker for n in ('python','powershell','git','dotnet','docker')}
        pins={n:H(p.read_bytes()) for n,p in paths.items()}
        with patch.object(policy,'_Docker') as docker,patch.object(policy,'_Transport') as child:
            with self.assertRaises(REFUSED):policy.RetainedCleanupGuard(self.repo,root,C(self.plan),self.reference,
                runtime_paths=paths,runtime_pins=pins,source_pins=self.pins)
            docker.assert_not_called();child.assert_not_called()
            with self.assertRaises(OSError):policy.RetainedCleanupGuard(self.repo,root,C(self.plan),self.reference,
                runtime_paths=paths,runtime_pins=pins,source_pins=self.pins)
            docker.assert_not_called();child.assert_not_called()


    def test_guardian_header_is_distinct_and_requires_docker_pin(self):
        value=json.loads(self.header);self.assertEqual(value['schema'],P.HEADER)
        value['runtimes'].pop('docker')
        with self.assertRaises(REFUSED):policy.context._header(C(value))
        value=json.loads(self.header);value['schema']='fleetory.retained-context-header.v1'
        with self.assertRaises(REFUSED):policy.context._header(C(value))


    def test_records_require_exactly_one_saved_newline(self):
        for field in ('imageBindingBase64','readbackBase64'):
            raw=policy.packet.decode(self.reply[field],8192)
            for changed in (raw[:-1],raw+b'\n'):
                with self.assertRaises(REFUSED):self.admit(dict(self.reply,**{field:policy.context.encode(changed)}))

    def test_backend_record_requires_exactly_one_saved_newline(self):
        reply,resource=self.bound();raw=policy.packet.decode(reply['backendBindingBase64'],8192)
        for changed in (raw[:-1],raw+b'\n'):
            with self.assertRaises(REFUSED):P.admit_bound(C(dict(reply,backendBindingBase64=policy.context.encode(changed))),
                self.header,self.offer,self.target.intent,resource,time.time_ns())

    def test_reply_from_another_fixed_input_cannot_become_this_resource(self):
        owner,resource,client,calls=self.owner_resource()
        reply=policy._Reply(policy._TOKEN,client,'runtime',resource.reply.raw,resource.reply.identifier,
            resource.reply.started,resource.reply.finished,'f'*64)
        with self.assertRaises(REFUSED):policy._Resource(owner,reply,self.target.intent,resource.observation)
        self.assertEqual(calls,[])

    def test_foreign_resource_capability_is_refused_by_guardian_cleanup(self):
        owner,resource,client,calls=self.owner_resource();other=object.__new__(policy.RetainedCleanupGuard)
        other.__dict__.update(owner.__dict__)
        other._intent=self.target.intent
        other._prepared=True;other._failed=False;other._cleanup_started=False;other._resources={'runtime':resource};other._result=None
        other._wall=time.time_ns();other._mono=time.monotonic_ns();other._expiry=other._wall+policy.LEASE_NS
        other._state=lambda:'exited';other._bases=copy.deepcopy(images.BASE_VALUES)
        client.base=lambda ref:next(v for v in other._bases if v['reference']==ref)
        with self.assertRaises(REFUSED):other.cleanup()
        self.assertEqual(calls,[])


    def test_failed_post_create_inspection_keeps_unknown_outcome(self):
        owner,resource,client,calls=self.owner_resource();owner._unknown=False;owner._resources={}
        client.inspect=lambda *_:b'{}'
        with self.assertRaises(REFUSED):owner._create('runtime',self.target.intent,lambda:resource.reply)
        self.assertTrue(owner._unknown);self.assertEqual(owner._resources,{})
        self.assertEqual(calls,[])


    def ready_owner(self):
        owner,resource,_,_=self.owner_resource();owner._prepared=True;owner._resources={'runtime':resource}
        owner._intent=copy.deepcopy(self.target.intent);owner._wall=time.time_ns();owner._mono=time.monotonic_ns()
        owner._expiry=min(owner._wall+policy.LEASE_NS,owner._intent['expiresNs'])
        owner._record('bound',dict(schema='generated-ready-test',nonce=owner._nonce,runtimeReceiptSha256=H(resource._snapshot),
            leaseOpenedNs=owner._wall,cleanupMonotonicOriginNs=owner._mono,leaseExpiresNs=owner._expiry))
        owner._policy_binding=None;policy._CleanupRequestBinding(owner)
        peer=object.__new__(policy._PolicyProcess);owner._policy_process=peer
        peer._owner=owner;peer._closed=False;peer._identity=dict(pid=owner._caller+100000)
        peer.request=lambda:policy.policy_request(owner._policy_binding.context_bytes(),owner._state(),owner._elapsed())
        def close(failed=False):peer._closed=True
        peer.close=close
        peer.report=lambda:dict(policy=peer._identity,creator=owner._transport._parent,policyReadyVerified=True,ownedPolicyMembersAbsent=True,peerFailedObserved=False,exitCode=0)
        return owner

    def test_cleanup_lease_and_intent_are_bound_to_persisted_creator_record(self):
        owner=self.ready_owner();owner._check_ready()
        for key in ('_wall','_mono','_expiry'):
            value=getattr(owner,key);setattr(owner,key,value+1)
            with self.assertRaises(REFUSED):owner._check_ready()
            setattr(owner,key,value)
        owner._check_ready()

    def test_coordinated_intent_deadline_rewrite_cannot_extend_own_cleanup_lease(self):
        owner=self.ready_owner();owner._intent['expiresNs']+=1000000000;owner._expiry+=1000000000
        with self.assertRaises(REFUSED):owner._check_ready()









    def test_replay_snapshot_uses_retained_descriptors_when_fresh_open_is_denied(self):
        from native_retained_cleanup_guard import _snapshot
        owner,_,_,_=self.owner_resource()
        with patch.object(Path,'read_bytes',side_effect=PermissionError('Protected held record')):
            snapshot=_snapshot(owner._root,list(owner._records.values()))
        self.assertEqual(set(snapshot),{policy.ledger_name('runtime',owner._nonce)})

    def test_replay_snapshot_refuses_unrelated_entries_without_reading_them(self):
        from native_retained_cleanup_guard import _snapshot
        owner,_,_,_=self.owner_resource();foreign=owner._root/'foreign.txt';foreign.write_bytes(b'public untouched')
        with patch.object(Path,'read_bytes',side_effect=PermissionError('No fresh opens')):
            with self.assertRaises(REFUSED):_snapshot(owner._root,list(owner._records.values()))
        self.assertEqual(foreign.read_bytes(),b'public untouched')
















class RetainedRemovalContracts(unittest.TestCase):
    """One immutable generated source vector; live owner/records/client are fresh per test."""
    @classmethod
    def setUpClass(cls):
        shared=RetainedCleanupContracts()
        cls.addClassCleanup(shared.doCleanups)
        shared.setUp()
        cls._source_fixture=shared

    def setUp(self):
        shared=type(self)._source_fixture
        self.held=ExitStack();self.addCleanup(self.held.close)
        # Register the directory first so live record handles close before removal.
        self.root=Path(self.held.enter_context(TemporaryDirectory()))
        self.plan=copy.deepcopy(shared.plan);self.offer=copy.deepcopy(shared.offer)
        self.pins=dict(shared.pins)
        self.header=bytes(shared.header)
        self.target=SimpleNamespace(intent=copy.deepcopy(shared.target.intent))
        self.fixture=SimpleNamespace(observation=vectors.RetainedRuntimeContracts.observation)

    owner_resource=RetainedCleanupContracts.owner_resource
    ready_owner=RetainedCleanupContracts.ready_owner

    def removal_fixture(self):
        owner=self.ready_owner();owner._cleanup_started=False;owner._result=None;owner._failed=False;owner._unknown=False
        resource=owner._resources['runtime'];client=owner._docker;calls=[];present=[True]
        owner._state=lambda:'exited';owner._bases=copy.deepcopy(images.BASE_VALUES)
        client.base=lambda ref:next(v for v in owner._bases if v['reference']==ref)
        def execute(args,data,seconds,limit):
            calls.append(list(args))
            if args==['container','rm','--force',resource.reply.identifier]:present[0]=False;return resource.reply.raw
            if args[:2]==['container','ls']:return resource.reply.raw if present[0] else b''
            raise AssertionError('Unexpected generated Docker command')
        client._execute=execute;client._call=lambda args:client._execute(args,b'',8,policy.guard.process.MAX_STDOUT)
        return owner,resource,client,calls,present

    def test_remove_failure_consumes_attempt_before_execution_and_refuses_retry(self):
        from native_retained_cleanup_guard import _fixture_dispose,_refused_cleanup
        owner,resource,client,calls,present=self.removal_fixture()
        with patch.object(client,'_execute',side_effect=OSError('Before execution')):_refused_cleanup(owner)
        self.assertTrue(present[0]);self.assertEqual(calls,[]);self.assertFalse(resource._closed)
        self.assertNotIn('runtime-closed',owner._records)
        with self.assertRaises(REFUSED):owner.cleanup()
        self.assertEqual(calls,[])
        _fixture_dispose(owner,[])
        self.assertFalse(present[0]);self.assertTrue(resource._closed);self.assertIsNone(owner._result)

    def test_lost_removal_reply_uses_live_fixture_fact_without_forging_guardian_closure(self):
        from native_retained_cleanup_guard import CapturedFixtureRemoval,_dispose_after_lost_removal,_refused_cleanup
        owner,resource,client,calls,present=self.removal_fixture();witness=CapturedFixtureRemoval(resource)
        execute=client._execute
        def intercepted(args,data,seconds,limit):
            return witness.remove_and_withhold(args,data,seconds,limit) if args[:2]==['container','rm'] else execute(args,data,seconds,limit)
        with patch.object(client,'_execute',side_effect=intercepted):_refused_cleanup(owner)
        self.assertFalse(present[0]);self.assertEqual(witness.raw,resource.reply.raw)
        before=list(calls)
        with self.assertRaises(REFUSED):witness.remove_and_withhold(['container','rm','--force',resource.reply.identifier],b'',8,policy.guard.process.MAX_STDOUT)
        with self.assertRaises(REFUSED):owner.cleanup()
        self.assertEqual(calls,before)
        _dispose_after_lost_removal(owner,[],[witness]);witness.verify(resource)
        self.assertEqual(sum(c[:2]==['container','rm'] for c in calls),1)
        self.assertFalse(resource._closed);self.assertNotIn('runtime-closed',owner._records);self.assertIsNone(owner._result)

    def test_removal_fact_refuses_serialized_metadata_and_foreign_live_creator(self):
        from native_retained_cleanup_guard import CapturedFixtureRemoval,_fixture_dispose
        owner,resource,_,calls,_=self.removal_fixture()
        with self.assertRaises(REFUSED):CapturedFixtureRemoval(dict(resource.facts()))
        with self.assertRaises(REFUSED):_fixture_dispose(owner,[],[dict(id=resource.reply.identifier,absenceVerified=True)])
        owner._resources['runtime']=object()
        with self.assertRaises(REFUSED):CapturedFixtureRemoval(resource)
        self.assertEqual(calls,[])

    def test_live_removal_fact_refuses_changed_creator_before_any_dispatch(self):
        from native_retained_cleanup_guard import CapturedFixtureRemoval
        owner,resource,client,calls,_=self.removal_fixture();witness=CapturedFixtureRemoval(resource)
        owner._cleanup_started=True;owner._record('delete',dict(status='ATTEMPT_CONSUMED'))
        original=resource.reply
        resource.reply=policy._Reply(policy._TOKEN,client,'runtime',original.raw,original.identifier,original.started,original.finished,original.input_pin)
        with self.assertRaises(REFUSED):witness.remove_and_withhold(['container','rm','--force',original.identifier],b'',8,policy.guard.process.MAX_STDOUT)
        self.assertEqual(calls,[])

    def test_live_removal_fact_cannot_extend_original_cleanup_deadline(self):
        from native_retained_cleanup_guard import CapturedFixtureRemoval
        owner,resource,_,calls,_=self.removal_fixture();witness=CapturedFixtureRemoval(resource)
        owner._cleanup_started=True;owner._record('delete',dict(status='ATTEMPT_CONSUMED'))
        with patch.object(policy.time,'monotonic_ns',return_value=owner._mono+policy.CLEANUP_NS):
            with self.assertRaises(REFUSED):witness.remove_and_withhold(['container','rm','--force',resource.reply.identifier],b'',8,policy.guard.process.MAX_STDOUT)
        self.assertEqual(calls,[])

    def test_live_removal_fact_rechecks_absence_and_never_removes_a_reappeared_id(self):
        from native_retained_cleanup_guard import CapturedFixtureRemoval
        owner,resource,_,calls,present=self.removal_fixture();witness=CapturedFixtureRemoval(resource)
        owner._cleanup_started=True;owner._record('delete',dict(status='ATTEMPT_CONSUMED'))
        self.assertEqual(witness.remove_and_withhold(['container','rm','--force',resource.reply.identifier],b'',8,policy.guard.process.MAX_STDOUT),b'')
        present[0]=True
        with self.assertRaises(REFUSED):witness.verify(resource)
        self.assertEqual(sum(c[:2]==['container','rm'] for c in calls),1)


    def test_missing_inner_reply_never_becomes_fixture_absence_authority(self):
        from native_retained_cleanup_guard import CapturedFixtureRemoval,_fixture_dispose
        owner,resource,client,calls,present=self.removal_fixture()
        execute=client._execute
        def lost(args,data,seconds,limit):execute(args,data,seconds,limit);return b''
        client._execute=lost;witness=CapturedFixtureRemoval(resource)
        owner._cleanup_started=True;owner._record('delete',dict(status='ATTEMPT_CONSUMED'))
        with self.assertRaises(REFUSED):witness.remove_and_withhold(['container','rm','--force',resource.reply.identifier],b'',8,policy.guard.process.MAX_STDOUT)
        self.assertTrue(witness.attempted);self.assertFalse(witness.captured);self.assertFalse(present[0])
        with self.assertRaises(REFUSED):_fixture_dispose(owner,[],[witness])
        self.assertEqual(sum(c[:2]==['container','rm'] for c in calls),1);self.assertFalse(resource._closed)

    def test_complete_inner_reply_without_actual_absence_cannot_close_fixture_or_guardian(self):
        from native_retained_cleanup_guard import CapturedFixtureRemoval,_fixture_dispose
        owner,resource,client,calls,present=self.removal_fixture();execute=client._execute
        def still_present(args,data,seconds,limit):
            if args[:2]==['container','rm']:calls.append(list(args));return resource.reply.raw
            return execute(args,data,seconds,limit)
        client._execute=still_present;witness=CapturedFixtureRemoval(resource)
        owner._cleanup_started=True;owner._record('delete',dict(status='ATTEMPT_CONSUMED'))
        with self.assertRaises(REFUSED):witness.remove_and_withhold(['container','rm','--force',resource.reply.identifier],b'',8,policy.guard.process.MAX_STDOUT)
        self.assertTrue(present[0]);self.assertFalse(witness.captured)
        with self.assertRaises(REFUSED):_fixture_dispose(owner,[],[witness])
        self.assertFalse(resource._closed);self.assertIsNone(owner._result)


    def test_unattempted_live_removal_witness_does_not_prevent_checked_fixture_disposal(self):
        from native_retained_cleanup_guard import CapturedFixtureRemoval,_dispose_after_lost_removal
        owner,resource,_,calls,present=self.removal_fixture();witness=CapturedFixtureRemoval(resource)
        self.assertFalse(_dispose_after_lost_removal(owner,[],[witness]))
        self.assertFalse(witness.attempted);self.assertFalse(present[0]);self.assertTrue(resource._closed)
        self.assertIsNone(owner._result);self.assertEqual(sum(c[:2]==['container','rm'] for c in calls),1)



def source_clock(plan):
    item=object.__new__(policy._Transport);item._wall=0;item._mono=0;item._plan=plan
    item._offer=dict(retainedOpenedNs=20_000_000_000,retainedExpiresNs=80_000_000_000,
        imageIntentBase64=policy.context.encode(C(dict(openedNs=21_000_000_000,expiresNs=81_000_000_000))))
    with patch.object(policy.time,'time_ns',return_value=25_000_000_000),patch.object(policy.time,'monotonic_ns',return_value=30_000_000_000):item._start_source_clock()
    return item



class RetainedCleanupLifecycleContracts(unittest.TestCase):
    def setUp(self):
        self.held=ExitStack();self.addCleanup(self.held.close)
        self.operator=Path(self.held.enter_context(TemporaryDirectory(prefix='fleetory-cleanup-clock-')))
        self.plan,_=native_fixture()

    def test_complete_creator_reply_is_required_without_trimming_or_id_adoption(self):
        client=object.__new__(policy._Docker)
        invalid=(b'',b'b'*63+b'\n',b'b'*64,b' '+b'b'*64+b'\n',b'B'*64+b'\n',b'b'*64+b'\nextra\n')
        for raw in invalid:
            with patch.object(client,'_execute',return_value=raw,create=True),self.assertRaises(REFUSED):client._created('runtime',[],'a'*64)
        with patch.object(client,'_execute',return_value=b'b'*64+b'\n',create=True):reply=client._created('runtime',[],'a'*64)
        self.assertIs(reply.token,policy._TOKEN);self.assertEqual(reply.identifier,'b'*64)


    def test_ledger_names_have_only_fixed_kinds_and_canonical_uuid(self):
        for kind in policy.KINDS:self.assertEqual(policy.ledger_name(kind,self.plan['nonce']),'retained-owned-'+kind+'-'+self.plan['nonce']+'.json')
        for kind,nonce in (('../x',self.plan['nonce']),('start','../x')):
            with self.assertRaises(REFUSED):policy.ledger_name(kind,nonce)


    def test_binary_docker_input_output_and_deadline_bounds_precede_dispatch(self):
        client=object.__new__(policy.guard.native._Docker)
        invalid=(((),b'',8,1),([],bytearray(),8,1),([],b'',True,1),([],b'',26,1),([],b'',8,0),([],b'',8,16*1024*1024+1))
        with patch.object(policy.guard.native.subprocess,'Popen') as spawn:
            for args,data,seconds,limit in invalid:
                with self.assertRaises(REFUSED):client._execute(args,data,seconds,limit)
            spawn.assert_not_called()


    def test_original_context_profile_keeps_its_fixed_55_second_clock(self):
        item=object.__new__(policy.context.RetainedContextTransport);item._wall=100;item._mono=200
        with patch.object(policy.time,'time_ns',return_value=100+55_000_000_000-1),patch.object(policy.time,'monotonic_ns',return_value=200+55_000_000_000-1):item._clock_check()
        for wall,mono in ((100+55_000_000_000,200+55_000_000_000-1),(100+55_000_000_000-1,200+55_000_000_000)):
            with patch.object(policy.time,'time_ns',return_value=wall),patch.object(policy.time,'monotonic_ns',return_value=mono),self.assertRaises(REFUSED+(policy.context.process.LaunchError,)):item._clock_check()


    def test_extended_handoff_honors_original_source_end_and_monotonic_bound(self):
        item=source_clock(self.plan)
        with patch.object(policy.time,'time_ns',return_value=70_000_000_000),patch.object(policy.time,'monotonic_ns',return_value=75_000_000_000):item._clock_check()
        for wall,mono in ((80_000_000_000,84_000_000_000),(79_000_000_000,85_000_000_000),(20_000_000_000,31_000_000_000),(30_000_000_000,29_000_000_000)):
            with patch.object(policy.time,'time_ns',return_value=wall),patch.object(policy.time,'monotonic_ns',return_value=mono),self.assertRaises(REFUSED):item._clock_check()
        self.assertEqual(item.clock_snapshot()['expiresNs'],80_000_000_000)


    def test_source_clock_cannot_be_renewed_or_extended_by_offer_mutation(self):
        item=source_clock(self.plan);before=item.clock_snapshot();item._offer['retainedExpiresNs']+=60_000_000_000
        with self.assertRaises(REFUSED):item._start_source_clock()
        self.assertEqual(item.clock_snapshot(),before)


    def test_source_clock_is_bound_to_its_persisted_admission_record(self):
        item=source_clock(self.plan);item._source_clock_record=self.held.enter_context(policy.guard.attempts._claim_record(self.operator,
            policy.ledger_name('admission',self.plan['nonce']),item.clock_snapshot()))
        item._check_source_clock();opened,end,mono,origin=item._source_clock;item._source_clock=(opened,end+1,mono+1,origin)
        with self.assertRaises(REFUSED):item._check_source_clock()


    def test_handoff_clock_before_source_opening_is_refused(self):
        item=source_clock(self.plan);del item._source_clock
        with patch.object(policy.time,'time_ns',return_value=20_000_000_000),patch.object(policy.time,'monotonic_ns',return_value=30_000_000_000),self.assertRaises(REFUSED):item._start_source_clock()


    def test_context_exit_cleans_known_failed_preparation_before_closing_controller(self):
        owner=object.__new__(policy.RetainedCleanupGuard);owner._closed=False;owner._cleanup_started=False;owner._prepared=False;owner._failed=True
        calls=[];owner.cleanup=lambda:calls.append('cleanup');owner.close=lambda:calls.append('close')
        owner.__exit__(OSError,None,None);self.assertEqual(calls,['cleanup','close'])


    def test_context_exit_does_not_replay_consumed_cleanup(self):
        owner=object.__new__(policy.RetainedCleanupGuard);owner._closed=False;owner._cleanup_started=True;owner._prepared=True;owner._failed=False
        with patch.object(owner,'cleanup') as cleanup,patch.object(owner,'close') as close:
            owner.__exit__(None,None,None);cleanup.assert_not_called();close.assert_called_once()


    def test_context_exit_closes_controller_even_if_own_rollback_fails(self):
        owner=object.__new__(policy.RetainedCleanupGuard);owner._closed=False;owner._cleanup_started=False;owner._prepared=False;owner._failed=True
        with patch.object(owner,'cleanup',side_effect=OSError('Generated cleanup failure')),patch.object(owner,'close') as close:
            with self.assertRaises(OSError):owner.__exit__(OSError,None,None)
            close.assert_called_once()


    def test_exit_during_identity_query_requires_actual_owned_exit_signal(self):
        owner=object.__new__(policy.RetainedCleanupGuard)
        from unittest.mock import Mock
        owner._transport=SimpleNamespace(_exited=Mock(side_effect=[False,False,False,True]),
            _fence=SimpleNamespace(identity=Mock(side_effect=OSError('Terminating owned process'))),
            _child=object(),_runtimes={'python':object()})
        with patch.object(policy.time,'sleep'):
            self.assertEqual(owner._state(),'exited')
        self.assertEqual(owner._transport._exited.call_count,4)


    def test_live_process_identity_failure_is_refused_after_fixed_wait(self):
        owner=object.__new__(policy.RetainedCleanupGuard)
        from unittest.mock import Mock
        owner._transport=SimpleNamespace(_exited=Mock(return_value=False),
            _fence=SimpleNamespace(identity=Mock(side_effect=OSError('Live observation denied'))),
            _child=object(),_runtimes={'python':object()})
        with patch.object(policy.time,'monotonic_ns',side_effect=[0,3_000_000_000]),patch.object(policy.time,'sleep') as sleep:
            with self.assertRaises(OSError):owner._state()
            sleep.assert_not_called()


    def test_changed_live_controller_identity_never_becomes_death(self):
        owner=object.__new__(policy.RetainedCleanupGuard)
        from unittest.mock import Mock
        owner._transport=SimpleNamespace(_exited=Mock(return_value=False),
            _fence=SimpleNamespace(identity=Mock(return_value={})),_controller={'pid':456},
            _child=object(),_runtimes={'python':object()})
        with patch.object(policy.guard,'_process_identity',return_value={'pid':123}):
            with self.assertRaises(REFUSED):owner._state()
        self.assertEqual(owner._transport._exited.call_count,1)


    def test_native_closure_accepts_expired_source_only_after_owned_members_absent(self):
        from native_retained_cleanup_guard import verify_closure
        value=dict(ownedControllerMembersAbsent=True,publicationDescriptorsHeld=58,
            gracefulDescriptorClosureVerified=False,controllerDeathObserved=True)
        verify_closure(value,'lease-expired',True)


    def test_native_closure_refuses_unexpected_non_graceful_live_source(self):
        from native_retained_cleanup_guard import verify_closure
        value=dict(ownedControllerMembersAbsent=True,publicationDescriptorsHeld=58,
            gracefulDescriptorClosureVerified=False,controllerDeathObserved=True)
        with self.assertRaises(REFUSED):verify_closure(value,'lease-expired',False)


    def test_source_expiry_never_waives_actual_owned_process_disposal(self):
        from native_retained_cleanup_guard import verify_closure
        value=dict(ownedControllerMembersAbsent=False,publicationDescriptorsHeld=58,
            gracefulDescriptorClosureVerified=False,controllerDeathObserved=True)
        with self.assertRaises(REFUSED):verify_closure(value,'lease-expired',True)


    def test_test_only_paused_comparison_allows_only_the_actual_paused_field(self):
        from native_retained_cleanup_guard import paused_fixture_observation
        original=dict(id='b'*64,paused=False,running=True,memory=402653184)
        paused_fixture_observation(C(dict(original,paused=True)),C(original))

    def test_test_only_paused_comparison_refuses_changed_identity_and_profile(self):
        from native_retained_cleanup_guard import paused_fixture_observation
        original=dict(id='b'*64,paused=False,running=True,memory=402653184)
        expected=dict(original,paused=True)
        for key,value in (('id','c'*64),('running',False),('memory',402653185),('paused',1),('status','running')):
            with self.subTest(key=key),self.assertRaises(REFUSED):paused_fixture_observation(C(dict(expected,**{key:value})),C(original))

    def test_test_only_paused_comparison_refuses_extra_fields_and_unpaused_input(self):
        from native_retained_cleanup_guard import paused_fixture_observation
        original=dict(id='b'*64,paused=False,running=True,memory=402653184)
        for changed in (original,dict(original,paused=True,extra=True)):
            with self.assertRaises(REFUSED):paused_fixture_observation(C(changed),C(original))

    def test_test_only_paused_comparison_requires_an_original_running_snapshot(self):
        from native_retained_cleanup_guard import paused_fixture_observation
        paused=dict(id='b'*64,paused=True,running=True,memory=402653184)
        with self.assertRaises(REFUSED):paused_fixture_observation(C(paused),C(paused))


    def test_fixture_removal_reply_requires_complete_exact_bytes_and_full_id(self):
        from native_retained_cleanup_guard import fixture_removal_reply
        identifier='b'*64;fixture_removal_reply(identifier.encode()+b'\n',identifier)
        for raw in (b'',identifier.encode(),('c'*64+'\n').encode(),b' '+identifier.encode()+b'\n',bytearray(identifier.encode()+b'\n'),True):
            with self.subTest(raw=raw),self.assertRaises(REFUSED):fixture_removal_reply(raw,identifier)

    def test_fixture_removal_reply_refuses_names_truncated_ids_and_noncanonical_identifiers(self):
        from native_retained_cleanup_guard import fixture_removal_reply
        for identifier in ('worker-name','b'*63,'B'*64,'../container'):
            with self.subTest(identifier=identifier),self.assertRaises(REFUSED):fixture_removal_reply(identifier.encode()+b'\n',identifier)


class RetainedPolicyRequestContracts(unittest.TestCase):
    """Wire policy requests cannot replace the live creator's replies, clocks or records."""
    setUpClass=classmethod(RetainedRemovalContracts.setUpClass.__func__)
    setUp=RetainedRemovalContracts.setUp
    ready_owner=RetainedCleanupContracts.ready_owner

    def owner_resource(self):
        result=RetainedCleanupContracts.owner_resource(self)
        result[0]._generated_calls=result[3]
        return result

    def owner(self):
        root=self.root;number=getattr(self,'_owner_number',0)+1;self._owner_number=number
        self.root=root/str(number);self.root.mkdir(mode=0o700)
        try:owner=self.ready_owner()
        finally:self.root=root
        owner._cleanup_started=True;owner._test_elapsed=0;owner._test_state='live'
        owner._elapsed=lambda:owner._test_elapsed;owner._state=lambda:owner._test_state
        return owner

    def request(self,owner,reason='lease-expired'):
        return C(dict(schema=policy.POLICY_REQUEST,contextSha256=H(owner._policy_binding.context_bytes()),reason=reason))

    def expired(self,owner):owner._test_elapsed=owner._expiry-owner._wall

    def test_public_context_contains_only_fixed_inputs_and_digests(self):
        owner=self.owner();raw=owner._policy_binding.context_bytes();value=policy.policy_context(raw)
        self.assertEqual(value['leaseOpenedNs'],owner._wall)
        self.assertEqual(value['readyRecordSha256'],H(owner._records['bound']._bytes))
        self.assertFalse(set(value)&{'containerId','command','path','endpoint','cleanupAuthorized','owner'})
        value['leaseOpenedNs']=0
        self.assertNotEqual(C(value),owner._policy_binding.context_bytes())

    def test_live_controller_before_original_expiry_has_no_request(self):
        owner=self.owner();raw=owner._policy_binding.context_bytes()
        for elapsed in (0,owner._expiry-owner._wall-1):self.assertIsNone(policy.policy_request(raw,'live',elapsed))

    def test_exact_original_lease_boundary_requests_cleanup(self):
        owner=self.owner();self.expired(owner)
        request=policy.policy_request(owner._policy_binding.context_bytes(),'live',owner._test_elapsed)
        self.assertEqual(owner._policy_binding.admit(request),('lease-expired','live'))
        self.assertEqual(owner._policy_binding._request_pin,H(request))

    def test_fenced_controller_exit_can_precede_lease_expiry(self):
        owner=self.owner();owner._test_state='exited'
        request=policy.policy_request(owner._policy_binding.context_bytes(),'exited',0)
        self.assertEqual(owner._policy_binding.admit(request),('controller-exited','exited'))

    def test_expiry_has_priority_when_both_conditions_hold(self):
        owner=self.owner();self.expired(owner)
        request=policy.policy_request(owner._policy_binding.context_bytes(),'exited',owner._test_elapsed)
        self.assertEqual(json.loads(request)['reason'],'lease-expired')

    def test_early_lease_request_is_independently_refused_by_creator(self):
        owner=self.owner()
        with self.assertRaises(REFUSED):owner._policy_binding.admit(self.request(owner))
        self.assertFalse(owner._policy_binding._accepted);self.assertEqual(owner._generated_calls,[])

    def test_claimed_controller_exit_cannot_replace_creator_observation(self):
        owner=self.owner()
        with self.assertRaises(REFUSED):owner._policy_binding.admit(self.request(owner,'controller-exited'))
        self.assertEqual(owner._generated_calls,[])

    def test_new_fence_observation_is_used_after_request_generation(self):
        owner=self.owner();request=policy.policy_request(owner._policy_binding.context_bytes(),'exited',0)
        with self.assertRaises(REFUSED):owner._policy_binding.admit(request)

    def test_controller_exit_request_remains_valid_if_lease_expires_in_transit(self):
        owner=self.owner();request=policy.policy_request(owner._policy_binding.context_bytes(),'exited',0)
        self.expired(owner);owner._test_state='exited'
        self.assertEqual(owner._policy_binding.admit(request),('controller-exited','exited'))

    def test_request_from_different_public_context_is_refused(self):
        owner=self.owner();self.expired(owner);value=json.loads(owner._policy_binding.context_bytes())
        value['sourcePinsSha256']='f'*64
        foreign=policy.policy_request(C(value),'live',owner._test_elapsed)
        with self.assertRaises(REFUSED):owner._policy_binding.admit(foreign)
        self.assertEqual(owner._generated_calls,[])

    def test_authority_paths_ids_and_extended_deadlines_are_not_request_fields(self):
        for key in ('containerId','command','operatorRoot','expiresNs','elapsedNs','cleanupAuthorized'):
            owner=self.owner();self.expired(owner);request=json.loads(self.request(owner));request[key]='foreign'
            with self.subTest(key=key),self.assertRaises(REFUSED):owner._policy_binding.admit(C(request))
            self.assertEqual(owner._generated_calls,[])

    def test_noncanonical_duplicate_and_oversized_requests_are_refused(self):
        for kind in ('space','duplicate','oversized','bytearray'):
            owner=self.owner();self.expired(owner);raw=self.request(owner)
            raw={'space':raw+b' ','duplicate':raw[:-1]+b',"reason":"lease-expired"}',
                 'oversized':raw+b' '*policy.MAX_POLICY,'bytearray':bytearray(raw)}[kind]
            with self.subTest(kind=kind),self.assertRaises(REFUSED):owner._policy_binding.admit(raw)
            self.assertFalse(owner._policy_binding._accepted)

    def test_refused_attempt_cannot_be_replaced_with_valid_request(self):
        owner=self.owner();self.expired(owner);binding=owner._policy_binding
        with self.assertRaises(REFUSED):binding.admit(b'{}')
        with self.assertRaises(REFUSED):binding.admit(self.request(owner))
        self.assertTrue(binding._attempted);self.assertFalse(binding._accepted);self.assertEqual(owner._generated_calls,[])

    def test_accepted_request_cannot_be_replayed(self):
        owner=self.owner();self.expired(owner);raw=self.request(owner);owner._policy_binding.admit(raw)
        with self.assertRaises(REFUSED):owner._policy_binding.admit(raw)
        self.assertEqual(owner._generated_calls,[])

    def test_late_request_cannot_restart_original_cleanup_clock(self):
        for elapsed in (-1,True,policy.CLEANUP_NS,policy.CLEANUP_NS+1):
            owner=self.owner();owner._test_elapsed=elapsed;owner._test_state='exited'
            with self.subTest(elapsed=elapsed),self.assertRaises(REFUSED):owner._policy_binding.admit(self.request(owner,'controller-exited'))
            self.assertEqual(owner._generated_calls,[])

    def test_pid_change_cannot_transfer_live_binding(self):
        owner=self.owner();self.expired(owner);raw=self.request(owner)
        with patch.object(policy.os,'getpid',return_value=owner._caller+1),self.assertRaises(REFUSED):owner._policy_binding.admit(raw)

    def test_original_clock_fields_cannot_be_rewritten(self):
        for key in ('_mono','_wall','_expiry'):
            owner=self.owner();raw=self.request(owner);setattr(owner,key,getattr(owner,key)+1)
            self.expired(owner)
            with self.subTest(key=key),self.assertRaises(REFUSED):owner._policy_binding.admit(raw)

    def test_live_client_and_transport_cannot_be_replaced_by_equivalent_metadata(self):
        for key in ('_docker','_transport','_records'):
            owner=self.owner();self.expired(owner);raw=self.request(owner)
            setattr(owner,key,dict(owner._records) if key=='_records' else SimpleNamespace())
            with self.subTest(key=key),self.assertRaises(REFUSED):owner._policy_binding.admit(raw)
            self.assertEqual(owner._generated_calls,[])

    def test_cloned_reply_cannot_replace_creator_retained_reply_object(self):
        owner=self.owner();self.expired(owner);raw=self.request(owner);resource=owner._resources['runtime'];reply=resource.reply
        resource.reply=policy._Reply(reply.token,reply.client,reply.kind,reply.raw,reply.identifier,reply.started,reply.finished,reply.input_pin)
        with self.assertRaises(REFUSED):owner._policy_binding.admit(raw)

    def test_foreign_resource_or_bound_handle_cannot_replace_original_live_objects(self):
        for key in ('runtime','bound'):
            owner=self.owner();self.expired(owner);raw=self.request(owner)
            if key=='runtime':owner._resources['runtime']=object()
            else:owner._records['bound']=SimpleNamespace(_bytes=owner._records['bound']._bytes)
            with self.subTest(key=key),self.assertRaises(REFUSED):owner._policy_binding.admit(raw)

    def test_serialized_policy_context_cannot_construct_creator_binding(self):
        owner=self.owner();raw=owner._policy_binding.context_bytes()
        for copied in (raw,json.loads(raw),dict(owner=owner._nonce),SimpleNamespace()):
            with self.subTest(kind=type(copied).__name__),self.assertRaises(REFUSED):policy._CleanupRequestBinding(copied)
        with self.assertRaises(REFUSED):policy._CleanupRequestBinding(owner)
        other=self.owner();other._policy_binding=None;other._prepared=False;del other._records['bound']
        with self.assertRaises(REFUSED):policy._CleanupRequestBinding(other)
        self.assertEqual(other._generated_calls,[])

    def test_replacing_binding_with_wire_context_is_not_admitted(self):
        owner=self.owner();binding=owner._policy_binding;owner._policy_binding=json.loads(binding.context_bytes())
        with self.assertRaises(REFUSED):binding.context_bytes()
        with self.assertRaises(REFUSED):owner._check_ready()

    def test_closed_creator_cannot_issue_or_admit_policy_requests(self):
        owner=self.owner();raw=self.request(owner);owner._closed=True
        with self.assertRaises(REFUSED):owner._policy_binding.context_bytes()
        with self.assertRaises(REFUSED):owner._policy_binding.admit(raw)

    def test_real_generated_owned_close_keeps_original_binding_checkable(self):
        owner=self.owner();resource=owner._resources['runtime'];resource.dispose()
        owner._policy_binding.check()
        self.assertTrue(resource._closed);self.assertIn('runtime-closed',owner._records)

    def test_forged_closed_resource_does_not_satisfy_live_binding(self):
        owner=self.owner();resource=owner._resources['runtime'];resource._closed=True
        with self.assertRaises((KeyError,*REFUSED)):owner._policy_binding.check()
        owner._record('runtime-closed',dict(schema='fleetory.retained-own-resource-closed.v1',nonce=owner._nonce,
            id='f'*64,receiptSha256=H(resource._snapshot),absenceVerified=True))
        with self.assertRaises(REFUSED):owner._policy_binding.check()

    def test_policy_inputs_reject_boolean_clocks_states_and_elapsed(self):
        owner=self.owner();raw=owner._policy_binding.context_bytes();context=json.loads(raw)
        for key in ('leaseOpenedNs','cleanupMonotonicOriginNs','leaseExpiresNs','runtimeExpiresNs'):
            with self.subTest(key=key),self.assertRaises(REFUSED):policy.policy_context(C(dict(context,**{key:True})))
        for state,elapsed in ((True,0),('foreign',0),('live',True),('live',-1),('live',policy.CLEANUP_NS)):
            with self.subTest(state=state,elapsed=elapsed),self.assertRaises(REFUSED):policy.policy_request(raw,state,elapsed)

    def test_coordinated_owner_and_policy_deadline_rewrite_cannot_replace_held_record(self):
        owner=self.owner();owner._intent['expiresNs']+=1
        for key in ('_wall','_mono','_expiry'):setattr(owner,key,getattr(owner,key)+1)
        value=json.loads(owner._policy_binding._context)
        for key in ('runtimeExpiresNs','leaseOpenedNs','cleanupMonotonicOriginNs','leaseExpiresNs'):value[key]+=1
        owner._policy_binding._context=C(value)
        policy.policy_context(C(value));self.expired(owner)
        raw=C(dict(schema=policy.POLICY_REQUEST,contextSha256=H(C(value)),reason='lease-expired'))
        with self.assertRaises(REFUSED):owner._policy_binding.admit(raw)

    def test_policy_functions_cannot_add_ids_or_dispatch_docker(self):
        owner=self.owner();raw=owner._policy_binding.context_bytes();self.expired(owner)
        for key in ('containerId','command','endpoint','owner'):
            with self.subTest(key=key),self.assertRaises(REFUSED):policy.policy_context(C(dict(json.loads(raw),**{key:'foreign'})))
        self.assertIsNotNone(policy.policy_request(raw,'live',owner._test_elapsed))
        self.assertEqual(owner._generated_calls,[])


class RetainedPolicyChildContracts(unittest.TestCase):
    """Generated lifecycle models; actual native peers are checked separately."""
    setUpClass=classmethod(RetainedRemovalContracts.setUpClass.__func__)
    setUp=RetainedRemovalContracts.setUp
    ready_owner=RetainedCleanupContracts.ready_owner
    owner_resource=RetainedPolicyRequestContracts.owner_resource
    owner=RetainedPolicyRequestContracts.owner
    request_bytes=RetainedPolicyRequestContracts.request

    def peer_fixture(self,ready_change=None,identity_change=None,spawn_error=None):
        previous=getattr(self,'_last_model',None)
        if previous is not None and hasattr(previous,'peer'):previous.peer.close()
        owner=self.owner();owner._policy_process=None;owner._waiting=policy.threading.Event();owner._unknown=False
        owner._transport._repo=ROOT
        python=SimpleNamespace(path=Path(sys.executable),digest=json.loads(self.header)['runtimes']['python'])
        owner._transport._runtimes={'python':python};owner._transport._header=self.header
        child=SimpleNamespace(returncode=None,stdout=object(),stderr=object(),pid=owner._caller+200000)
        def wait(timeout):
            self.assertIsNotNone(child.returncode)
            return child.returncode
        child.wait=wait;child.poll=lambda:child.returncode
        stdin=SimpleNamespace(closed=False)
        stdin.close=lambda:setattr(stdin,'closed',True)
        child.stdin=stdin
        identity=dict(owner._transport._parent,pid=child.pid)
        if identity_change:identity_change(identity)
        fence=SimpleNamespace()
        # Platform fences return imageSha256; the trusted adapter forms the protocol identity.
        fence.identity=lambda *_:{('imageSha256' if k=='executableSha256' else k):v for k,v in identity.items()}
        fence.exited=lambda:child.returncode is not None
        events=[];commands=[];ended=[];context_pin=H(owner._policy_binding.context_bytes())
        class Pumps:
            def __init__(p,process,data):
                self.assertIs(process,child);self.assertEqual(data,b'')
                p.stdout=bytearray();p.stderr=bytearray();p.errors=[];p.threads=[];p.finish_action=None
            def _read(p,*_):pass
            def _send(p,raw):
                events.append(raw)
                if raw.endswith(b'\n'):
                    self.assertIn('policy-start',owner._records)
                    header,context_raw=policy.policy_child_header(raw[:-1])
                    ready=dict(schema=policy.POLICY_READY,contextSha256=H(context_raw),parent=header['parent'],policy=header['policy'],
                        sourcePinsSha256=H(C(header['sourcePins'])),noDockerInterface=True,clocksReset=False)
                    if ready_change:ready_change(ready)
                    p.stdout.extend(policy.context.frame(ready,policy.MAX_POLICY))
                else:
                    event=policy.admit_policy_event(raw[4:],context_pin)
                    if event=='cancel':child.returncode=0
                    else:
                        request=dict(schema=policy.POLICY_REQUEST,contextSha256=context_pin,reason='controller-exited')
                        p.stdout.extend(policy.context.frame(request,policy.MAX_POLICY));child.returncode=0
            def finish(p):
                if p.finish_action:
                    action,p.finish_action=p.finish_action,None;action()
        def spawn(command):
            self.assertIn('policy-start',owner._records);self.assertEqual(events,[])
            commands.append(command)
            if spawn_error:raise spawn_error
            return child
        def finish(process,owned,pumps):
            if process is None:return None,None
            self.assertIs(process,child);self.assertIs(owned,fence)
            if child.returncode is None:child.returncode=0
            if pumps:pumps.finish()
            ended.append(process)
            return dict(noRunningMembersVerified=True),None
        for name,value in (('_spawn',spawn),('_create_fence',lambda actual:fence),('_Pumps',Pumps),('_finish_owned',finish)):
            self.held.enter_context(patch.object(policy.context.process,name,value))
        model=SimpleNamespace(owner=owner,child=child,fence=fence,identity=identity,events=events,commands=commands,ended=ended)
        self._last_model=model
        return model

    def start(self,**changes):
        model=self.peer_fixture(**changes);model.peer=policy._PolicyProcess(model.owner)
        self.addCleanup(model.peer.close)
        return model

    def complete(self,model,reason='lease-expired',code=0,tail=b''):
        model.owner._test_elapsed=model.owner._expiry-model.owner._wall if reason=='lease-expired' else 0
        model.owner._test_state='exited' if reason=='controller-exited' else 'live'
        raw=self.request_bytes(model.owner,reason)
        model.peer._pumps.stdout.extend(policy.context.frame(json.loads(raw),policy.MAX_POLICY)+tail)
        model.child.returncode=code
        return raw

    def test_launch_is_consumed_before_fixed_command_and_input(self):
        model=self.start();command=model.commands[0]
        self.assertEqual(command.arguments,('-I','-B',str(ROOT/'eng/pilot/RetainedContextController.py'),'--cleanup-policy'))
        self.assertEqual(command.directory,ROOT);self.assertNotIn('docker',command.env)
        self.assertFalse(set(command.env)&{'DOCKER_HOST','DOCKER_CONFIG','BAO_TOKEN','VAULT_TOKEN','PGPASSWORD'})
        header,_=policy.policy_child_header(model.events[0][:-1])
        self.assertEqual(set(header),{'schema','parent','policy','pythonSha256','sourcePins','contextBase64'})
        self.assertEqual(model.owner._generated_calls,[])

    def test_ready_binds_actual_distinct_peer_and_original_context(self):
        model=self.start();record=model.owner._records['policy-ready'].report()
        self.assertEqual(record['policy'],model.identity)
        self.assertNotIn(record['policy']['pid'],(model.owner._caller,model.owner._transport._controller['pid']))
        self.assertTrue(record['actualOwnedFenceHeld']);self.assertTrue(record['noDockerInterface']);self.assertFalse(record['clocksReset'])

    def test_policy_start_cannot_be_replayed_or_built_from_wire(self):
        model=self.start()
        for owner in (model.owner,json.loads(model.peer._context),SimpleNamespace()):
            with self.subTest(owner=type(owner).__name__),self.assertRaises(REFUSED):policy._PolicyProcess(owner)
        self.assertEqual(len(model.commands),1)

    def test_each_ready_fact_must_match_and_failure_disposes_only_owned_peer(self):
        for key in ('schema','contextSha256','parent','policy','sourcePinsSha256','noDockerInterface','clocksReset'):
            with self.subTest(key=key):
                model=self.peer_fixture(ready_change=lambda v:v.update({key:'foreign'}))
                with self.assertRaises(REFUSED):policy._PolicyProcess(model.owner)
                self.assertEqual(model.ended,[model.child]);self.assertTrue(model.owner._policy_process._closed)
                self.assertEqual(model.owner._generated_calls,[])

    def test_extra_ready_authority_is_refused(self):
        model=self.peer_fixture(ready_change=lambda v:v.update(containerId='f'*64))
        with self.assertRaises(REFUSED):policy._PolicyProcess(model.owner)
        self.assertEqual(model.ended,[model.child])

    def test_spawn_failure_is_consumed_without_releasing_input(self):
        model=self.peer_fixture(spawn_error=OSError('Generated launch refusal'))
        with self.assertRaises(OSError):policy._PolicyProcess(model.owner)
        self.assertIn('policy-start',model.owner._records);self.assertEqual(model.events,[])
        with self.assertRaises(REFUSED):policy._PolicyProcess(model.owner)

    def test_policy_identity_cannot_equal_creator_or_controller(self):
        for role in ('creator','controller'):
            model=self.peer_fixture()
            model.identity['pid']=model.owner._caller if role=='creator' else model.owner._transport._controller['pid']
            with self.subTest(role=role),self.assertRaises(REFUSED):policy._PolicyProcess(model.owner)
            self.assertEqual(model.events,[]);self.assertEqual(model.ended,[model.child])

    def test_policy_image_mismatch_refuses_before_input(self):
        model=self.peer_fixture(identity_change=lambda v:v.update(executableSha256='f'*64))
        with self.assertRaises(REFUSED):policy._PolicyProcess(model.owner)
        self.assertEqual(model.events,[]);self.assertEqual(model.ended,[model.child])

    def test_header_extra_fields_changed_pins_and_invalid_context_are_refused(self):
        model=self.start();header=json.loads(model.events[0][:-1])
        values=[dict(header,command='docker'),dict(header,pythonSha256='f'*64),dict(header,contextBase64=policy.context.encode(b'{}')),
            dict(header,sourcePins={}),dict(header,parent=header['policy'])]
        for value in values:
            with self.subTest(keys=list(value)),self.assertRaises(REFUSED):policy.policy_child_header(C(value))

    def test_header_requires_bounded_canonical_unique_json(self):
        model=self.start();raw=model.events[0][:-1]
        for value in (raw+b' ',raw[:-1]+b',"schema":"duplicate"}',b' '*policy.MAX_POLICY_HEADER,raw.decode()):
            with self.subTest(kind=type(value).__name__),self.assertRaises(REFUSED):policy.policy_child_header(value)

    def test_event_has_only_fixed_context_digest_and_one_action(self):
        digest='a'*64
        for event in ('controller-exited','cancel'):
            raw=C(policy.policy_event(digest,event));self.assertEqual(policy.admit_policy_event(raw,digest),event)
        for value in (dict(policy.policy_event(digest,'cancel'),command='foreign'),policy.policy_event('b'*64,'cancel'),
                dict(policy.policy_event(digest,'cancel'),event='guardian-exited')):
            with self.subTest(value=value),self.assertRaises(REFUSED):policy.admit_policy_event(C(value),digest)

    def test_clean_expiry_frame_is_checked_before_creator_admission(self):
        model=self.start();raw=self.complete(model)
        self.assertEqual(model.peer.request(),raw);self.assertFalse(model.owner._policy_binding._attempted)
        self.assertEqual(model.owner._policy_binding.admit(raw),('lease-expired','live'))
        model.peer.close();report=model.peer.report()
        self.assertTrue(report['ownedPolicyMembersAbsent']);self.assertFalse(report['peerFailedObserved']);self.assertEqual(report['exitCode'],0)

    def test_controller_exit_event_does_not_authorize_a_forged_exit(self):
        model=self.start();model.owner._test_state='exited'
        raw=model.peer.request();self.assertTrue(model.child.stdin.closed)
        self.assertEqual(policy.admit_policy_event(model.events[-1][4:],H(model.peer._context)),'controller-exited')
        model.owner._test_state='live'
        with self.assertRaises(REFUSED):model.owner._policy_binding.admit(raw)
        self.assertEqual(model.owner._generated_calls,[])

    def test_modeled_pipe_writer_cannot_read_live_creator_records(self):
        model=self.peer_fixture();creator_thread=policy.threading.get_ident();read=model.owner._policy_binding.context_bytes
        def creator_read():
            self.assertEqual(policy.threading.get_ident(),creator_thread)
            return read()
        model.owner._policy_binding.context_bytes=creator_read
        model.peer=policy._PolicyProcess(model.owner);self.addCleanup(model.peer.close)
        model.owner._test_state='exited';raw=model.peer.request()
        self.assertEqual(model.owner._policy_binding.admit(raw),('controller-exited','exited'))
        self.assertEqual(model.owner._generated_calls,[])

    def test_complete_output_is_drained_after_observed_exit(self):
        model=self.start();raw=self.request_bytes(model.owner,'controller-exited');model.child.returncode=0
        model.peer._pumps.finish_action=lambda:model.peer._pumps.stdout.extend(policy.context.frame(json.loads(raw),policy.MAX_POLICY))
        self.assertEqual(model.peer.request(),raw)

    def test_eof_partial_extra_stderr_and_nonzero_exit_refuse(self):
        for fault in ('eof','partial','extra','stderr','exit'):
            with self.subTest(fault=fault):
                model=self.start();self.complete(model,code=1 if fault=='exit' else 0,tail=b'extra' if fault=='extra' else b'')
                if fault=='eof':del model.peer._pumps.stdout[model.peer._total:]
                if fault=='partial':del model.peer._pumps.stdout[-1:]
                if fault=='stderr':model.peer._pumps.stderr.extend(b'generated diagnostic')
                with self.assertRaises(REFUSED):model.peer.request()
                self.assertFalse(model.owner._policy_binding._accepted);self.assertEqual(model.owner._generated_calls,[])

    def test_original_cleanup_deadline_is_not_restarted_for_policy(self):
        model=self.start();self.complete(model)
        model.owner._elapsed=lambda:policy.packet.require(False)
        with self.assertRaises(REFUSED):model.peer.request()
        self.assertEqual(model.owner._generated_calls,[])

    def test_blocked_input_still_checks_original_creator_deadline(self):
        model=self.start();started=policy.threading.Event();release=policy.threading.Event()
        def blocked(_):started.set();release.wait(3)
        check=model.peer._check;send=model.peer._pumps._send
        def expired():
            self.assertTrue(started.wait(1));raise ValueError('Generated original deadline refusal')
        model.peer._check=expired;model.peer._pumps._send=blocked
        try:
            with self.assertRaisesRegex(ValueError,'original deadline'):model.peer._send(b'fixed generated input')
        finally:
            release.set()
            for writer in model.peer._pumps.threads:writer.join(1)
            model.peer._check=check;model.peer._pumps._send=send
        self.assertFalse(any(writer.is_alive() for writer in model.peer._pumps.threads))
        self.assertEqual(model.owner._generated_calls,[])

    def test_substituted_transport_child_fence_and_policy_context_refuse(self):
        for attribute,value in (('_transport',object()),('_source_pin','f'*64),('_child',object()),('_fence',object()),('_context',b'{}')):
            with self.subTest(attribute=attribute):
                model=self.start();original=getattr(model.peer,attribute);setattr(model.peer,attribute,value)
                with self.assertRaises(REFUSED):model.peer._check()
                setattr(model.peer,attribute,original)

    def test_changed_creator_pid_refuses_policy_use(self):
        model=self.start()
        with patch.object(policy.os,'getpid',return_value=model.peer._caller+1),self.assertRaises(REFUSED):model.peer._check()

    def test_close_cancels_only_own_peer_and_is_idempotent(self):
        model=self.start();model.peer.close();model.peer.close()
        self.assertEqual(len(model.ended),1);self.assertEqual(len(model.events),2)
        self.assertEqual(policy.admit_policy_event(model.events[-1][4:],H(model.peer._context)),'cancel')
        self.assertTrue(model.owner._records['policy-closed'].report()['ownedPolicyMembersAbsent'])
        self.assertEqual(model.owner._generated_calls,[])

    def test_creator_failure_path_uses_owned_absence_not_a_wire_exit(self):
        model=self.start();model.child.returncode=1;model.peer.close(failed=True)
        self.assertEqual(model.owner._policy_binding.creator_fallback(model.peer),('policy-peer-failed','live'))
        self.assertFalse(model.owner._policy_binding._accepted);self.assertIsNone(model.owner._policy_binding._request_pin)
        with self.assertRaises(REFUSED):model.owner._policy_binding.creator_fallback(model.peer)

    def test_fallback_refuses_live_peer_and_unknown_create_outcome(self):
        for fault in ('live','unknown'):
            model=self.start()
            if fault=='unknown':model.peer.close(failed=True);model.owner._unknown=True
            with self.subTest(fault=fault),self.assertRaises(REFUSED):model.owner._policy_binding.creator_fallback(model.peer)
            self.assertEqual(model.owner._generated_calls,[])

    def test_fallback_refuses_copied_or_foreign_peer(self):
        model=self.start();model.peer.close(failed=True)
        for peer in (json.loads(C(model.peer.report())),object.__new__(policy._PolicyProcess),SimpleNamespace()):
            model.owner._policy_binding._fallback_attempted=False
            with self.subTest(kind=type(peer).__name__),self.assertRaises(REFUSED):model.owner._policy_binding.creator_fallback(peer)

    def test_refused_frame_consumes_admission_without_fabricating_acceptance(self):
        model=self.start();raw=self.complete(model);value=json.loads(raw);value['contextSha256']='f'*64
        with self.assertRaises(REFUSED):model.owner._policy_binding.admit(C(value))
        model.peer.close(failed=True)
        self.assertEqual(model.owner._policy_binding.creator_fallback(model.peer)[0],'policy-peer-failed')
        self.assertTrue(model.owner._policy_binding._attempted);self.assertFalse(model.owner._policy_binding._accepted)
        self.assertEqual(model.owner._generated_calls,[])

    def test_accepted_request_cannot_be_reclassified_as_failure_cleanup(self):
        model=self.start();model.owner._policy_binding.admit(self.complete(model));model.peer.close(failed=True)
        with self.assertRaises(REFUSED):model.owner._policy_binding.creator_fallback(model.peer)

    def test_existing_delete_record_cannot_be_retried_via_peer_failure(self):
        model=self.start();model.peer.close(failed=True);model.owner._record('delete',dict(schema='generated-consumed'))
        with self.assertRaises(REFUSED):model.owner._policy_binding.creator_fallback(model.peer)
        self.assertEqual(model.owner._generated_calls,[])

    def service(self,elapsed,event=None,parent_live=True):
        model=self.start();header=model.peer._header;value,raw=policy.policy_child_header(header);lease=policy.policy_context(raw)
        output=[];checks=[];clock=[elapsed]
        class Held:
            def __enter__(h):return h
            def __exit__(h,*_):pass
            def check(h):checks.append('source')
            def snapshot(h):return dict(state='live' if parent_live else 'exited')
        def receive(box):
            if event is None:return
            box['done']=True
            if event=='eof':box['error']=True
            else:box['raw']=C(policy.policy_event(H(raw),event))
        def thread(target,args,daemon):return SimpleNamespace(start=lambda:target(*args))
        with ExitStack() as held:
            for target,attribute,replacement in ((policy.sys,'stdin',SimpleNamespace(buffer=io.BytesIO(header+b'\n'))),
                    (policy.context.process.control,'DirectoryLease',lambda *_:Held()),
                    (policy.context.publication.prep,'_RootInputPin',lambda *_:Held()),
                    (policy.context.process,'PinnedFile',lambda *_:Held()),(policy.guard.identity,'HeldLocalPeer',lambda *_:Held()),
                    (policy,'_policy_event_input',receive),(policy.threading,'Thread',thread),
                    (policy.time,'time_ns',lambda:lease['leaseOpenedNs']+clock[0]),
                    (policy.time,'monotonic_ns',lambda:lease['cleanupMonotonicOriginNs']+clock[0]),
                    (policy.time,'sleep',lambda _:clock.__setitem__(0,policy.LEASE_NS))):
                held.enter_context(patch.object(target,attribute,replacement))
            policy.serve_policy(output.append)
        return model,output,checks

    def test_service_waits_for_original_lease_without_docker_or_clock_reset(self):
        model,output,checks=self.service(0)
        self.assertEqual(len(output),2);self.assertEqual(len(checks),len(policy.context.SOURCES))
        request=json.loads(output[1][4:]);self.assertEqual(request['reason'],'lease-expired')
        self.assertEqual(request['contextSha256'],H(model.peer._context));self.assertEqual(model.owner._generated_calls,[])

    def test_service_can_request_after_source_admission_without_extending_cleanup(self):
        _,output,_=self.service(policy.CLEANUP_NS-1)
        self.assertEqual(json.loads(output[1][4:])['reason'],'lease-expired')

    def test_service_controller_exit_is_only_a_request(self):
        model,output,_=self.service(0,'controller-exited')
        with self.assertRaises(REFUSED):model.owner._policy_binding.admit(bytes(output[1][4:]))
        self.assertEqual(model.owner._generated_calls,[])

    def test_service_cancel_closes_without_cleanup_request(self):
        _,output,checks=self.service(0,'cancel')
        self.assertEqual(len(output),1);self.assertEqual(checks,[])

    def test_service_eof_or_lost_parent_does_not_forge_ready_cleanup(self):
        for event,parent_live in (('eof',True),(None,False)):
            with self.subTest(event=event),self.assertRaises(REFUSED):self.service(0,event,parent_live)

    def test_service_original_cleanup_clock_expiry_and_rollback_refuse(self):
        for elapsed in (-1,policy.CLEANUP_NS):
            with self.subTest(elapsed=elapsed),self.assertRaises(REFUSED):self.service(elapsed)

    def creator_cleanup(self,invalid_request):
        model=self.start();owner=model.owner;owner._cleanup_started=False;owner._failed=False;owner._result=None
        owner._bases=copy.deepcopy(images.BASE_VALUES)
        owner._docker.base=lambda reference:next(v for v in owner._bases if v['reference']==reference)
        if invalid_request:
            raw=json.loads(self.complete(model));raw['contextSha256']='f'*64
            del model.peer._pumps.stdout[model.peer._total:]
            model.peer._pumps.stdout.extend(policy.context.frame(raw,policy.MAX_POLICY))
        else:model.child.returncode=1
        result=owner.cleanup()
        self.assertEqual(result['reason'],'policy-peer-failed');self.assertFalse(result['policyRequestValidated'])
        self.assertTrue(result['policyPeerFailedObserved']);self.assertTrue(result['policyProcessSeparated'])
        self.assertTrue(result['creatorAliveDuringCleanup']);self.assertFalse(result['guardianDeathCleanupVerified'])
        self.assertIsNone(owner._records['delete'].report()['policyRequestSha256'])
        calls=list(owner._generated_calls)
        self.assertEqual(sum(c[:2]==['container','rm'] for c in calls),1)
        with self.assertRaises(REFUSED):owner.cleanup()
        self.assertEqual(owner._generated_calls,calls)
        return owner

    def test_modeled_peer_exit_keeps_one_creator_dispatch_without_wire_admission(self):
        owner=self.creator_cleanup(False)
        self.assertFalse(owner._policy_binding._attempted);self.assertTrue(owner._policy_binding._fallback_attempted)

    def test_modeled_bad_request_consumes_admission_but_known_resources_are_not_orphaned(self):
        owner=self.creator_cleanup(True)
        self.assertTrue(owner._policy_binding._attempted);self.assertTrue(owner._resources['runtime']._closed)


if __name__=='__main__':
    result=unittest.TextTestRunner().run(unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(case) for case in (RetainedCleanupContracts,RetainedRemovalContracts,RetainedCleanupLifecycleContracts,RetainedPolicyRequestContracts,RetainedPolicyChildContracts)))
    if not result.wasSuccessful() or result.skipped:raise SystemExit(1)
    print('RETAINED OWNED CLEANUP CONTRACT PASS: '+json.dumps(dict(tests=result.testsRun,skipped=0,generatedOnly=True,
        actualDockerOperationsPerformed=0,actualNativePublicationUsed=False,sourceFiles=len(policy.context.SOURCES),
        ownCreatorOriginProvenByTheseGeneratedTests=False,fullSystemRecoveryVerified=False,phase7Complete=False),sort_keys=True))
