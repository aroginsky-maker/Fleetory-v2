"""Generated handoff/own-receipt/consumption contracts; no actual compiler or Docker proof."""
from contextlib import ExitStack
import copy
import json
import os
from pathlib import Path
import sys
import tarfile
import time
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
        self.held=ExitStack();self.addCleanup(self.held.close)
        self.fixture=vectors.RetainedRuntimeContracts();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
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

    def test_complete_creator_reply_is_required_without_trimming_or_id_adoption(self):
        client=object.__new__(policy._Docker)
        invalid=(b'',b'b'*63+b'\n',b'b'*64,b' '+b'b'*64+b'\n',b'B'*64+b'\n',b'b'*64+b'\nextra\n')
        for raw in invalid:
            with patch.object(client,'_execute',return_value=raw,create=True),self.assertRaises(REFUSED):client._created('runtime',[],'a'*64)
        with patch.object(client,'_execute',return_value=b'b'*64+b'\n',create=True):reply=client._created('runtime',[],'a'*64)
        self.assertIs(reply.token,policy._TOKEN);self.assertEqual(reply.identifier,'b'*64)

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

    def test_ledger_names_have_only_fixed_kinds_and_canonical_uuid(self):
        for kind in policy.KINDS:self.assertEqual(policy.ledger_name(kind,self.plan['nonce']),'retained-owned-'+kind+'-'+self.plan['nonce']+'.json')
        for kind,nonce in (('../x',self.plan['nonce']),('start','../x')):
            with self.assertRaises(REFUSED):policy.ledger_name(kind,nonce)

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

    def test_binary_docker_input_output_and_deadline_bounds_precede_dispatch(self):
        client=object.__new__(policy.guard.native._Docker)
        invalid=(((),b'',8,1),([],bytearray(),8,1),([],b'',True,1),([],b'',26,1),([],b'',8,0),([],b'',8,16*1024*1024+1))
        with patch.object(policy.guard.native.subprocess,'Popen') as spawn:
            for args,data,seconds,limit in invalid:
                with self.assertRaises(REFUSED):client._execute(args,data,seconds,limit)
            spawn.assert_not_called()

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


    def test_original_context_profile_keeps_its_fixed_55_second_clock(self):
        item=object.__new__(policy.context.RetainedContextTransport);item._wall=100;item._mono=200
        with patch.object(policy.time,'time_ns',return_value=100+55_000_000_000-1),patch.object(policy.time,'monotonic_ns',return_value=200+55_000_000_000-1):item._clock_check()
        for wall,mono in ((100+55_000_000_000,200+55_000_000_000-1),(100+55_000_000_000-1,200+55_000_000_000)):
            with patch.object(policy.time,'time_ns',return_value=wall),patch.object(policy.time,'monotonic_ns',return_value=mono),self.assertRaises(REFUSED+(policy.context.process.LaunchError,)):item._clock_check()

    def source_clock(self):
        item=object.__new__(policy._Transport);item._wall=0;item._mono=0;item._plan=self.plan
        item._offer=dict(retainedOpenedNs=20_000_000_000,retainedExpiresNs=80_000_000_000,
            imageIntentBase64=policy.context.encode(C(dict(openedNs=21_000_000_000,expiresNs=81_000_000_000))))
        with patch.object(policy.time,'time_ns',return_value=25_000_000_000),patch.object(policy.time,'monotonic_ns',return_value=30_000_000_000):item._start_source_clock()
        return item

    def test_extended_handoff_honors_original_source_end_and_monotonic_bound(self):
        item=self.source_clock()
        with patch.object(policy.time,'time_ns',return_value=70_000_000_000),patch.object(policy.time,'monotonic_ns',return_value=75_000_000_000):item._clock_check()
        for wall,mono in ((80_000_000_000,84_000_000_000),(79_000_000_000,85_000_000_000),(20_000_000_000,31_000_000_000),(30_000_000_000,29_000_000_000)):
            with patch.object(policy.time,'time_ns',return_value=wall),patch.object(policy.time,'monotonic_ns',return_value=mono),self.assertRaises(REFUSED):item._clock_check()
        self.assertEqual(item.clock_snapshot()['expiresNs'],80_000_000_000)

    def test_source_clock_cannot_be_renewed_or_extended_by_offer_mutation(self):
        item=self.source_clock();before=item.clock_snapshot();item._offer['retainedExpiresNs']+=60_000_000_000
        with self.assertRaises(REFUSED):item._start_source_clock()
        self.assertEqual(item.clock_snapshot(),before)

    def test_source_clock_is_bound_to_its_persisted_admission_record(self):
        item=self.source_clock();item._source_clock_record=self.held.enter_context(policy.guard.attempts._claim_record(self.operator,
            policy.ledger_name('admission',self.plan['nonce']),item.clock_snapshot()))
        item._check_source_clock();opened,end,mono,origin=item._source_clock;item._source_clock=(opened,end+1,mono+1,origin)
        with self.assertRaises(REFUSED):item._check_source_clock()

    def test_handoff_clock_before_source_opening_is_refused(self):
        item=self.source_clock();del item._source_clock
        with patch.object(policy.time,'time_ns',return_value=20_000_000_000),patch.object(policy.time,'monotonic_ns',return_value=30_000_000_000),self.assertRaises(REFUSED):item._start_source_clock()


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


if __name__=='__main__':
    result=unittest.TextTestRunner().run(unittest.defaultTestLoader.loadTestsFromTestCase(RetainedCleanupContracts))
    if not result.wasSuccessful() or result.skipped:raise SystemExit(1)
    print('RETAINED OWNED CLEANUP CONTRACT PASS: '+json.dumps(dict(tests=result.testsRun,skipped=0,generatedOnly=True,
        actualDockerOperationsPerformed=0,actualNativePublicationUsed=False,sourceFiles=len(policy.context.SOURCES),
        ownCreatorOriginProvenByTheseGeneratedTests=False,fullSystemRecoveryVerified=False,phase7Complete=False),sort_keys=True))
