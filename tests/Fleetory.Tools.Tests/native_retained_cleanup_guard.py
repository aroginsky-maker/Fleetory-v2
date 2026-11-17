"""Actual own build/readback/create, expiry/death cleanup and refused counterexamples; public only."""
import copy
import json
from pathlib import Path
import shutil
import sys
import threading
import time
import uuid
from unittest.mock import patch

import audit_probe_image_tests  # Installs the fixed eng/pilot import path.
import audit_retained_cleanup_guard as policy
from historical_audit_restore_tests import fixture

C,H,packet=policy.C,policy.H,policy.packet
CASES=('lease-expired','controller-exited','source-admission-expired','controller-exited-before-handoff','foreign-observation',
    'lost-create-reply','partial-create-reply','cli-inspection-failure','own-runtime-paused',
    'remove-cli-fails-before-execution','remove-reply-lost-after-own-execution')
POLICY_FAULT_CASES=('policy-child-exited','policy-input-eof')
CASES+=POLICY_FAULT_CASES
REFUSED=(OSError,ValueError,policy.context.process.LaunchError)


def _absent(client,identifier):
    return client._call(['container','ls','-a','--no-trunc','--filter','id='+policy.guard._identifier(identifier),'--format','{{.ID}}'])==b''


class CapturedFixtureWorker:
    """Test-only live creator: the complete reply is captured at its own inner RPC, never adopted by the guardian."""
    def __init__(self,client,intent,raw,opened,finished):
        identifier=policy.guard._identifier(raw.decode('ascii').strip())
        packet.require(raw==identifier.encode('ascii')+b'\n')
        self.client,self.intent,self.identifier=client,copy.deepcopy(intent),identifier
        self.observation=client.inspect('runtime',identifier)
        policy.owned_observation('runtime',self.observation,self.intent,identifier,opened,finished)
        self.closed=False

    def dispose(self):
        if self.closed:return
        raw=self.client.inspect('runtime',self.identifier)
        packet.require(C(packet.strict_json(raw,policy.container.MAX_OBSERVATION))==C(packet.strict_json(self.observation,policy.container.MAX_OBSERVATION)))
        packet.require(self.client._call(['container','rm','--force',self.identifier])==self.identifier.encode('ascii')+b'\n')
        packet.require(_absent(self.client,self.identifier));self.closed=True


def fixture_removal_reply(raw,identifier):
    """Pure comparison only; a reply string does not recreate a live fixture removal."""
    policy.guard._identifier(identifier)
    packet.require(type(raw) is bytes and raw==identifier.encode('ascii')+b'\n')


class CapturedFixtureRemoval:
    """Test-only live creator/remover fact. It never closes or repairs the guardian's unknown outcome."""
    def __init__(self,resource):
        packet.require(type(resource) is policy._Resource and type(resource.owner) is policy.RetainedCleanupGuard)
        owner=resource.owner
        packet.require(owner._prepared and not owner._cleanup_started and owner._resources.get('runtime') is resource)
        resource.fresh()
        self.resource,self.owner,self.client=resource,owner,owner._docker
        self.reply,self.record,self.snapshot=resource.reply,resource._record,resource._snapshot
        self.clock=(owner._mono,owner._wall,owner._expiry)
        self.execute=self.client._execute
        self.attempted,self.captured=False,False
        self.raw=None
        self._check()

    def _check(self):
        owner,resource=self.owner,self.resource
        packet.require(resource.owner is owner and owner._resources.get('runtime') is resource and owner._docker is self.client and
            resource.reply is self.reply and resource._record is self.record and resource._snapshot==self.snapshot and
            self.reply.client is self.client and self.reply.kind=='runtime' and self.clock==(owner._mono,owner._wall,owner._expiry) and
            not resource._closed and owner._result is None and 'runtime-closed' not in owner._records and 'result' not in owner._records)
        owner._check_owned();resource.check();owner._elapsed()

    def remove_and_withhold(self,args,data,seconds,limit):
        self._check()
        packet.require(self.owner._cleanup_started and 'delete' in self.owner._records and not self.attempted and
            args==['container','rm','--force',self.reply.identifier] and data==b'' and
            type(seconds) is int and seconds==8 and type(limit) is int and limit==policy.guard.process.MAX_STDOUT)
        self.attempted=True
        raw=self.execute(args,data,seconds,limit)
        fixture_removal_reply(raw,self.reply.identifier)
        packet.require(_absent(self.client,self.reply.identifier))
        self._check();self.raw=bytes(raw);self.captured=True
        return b''

    def verify(self,resource):
        self._check()
        packet.require(resource is self.resource and self.attempted and self.captured)
        fixture_removal_reply(self.raw,self.reply.identifier)
        packet.require(_absent(self.client,self.reply.identifier))


def _records(owner):
    saved={}
    for kind,item in owner._records.items():
        value=item.report();value.pop('localConsumedRecordFlushed')
        saved[kind]=dict(value=value,sha256=H(item._bytes))
        packet.require(item._bytes==C(value)+b'\n')
    return saved


def _fixture_dispose(owner,captured,removals=()):
    packet.require(type(removals) in (tuple,list) and len(removals)<=1)
    absent=set()
    for removal in removals:
        packet.require(type(removal) is CapturedFixtureRemoval and removal.owner is owner)
        removal.verify(removal.resource);absent.add(removal.resource)
    for worker in captured:worker.dispose()
    for kind in ('runtime','copy','image'):
        resource=owner._resources.get(kind)
        if resource is not None and not resource._closed and resource not in absent:resource.dispose()
    packet.require(all(v._closed or v in absent for v in owner._resources.values()) and all(v.closed for v in captured))


def _dispose_after_lost_removal(owner,captured,removals):
    packet.require(len(removals)==1 and type(removals[0]) is CapturedFixtureRemoval and removals[0].owner is owner)
    if not removals[0].attempted:
        _fixture_dispose(owner,captured);return False
    client=owner._docker;execute=client._execute;identifier=removals[0].reply.identifier;repeated=[]
    def tracked(args,data,seconds,limit):
        if args[:2]==['container','rm'] and args[-1]==identifier:
            repeated.append(list(args));raise ValueError('Fixture tried a second runtime removal.')
        return execute(args,data,seconds,limit)
    with patch.object(client,'_execute',side_effect=tracked):
        _fixture_dispose(owner,captured,removals)
        removals[0].verify(owner._resources['runtime'])
    packet.require(repeated==[])
    return True


def _refused_cleanup(owner):
    try:owner.cleanup()
    except REFUSED:pass
    else:raise ValueError('Expected guardian refusal was not observed.')
    packet.require(owner._result is None and 'result' not in owner._records and owner._cleanup_started)


def _snapshot(root,items):
    packet.require(type(items) is list and all(type(item) is policy.guard.attempts.ConsumedAttempt for item in items))
    result={}
    for item in items:
        item.check();packet.require(item._name not in result);result[item._name]=H(item._bytes)
    packet.require(set(result)=={p.name for p in root.iterdir()})
    return result


def _replay(owner,prepared,raw,reference,paths,pins,sources,closed_snapshot=None):
    held=[*owner._records.values(),owner._transport._start,owner._transport._ready]
    def current():
        if not owner._closed:return _snapshot(owner._root,held)
        packet.require(closed_snapshot is not None and set(closed_snapshot)=={p.name for p in owner._root.iterdir()})
        value={name:H((owner._root/name).read_bytes()) for name in closed_snapshot}
        packet.require(value==closed_snapshot)
        return value
    records=current()
    with patch.object(owner._docker,'_execute') as execute:
        try:owner.cleanup()
        except REFUSED:pass
        else:raise ValueError('Consumed guardian cleanup restarted.')
        execute.assert_not_called()
    with patch.object(policy,'_Docker') as docker,patch.object(policy,'_Transport') as controller:
        try:policy.RetainedCleanupGuard(prepared.repository,owner._root,raw,reference,
            runtime_paths=paths,runtime_pins=pins,source_pins=sources)
        except OSError:pass
        else:raise ValueError('Consumed guardian started again.')
        docker.assert_not_called();controller.assert_not_called()
    packet.require(records==current())


def _lost_reply(owner,case,captured):
    execute=owner._docker._execute
    def intercepted(args,data,seconds,limit):
        opened=time.time_ns();raw=execute(args,data,seconds,limit);finished=time.time_ns()
        if args and args[0]=='run':
            captured.append(CapturedFixtureWorker(owner._docker,owner._intent,raw,opened,finished))
            return b'' if case=='lost-create-reply' else raw[:-9]
        return raw
    with patch.object(owner._docker,'_execute',side_effect=intercepted):
        try:owner.prepare()
        except REFUSED:pass
        else:raise ValueError('Lost/partial create reply was admitted.')
    packet.require(len(captured)==1 and owner._unknown and 'runtime' not in owner._resources and not owner._prepared)
    packet.require(not _absent(owner._docker,captured[0].identifier))
    # A separate test creator disposes its own complete inner reply. The guardian never receives that ID.
    captured[0].dispose();_refused_cleanup(owner)
    packet.require(not any(r.reply.identifier==captured[0].identifier for r in owner._resources.values()))
    return dict(guardPrepareRefused=True,unknownCreateOutcomeRetained=True,lostIdNotAdoptedByGuardian=True,
        fixtureCreatorDisposedItsCapturedWorker=True,capturedWorkerId=captured[0].identifier,guardianCleanupAccepted=False)


def _sentinel(owner,captured):
    intent=copy.deepcopy(owner._intent);nonce=str(uuid.uuid4())
    intent.update(nonce=nonce,name=policy.runtime.name(nonce),labels=dict(intent['labels'],**{'fleetory.audit.control.nonce':nonce}))
    opened=time.time_ns();raw=owner._docker._execute(policy.guard.native._arguments(intent),b'',8,16384);finished=time.time_ns()
    foreign=CapturedFixtureWorker(owner._docker,intent,raw,opened,finished);captured.append(foreign)
    return foreign


def _foreign(owner,captured):
    foreign=_sentinel(owner,captured)
    original=owner._docker.inspect;execute=owner._docker._execute;deletions=[]
    def inspection(kind,identifier):
        if kind=='runtime':return foreign.observation
        return original(kind,identifier)
    def tracked(args,data,seconds,limit):
        if args[:2] in (['container','rm'],['image','rm']):deletions.append(args)
        return execute(args,data,seconds,limit)
    with patch.object(owner._docker,'inspect',side_effect=inspection),patch.object(owner._docker,'_execute',side_effect=tracked):
        _refused_cleanup(owner)
    packet.require(deletions==[] and original('runtime',foreign.identifier)==foreign.observation)
    packet.require(not _absent(owner._docker,owner._resources['runtime'].reply.identifier))
    return dict(guardCleanupRefused=True,foreignContainerId=foreign.identifier,foreignContainerUntouched=True,
        ownContainerUntouchedBeforeFixtureDisposal=True,guardianDeleteCalls=0,guardianCleanupAccepted=False)


def paused_fixture_observation(raw,original):
    """Pure test comparison, not a capability or authorization to normalize a guard observation."""
    expected=packet.strict_json(original,policy.container.MAX_OBSERVATION)
    packet.require(expected['paused'] is False and expected['running'] is True)
    expected['paused']=True
    packet.require(C(packet.strict_json(raw,policy.container.MAX_OBSERVATION))==C(expected))


def _paused(owner,captured):
    sentinel=_sentinel(owner,captured);resource=owner._resources['runtime'];resource.fresh()
    client=owner._docker;identifier=resource.reply.identifier;original=resource.observation
    packet.require(client._call(['container','pause',identifier])==identifier.encode('ascii')+b'\n')
    try:
        observed=client.inspect('runtime',identifier);paused_fixture_observation(observed,original)
        execute=client._execute;deletions=[]
        def tracked(args,data,seconds,limit):
            if args[:2] in (['container','rm'],['image','rm']):deletions.append(args)
            return execute(args,data,seconds,limit)
        with patch.object(client,'_execute',side_effect=tracked):_refused_cleanup(owner)
        packet.require(deletions==[] and 'runtime-closed' not in owner._records)
        paused_fixture_observation(client.inspect('runtime',identifier),original)
        packet.require(client.inspect('runtime',sentinel.identifier)==sentinel.observation)
        result=dict(guardCleanupRefused=True,actualOwnRuntimePaused=True,pausedObservationSha256=H(observed),
            pausedOwnContainerId=identifier,foreignContainerId=sentinel.identifier,foreignContainerUntouched=True,
            ownContainerUntouchedBeforeFixtureDisposal=True,guardianDeleteCalls=0,guardianCleanupAccepted=False)
    finally:
        # Only the separate live test creator restores its exact own paused object for disposal.
        paused_fixture_observation(client.inspect('runtime',identifier),original)
        packet.require(client._call(['container','unpause',identifier])==identifier.encode('ascii')+b'\n')
        resource.fresh()
    result['fixtureOnlyUnpauseBeforeFreshDisposalVerified']=True
    return result


def _cli_failure(owner):
    execute=owner._docker._execute;deletions=[]
    def failed(args,data,seconds,limit):
        if args[:2] in (['container','rm'],['image','rm']):deletions.append(args)
        if args[:2]==['container','inspect'] and args[-1]==owner._resources['runtime'].reply.identifier:
            raise OSError('Generated one-shot inspection failure')
        return execute(args,data,seconds,limit)
    with patch.object(owner._docker,'_execute',side_effect=failed):_refused_cleanup(owner)
    packet.require(deletions==[] and not _absent(owner._docker,owner._resources['runtime'].reply.identifier))
    return dict(guardCleanupRefused=True,inspectionFailureInjected=True,guardianDeleteCalls=0,
        ownContainerUntouchedBeforeFixtureDisposal=True,guardianCleanupAccepted=False)


def _removal_failure(owner,case,removals):
    client=owner._docker;resource=owner._resources['runtime'];identifier=resource.reply.identifier
    witness=CapturedFixtureRemoval(resource) if case=='remove-reply-lost-after-own-execution' else None
    if witness is not None:removals.append(witness)
    execute=client._execute;deletions=[]
    def intercepted(args,data,seconds,limit):
        if args[:2] in (['container','rm'],['image','rm']):
            deletions.append(list(args))
            packet.require(args==['container','rm','--force',identifier] and len(deletions)==1)
            if witness is None:raise OSError('Generated own removal failure before Docker execution')
            return witness.remove_and_withhold(args,data,seconds,limit)
        return execute(args,data,seconds,limit)
    with patch.object(client,'_execute',side_effect=intercepted):_refused_cleanup(owner)
    packet.require(len(deletions)==1 and not resource._closed and 'runtime-closed' not in owner._records)
    absent=_absent(client,identifier)
    packet.require(absent is (witness is not None))
    if witness is not None:witness.verify(resource)
    else:resource.fresh()
    return dict(guardCleanupRefused=True,guardianCleanupAccepted=False,guardianDeleteCalls=1,
        actualDockerRemovalCalls=0 if witness is None else 1,removeFailureBeforeExecution=witness is None,
        completeRemovalReplyWithheld=witness is not None,completeInnerRemovalReplySha256=None if witness is None else H(witness.raw),
        unknownRemovalOutcomeRetained=True,guardianRuntimeClosedReceiptAbsent=True,ownContainerId=identifier,
        ownContainerAbsentBeforeFixtureDisposal=absent,fixtureOnlyLiveRemovalFactUsed=witness is not None)


def _handoff_death(owner):
    record,close=owner._record,owner.close;captured={};killed=False
    def create_record(kind,value):
        nonlocal killed
        item=record(kind,value)
        if kind=='runtime':owner._transport._fence.terminate();killed=True
        return item
    def observed_close():
        if not owner._closed:
            captured['records']=_records(owner)
            captured['snapshot']=_snapshot(owner._root,[*owner._records.values(),owner._transport._start,owner._transport._ready])
        close()
    owner.close=observed_close
    with patch.object(owner,'_record',side_effect=create_record):
        try:owner.run()
        except REFUSED:pass
        else:raise ValueError('Interrupted handoff was admitted.')
    packet.require(killed and owner._closed and owner._result is not None)
    result=packet.strict_json(owner._result,8192)
    packet.require(result['reason']=='controller-exited-before-handoff' and result['controllerDeathCleanupVerified'] and
        result['ownSuccessfulCreateReplyHeld'] and result['typedImageReadbackPreparationVerified'] and
        not result['typedRetainedHandoffVerified'] and result['ownCreatedResourcesAbsent'])
    packet.require(result['policyRequestValidated'] is False and result['policyProcessSeparated'] is False)
    return dict(guardianCleanupAccepted=True,result=result,actualControllerKilledAfterOwnReplyBeforeBinding=True,
        failedHandoffNotAdmitted=True,automaticOwnRollbackBeforeContextClosureVerified=True),captured


def _positive(owner,case):
    timer=None;killed=threading.Event();errors=[]
    if case=='controller-exited':
        def terminate():
            try:
                packet.require(owner._waiting.wait(3));owner._transport._fence.terminate();killed.set()
            except BaseException:errors.append(True)
        timer=threading.Thread(target=terminate);timer.start()
    if case=='source-admission-expired':
        deadline=time.monotonic()+75
        while time.time_ns()<=owner._intent['expiresNs']:
            packet.require(time.monotonic()<deadline);time.sleep(0.1)
        while owner._state()!='exited':
            packet.require(time.monotonic()<deadline);time.sleep(0.05)
        try:owner._transport.context_bytes()
        except REFUSED:pass
        else:raise ValueError('Expired child capability remained usable.')
    try:result=owner.cleanup()
    finally:
        if timer is not None:timer.join(3)
    expected='controller-exited' if case=='controller-exited' else 'lease-expired'
    packet.require(result['reason']==expected and result['actualCleanupExecuted'] and result['ownCreatedResourcesAbsent'] and
        result['typedRetainedHandoffVerified'] and result['cleanupIndependentOfLiveChildCapability'])
    packet.require(result['sourceAdmissionExpiredBeforeCleanup'] is (case=='source-admission-expired'))
    packet.require(result['policyRequestValidated'] is True and result['policyProcessSeparated'] is True and result['policyPeerFailedObserved'] is False)
    peer=result['policyProcess']
    packet.require(peer['policyReadyVerified'] and peer['ownedPolicyMembersAbsent'] and peer['exitCode']==0 and not peer['peerFailedObserved'])
    packet.require(peer['policy']['pid'] not in (owner._caller,owner._transport._controller['pid']))
    packet.hex_value(owner._records['delete'].report()['policyRequestSha256'])
    if timer is not None:packet.require(killed.is_set() and not errors and not timer.is_alive())
    return dict(guardianCleanupAccepted=True,result=result,actualControllerKilledWhileGuardianWaiting=case=='controller-exited',
        actualOriginalAdmissionExpiredBeforeCleanup=case=='source-admission-expired')




def _policy_fault(owner,case):
    """Actual fixed owned peer fault; the surviving creator keeps all Docker authority."""
    packet.require(case in POLICY_FAULT_CASES and type(owner) is policy.RetainedCleanupGuard and
        owner._prepared and not owner._cleanup_started and not owner._unknown)
    owner._check_owned();peer=owner._policy_process
    packet.require(type(peer) is policy._PolicyProcess and peer._owner is owner and peer._ready and
        not peer._closed and not peer._failed and not peer._exited())
    packet.require(owner._state()=='live' and owner._wall+owner._elapsed()<owner._expiry)
    identity=policy.guard._process_identity(peer._fence.identity(peer._child,peer._python))
    packet.require(identity==peer._identity and identity['pid'] not in (owner._caller,owner._transport._controller['pid']))
    resource=owner._resources['runtime'];resource.fresh()
    client,reply,bound=owner._docker,resource.reply,owner._records['bound']
    clock=(owner._mono,owner._wall,owner._expiry);context=owner._policy_binding.context_bytes()
    packet.require(reply.client is client and owner._policy_binding._resource is resource and not owner._policy_binding._attempted)
    packet.require(len(peer._pumps.stdout)==peer._total and not peer._pumps.stderr and not peer._pumps.errors)
    injected=time.time_ns();packet.require(injected<owner._expiry)
    if case=='policy-child-exited':
        # Signal only the already held owned OS fence, retaining its unreaped Linux leader.
        ended=peer._fence.terminate();packet.require(ended['noRunningMembersVerified'])
    else:
        # No cancel/event frame: the actual input pipe closes after the ready acknowledgement.
        peer._child.stdin.close();packet.require(peer._child.stdin.closed and not peer._notified)
    deadline=time.monotonic_ns()+3_000_000_000
    while not peer._exited():
        packet.require(time.monotonic_ns()<deadline);time.sleep(0.01)
    packet.require(owner._state()=='live' and clock==(owner._mono,owner._wall,owner._expiry))
    execute=client._execute;deletions=[]
    def observed(args,data,seconds,limit):
        if args[:2] in (['container','rm'],['image','rm']):
            packet.require(peer._closed and peer._failed and peer._end['noRunningMembersVerified'] and
                owner._docker is client and owner._resources['runtime'] is resource and resource.reply is reply and
                owner._records['bound'] is bound and clock==(owner._mono,owner._wall,owner._expiry) and
                owner._policy_binding.context_bytes()==context)
            deletions.append(list(args))
        return execute(args,data,seconds,limit)
    with patch.object(client,'_execute',side_effect=observed):result=owner.cleanup()
    packet.require(result['reason']=='policy-peer-failed' and result['actualCleanupExecuted'] and
        result['ownCreatedResourcesAbsent'] and result['typedRetainedHandoffVerified'] and
        result['policyProcessSeparated'] and result['policyPeerFailedObserved'] and not result['policyRequestValidated'])
    packet.require(not owner._policy_binding._accepted and not owner._policy_binding._attempted and
        owner._policy_binding._fallback_attempted and owner._records['delete'].report()['policyRequestSha256'] is None)
    report=result['policyProcess'];packet.require(report['policy']==identity and report['ownedPolicyMembersAbsent'] and
        report['peerFailedObserved'] and report['exitCode'] is not None and report['exitCode']!=0)
    packet.require(deletions==[['container','rm','--force',reply.identifier],['image','rm',owner._resources['image'].reply.identifier]])
    packet.require(clock==(owner._mono,owner._wall,owner._expiry) and not result['guardianDeathCleanupVerified'])
    return dict(guardianCleanupAccepted=True,result=result,actualPolicyChildDeathInjected=case=='policy-child-exited',
        actualPolicyInputEofInjected=case=='policy-input-eof',faultInjectedBeforeOriginalLeaseExpiry=True,
        faultInjectedAtNs=injected,originalLeaseExpiresNs=clock[2],originalClockTuple=list(clock),
        originalCreatorObjectsRetained=True,ownedPolicyAbsenceVerifiedBeforeDeletion=True,
        creatorOnlyFailureDispatchConsumed=True,noPositivePolicyAdmission=True,ownRemovalCalls=deletions)


def verify_closure(value,case,expired):
    packet.require(case in CASES and type(expired) is bool)
    packet.require(value['ownedControllerMembersAbsent'] and value['publicationDescriptorsHeld']==58)
    if not value['gracefulDescriptorClosureVerified']:
        packet.require(value['controllerDeathObserved'] and
            (case in ('controller-exited','source-admission-expired','controller-exited-before-handoff') or expired))


def exercise(prepared,cases=CASES):
    packet.require(type(cases) is tuple and cases and len(set(cases))==len(cases) and all(c in CASES for c in cases))
    paths={n:getattr(prepared,n) for n in ('python','powershell','git','dotnet')}
    paths['docker']=Path(shutil.which('docker') or '').resolve(strict=True)
    pins={n:H(Path(p).read_bytes()) for n,p in paths.items()}
    sources=policy.context.source_measurement(prepared.repository);manifest=C(prepared.published['bundle']);outcomes=[]
    with policy.context.bundle.HeldProbeBundle(prepared.root/'reference/publish',manifest,H(manifest)) as reference:
        descriptors={n:p.fd for n,p in reference.pins.items()};packet.require(len(descriptors)==58)
        for case in cases:
            plan,_=fixture();plan.update(nonce=str(uuid.uuid4()),revision=prepared.published['source']['revision'],
                codeSha256=prepared.published['source']['sha256'],probeSha256=reference.entries['ServerBackendProbe.dll']['sha256'],
                probeBundleSha256=reference.value['sha256'])
            root=prepared.root/('retained-owned-'+plan['nonce']);root.mkdir(mode=0o700)
            began=time.monotonic_ns()
            raw=C(plan);owner=policy.RetainedCleanupGuard(prepared.repository,root,raw,reference,
                runtime_paths=paths,runtime_pins=pins,source_pins=sources)
            print('NATIVE RETAINED OWNED STAGE: '+json.dumps(dict(case=case,stage='controller-offer',elapsedNs=time.monotonic_ns()-began)),flush=True)
            write_record=owner._record
            def tracked(kind,value):
                item=write_record(kind,value)
                print('NATIVE RETAINED OWNED STAGE: '+json.dumps(dict(case=case,stage=kind,elapsedNs=time.monotonic_ns()-began)),flush=True)
                return item
            owner._record=tracked
            captured=[];removals=[];result=None;ready=None;transport=None;closed_capture=None
            try:
                if case=='controller-exited-before-handoff':result,closed_capture=_handoff_death(owner)
                elif case in ('lost-create-reply','partial-create-reply'):result=_lost_reply(owner,case,captured)
                else:
                    ready=owner.prepare()
                    packet.require(ready['typedHandoffVerified'] and owner._transport._offer['publicationDescriptorsHeld']==58)
                    packet.require(descriptors=={n:p.fd for n,p in reference.pins.items()})
                    if case=='foreign-observation':result=_foreign(owner,captured)
                    elif case=='cli-inspection-failure':result=_cli_failure(owner)
                    elif case=='own-runtime-paused':result=_paused(owner,captured)
                    elif case in ('remove-cli-fails-before-execution','remove-reply-lost-after-own-execution'):result=_removal_failure(owner,case,removals)
                    elif case in POLICY_FAULT_CASES:result=_policy_fault(owner,case)
                    else:result=_positive(owner,case)
                _replay(owner,prepared,raw,reference,paths,pins,sources,None if closed_capture is None else closed_capture['snapshot'])
            finally:
                try:
                    if removals:
                        removed=_dispose_after_lost_removal(owner,captured,removals)
                        if result is not None:
                            packet.require(removed and not owner._resources['runtime']._closed)
                            result['noSecondRuntimeRemovalVerified']=True
                            result['guardianRuntimeStillUnclosedAfterFixtureDisposal']=True
                    else:_fixture_dispose(owner,captured)
                    if result is not None and not result['guardianCleanupAccepted']:_replay(owner,prepared,raw,reference,paths,pins,sources)
                finally:
                    peer=getattr(owner,'_policy_process',None)
                    if peer is not None:peer.close()
                    policy_report=peer.report() if peer is not None else None
                    records=_records(owner) if closed_capture is None else closed_capture['records']
                    expired_before_close=hasattr(owner,'_intent') and time.time_ns()>=owner._intent['expiresNs']
                    transport=owner._transport;owner.close()
            closed=transport.result();verify_closure(closed,case,bool(expired_before_close))
            packet.require(descriptors=={n:p.fd for n,p in reference.pins.items()});reference.check()
            outcomes.append(dict(case=case,**result,ready=ready,records=records,controllerClosure=closed,
                guardian=closed['parent'],controller=closed['controller'],allFixtureOwnedResourcesDisposed=True,
                creator=closed['parent'],policyProcess=policy_report,legacyGuardianFieldIsCreator=True,
                sourceAdmissionExpiredBeforeControllerClose=bool(expired_before_close),
                original58ParentReferenceDescriptorsUnchanged=True,startAndCleanupReplayRefused=True,
                fixtureDisposalDoesNotAuthorizeGuardReplay=True,originalInputsRead=False,originalPrivatePkiUsed=False,
                sourceVpsAccessed=False,fullSystemRecoveryVerified=False,phase7Complete=False))
            print('ACTUAL RETAINED OWNED CLEANUP CASE PASS: '+case,flush=True)
    return dict(schema='fleetory.actual-retained-owned-cleanup.v1',verified=True,sourceRevision=prepared.published['source']['revision'],
        sourcePins=sources,sourceFilesPinned=len(sources),cases=outcomes,actualRetainedControllers=len(cases),
        positiveGuardianCleanupCases=sum(c in CASES[:4]+POLICY_FAULT_CASES for c in cases),
        fullTypedHandoffCleanupCases=sum(c in CASES[:3]+POLICY_FAULT_CASES for c in cases),allFixtureOwnedResourcesDisposed=True,
        policyChildDeathCleanupVerified='policy-child-exited' in cases,policyInputLossCleanupVerified='policy-input-eof' in cases,
        same58ChildPublicationDescriptorsUsed=True,independent58ParentReferenceDescriptorsUnchanged=True,
        originalInputsRead=False,originalPrivatePkiUsed=False,sourceVpsAccessed=False,fullSystemRecoveryVerified=False,phase7Complete=False)


def run(cases=CASES):
    from native_publication_faults import reference_fixture
    with reference_fixture() as prepared:result=exercise(prepared,cases)
    result['ownPublicFixtureDisposed']=True
    return result


if __name__=='__main__':
    packet.require(len(sys.argv)==1 or len(sys.argv)==3 and sys.argv[1]=='--case' and sys.argv[2] in CASES)
    cases=CASES if len(sys.argv)==1 else (sys.argv[2],)
    print('ACTUAL RETAINED OWNED CLEANUP PASS: '+json.dumps(run(cases),sort_keys=True))
