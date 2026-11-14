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
    'lost-create-reply','partial-create-reply','cli-inspection-failure')
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


def _records(owner):
    saved={}
    for kind,item in owner._records.items():
        value=item.report();value.pop('localConsumedRecordFlushed')
        saved[kind]=dict(value=value,sha256=H(item._bytes))
        packet.require(item._bytes==C(value)+b'\n')
    return saved


def _fixture_dispose(owner,captured):
    for worker in captured:worker.dispose()
    for kind in ('runtime','copy','image'):
        resource=owner._resources.get(kind)
        if resource is not None and not resource._closed:resource.dispose()
    packet.require(all(v._closed for v in owner._resources.values()) and all(v.closed for v in captured))


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


def _foreign(owner,captured):
    intent=copy.deepcopy(owner._intent);nonce=str(uuid.uuid4())
    intent.update(nonce=nonce,name=policy.runtime.name(nonce),labels=dict(intent['labels'],**{'fleetory.audit.control.nonce':nonce}))
    opened=time.time_ns();raw=owner._docker._execute(policy.guard.native._arguments(intent),b'',8,16384);finished=time.time_ns()
    foreign=CapturedFixtureWorker(owner._docker,intent,raw,opened,finished);captured.append(foreign)
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
    if timer is not None:packet.require(killed.is_set() and not errors and not timer.is_alive())
    return dict(guardianCleanupAccepted=True,result=result,actualControllerKilledWhileGuardianWaiting=case=='controller-exited',
        actualOriginalAdmissionExpiredBeforeCleanup=case=='source-admission-expired')



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
            captured=[];result=None;ready=None;transport=None;closed_capture=None
            try:
                if case=='controller-exited-before-handoff':result,closed_capture=_handoff_death(owner)
                elif case in ('lost-create-reply','partial-create-reply'):result=_lost_reply(owner,case,captured)
                else:
                    ready=owner.prepare()
                    packet.require(ready['typedHandoffVerified'] and owner._transport._offer['publicationDescriptorsHeld']==58)
                    packet.require(descriptors=={n:p.fd for n,p in reference.pins.items()})
                    if case=='foreign-observation':result=_foreign(owner,captured)
                    elif case=='cli-inspection-failure':result=_cli_failure(owner)
                    else:result=_positive(owner,case)
                _replay(owner,prepared,raw,reference,paths,pins,sources,None if closed_capture is None else closed_capture['snapshot'])
            finally:
                try:
                    _fixture_dispose(owner,captured)
                    if result is not None and not result['guardianCleanupAccepted']:_replay(owner,prepared,raw,reference,paths,pins,sources)
                finally:
                    records=_records(owner) if closed_capture is None else closed_capture['records']
                    expired_before_close=hasattr(owner,'_intent') and time.time_ns()>=owner._intent['expiresNs']
                    transport=owner._transport;owner.close()
            closed=transport.result();verify_closure(closed,case,bool(expired_before_close))
            packet.require(descriptors=={n:p.fd for n,p in reference.pins.items()});reference.check()
            outcomes.append(dict(case=case,**result,ready=ready,records=records,controllerClosure=closed,
                guardian=closed['parent'],controller=closed['controller'],allFixtureOwnedResourcesDisposed=True,
                sourceAdmissionExpiredBeforeControllerClose=bool(expired_before_close),
                original58ParentReferenceDescriptorsUnchanged=True,startAndCleanupReplayRefused=True,
                fixtureDisposalDoesNotAuthorizeGuardReplay=True,originalInputsRead=False,originalPrivatePkiUsed=False,
                sourceVpsAccessed=False,fullSystemRecoveryVerified=False,phase7Complete=False))
            print('ACTUAL RETAINED OWNED CLEANUP CASE PASS: '+case,flush=True)
    return dict(schema='fleetory.actual-retained-owned-cleanup.v1',verified=True,sourceRevision=prepared.published['source']['revision'],
        sourcePins=sources,sourceFilesPinned=len(sources),cases=outcomes,actualRetainedControllers=len(cases),
        positiveGuardianCleanupCases=sum(c in CASES[:4] for c in cases),fullTypedHandoffCleanupCases=sum(c in CASES[:3] for c in cases),allFixtureOwnedResourcesDisposed=True,
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
