"""Independent own-created retained public probe cleanup. No adopted ID or original-service API."""
from contextlib import ExitStack
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import sys
import threading
import time

import audit_retained_guard_protocol as protocol

context,retained=protocol.context,protocol.retained
guard,packet,C,H=context.guard,context.packet,context.C,context.H
runtime,container=retained.runtime,retained.container
PURPOSE='retained-publication-independent-cleanup.v1'
LEASE_NS,CLEANUP_NS=5_000_000_000,75_000_000_000
_TOKEN=object()
KINDS=('start','admission','build','image','copy','copy-delete','copy-closed','runtime','runtime-closed','bound','delete','image-closed','result')
BASE_FORMAT='{"id":{{json .Id}},"layers":{{json .RootFS.Layers}},"labels":{{if .Config.Labels}}{{json .Config.Labels}}{{else}}{}{{end}}}'
IMAGE_FORMAT=('{"schema":"fleetory.audit-probe-image-observation.v1","id":{{json .Id}},'
    '"tags":{{if .RepoTags}}{{json .RepoTags}}{{else}}[]{{end}},"digests":{{if .RepoDigests}}{{json .RepoDigests}}{{else}}[]{{end}},'
    '"created":{{json .Created}},"labels":{{json .Config.Labels}},"rootfs":{{json .RootFS.Type}},"layers":{{json .RootFS.Layers}},'
    '"os":{{json .Os}},"architecture":{{json .Architecture}},"user":{{json .Config.User}}}')
STOP_SCHEMA='fleetory.retained-guardian-copy-observation.v1'


def _format(schema,fields):
    return '{"schema":"'+schema+'",'+','.join(json.dumps(k)+':{{json '+v+'}}' for k,v in fields.items())+'}'


STOP_FORMAT=_format(STOP_SCHEMA,dict(guard.native.FIELDS,status='.State.Status',pid='.State.Pid'))
WORKER_FORMAT=_format(retained.OBSERVATION_SCHEMA,guard.native.FIELDS)


def ledger_name(kind,nonce):
    packet.require(kind in KINDS)
    return 'retained-owned-'+kind+'-'+packet.identity(nonce)+'.json'


def _copy_name(nonce):return 'fleetory-probe-copy-'+packet.identity(nonce).replace('-','')


def _copy_arguments(intent):
    return ['create','--name',_copy_name(intent['nonce']),'--label','fleetory.audit.control.copy=public-probe-readback.v1',
        '--network=none','--read-only','--cap-drop=ALL','--security-opt=no-new-privileges:true','--memory=64m',
        '--cpus=0.25','--pids-limit=32','--restart=no','--ulimit=core=0:0','--entrypoint=/bin/true',intent['imageId']]


def copy_observation(raw,intent,identifier,opened,finished):
    value=packet.strict_json(raw,container.MAX_OBSERVATION)
    packet.keys(value,'schema '+' '.join(guard.native.FIELDS)+' status pid')
    packet.require(value['schema']==STOP_SCHEMA and value['id']==identifier and value['name']=='/'+_copy_name(intent['nonce']) and
        value['imageId']==value['configImage']==intent['imageId'] and
        value['labels']==dict(intent['labels'],**{'fleetory.audit.control.copy':'public-probe-readback.v1'}))
    created=container.timestamp_ns(value['created']);packet.require(opened<=created<=finished)
    container._container_common_sandbox(value)
    packet.require(value['running'] is False and value['autoRemove'] is False and value['status']=='created' and
        type(value['pid']) is int and value['pid']==0 and type(value['networks']) is dict and set(value['networks']) in (set(),{'none'}))
    packet.require(value['user']=='3322:3322' and value['entrypoint']==['/bin/true'] and value['command'] in (None,[]) and
        value['environment']==runtime.ENVIRONMENT and value['ulimits']==runtime.PROFILE['ulimits'])
    packet.require(all(type(value[k]) is int and value[k]==v for k,v in (('memory',67108864),('nanoCpus',250000000),('pidsLimit',32))))
    packet.require(value['tmpfs'] is None or value['tmpfs']=={})
    return value


def owned_observation(kind,raw,intent,identifier,opened,finished):
    """Pure fixed profile and own RPC creation window; no admission/cleanup authority from a record."""
    packet.require(type(opened) is int and type(finished) is int and opened<=finished)
    if kind=='image':value,created=context.probe.ProbeImageBinding._profile_observation(raw,intent,identifier)
    elif kind=='copy':
        value=copy_observation(raw,intent,identifier,opened,finished)
        created=container.timestamp_ns(value['created'])
    else:
        packet.require(kind=='runtime')
        value,created=container._container_observation(raw,intent,identifier,retained.OBSERVATION_SCHEMA,
            container.OBSERVATION_FIELDS+' environment ulimits')
        runtime._runtime_profile(value,intent)
    packet.require(opened<=created<=finished)
    return value


def copy_projection(value):
    return C(dict(id=value['id'],name=value['name'],image=value['imageId'],configImage=value['configImage'],labels=value['labels'],
        running=False,status='created',pid=0,network='none',mounts=[],readonly=True,privileged=False,user='3322:3322',entrypoint=['/bin/true']))


@dataclass(frozen=True)
class _Reply:
    token: object
    client: object
    kind: str
    raw: bytes
    identifier: str
    started: int
    finished: int
    input_pin: str


class _Docker(guard.native._Docker):
    def base(self,reference):
        packet.require(reference in context.probe.BASES)
        value=packet.strict_json(self._call(['image','inspect','--format',BASE_FORMAT,reference]),8192)
        packet.keys(value,'id layers labels')
        return dict(reference=reference,**value)

    def _created(self,kind,args,pin,data=b''):
        packet.require(kind in ('image','copy','runtime'))
        opened=time.time_ns()
        raw=self._execute(args,data,25 if kind=='image' else 8,16384)
        finished=time.time_ns();text=raw.decode('ascii').strip()
        (container.image_id if kind=='image' else guard._identifier)(text)
        packet.require(raw==text.encode('ascii')+b'\n' and opened<=finished)
        return _Reply(_TOKEN,self,kind,bytes(raw),text,opened,finished,pin)

    def build(self,data):
        packet.require(type(data) is bytes and 0<len(data)<=context.bundle.MAX_CONTEXT)
        return self._created('image',['build','--quiet','--network=none','--pull=false','--no-cache','--force-rm','--file','Dockerfile','-'],H(data),data)

    def copy_container(self,intent):return self._created('copy',_copy_arguments(intent),H(C(intent)))

    def worker(self,intent):return self._created('runtime',guard.native._arguments(intent),H(C(intent)))

    def inspect(self,kind,identifier):
        packet.require(kind in ('image','copy','runtime'))
        (container.image_id if kind=='image' else guard._identifier)(identifier)
        template=IMAGE_FORMAT if kind=='image' else STOP_FORMAT if kind=='copy' else WORKER_FORMAT
        return self._call(['image' if kind=='image' else 'container','inspect','--format',template,identifier])

    def readback(self,identifier):
        guard._identifier(identifier)
        return self._execute(['cp',identifier+':/tool/.','-'],b'',8,context.bundle.MAX_CONTEXT)


class _Transport(context.RetainedContextTransport):
    _guardian=True

    def _receive(self):
        super()._receive()
        self._start_source_clock()

    def _start_source_clock(self):
        packet.require(not hasattr(self,'_source_clock'))
        intent=packet.strict_json(packet.decode(self._offer['imageIntentBase64'],context.probe.image.MAX_INTENT),context.probe.image.MAX_INTENT)
        end=min(self._offer['retainedExpiresNs'],intent['expiresNs'])
        mono,wall=time.monotonic_ns(),time.time_ns()
        opened=max(self._offer['retainedOpenedNs'],intent['openedNs'])
        packet.require(opened<=wall<end and 0<end-wall<=context.publication.WINDOW_NS)
        self._source_clock=(opened,end,mono+end-wall,mono)
        self._source_clock_record=None

    def clock_snapshot(self):
        opened,end,mono_end,origin=self._source_clock
        return dict(schema='fleetory.retained-own-admission-clock.v1',nonce=self._plan['nonce'],
            openedNs=opened,expiresNs=end,monotonicDeadlineNs=mono_end,monotonicOriginNs=origin)

    def _check_source_clock(self):
        if self._source_clock_record is not None:
            value=self._source_clock_record.report();value.pop('localConsumedRecordFlushed')
            packet.require(C(value)==C(self.clock_snapshot()))

    def _clock_check(self):
        if not hasattr(self,'_source_clock'):
            super()._clock_check();return
        opened,end,mono_end,origin=self._source_clock
        packet.require(opened<=time.time_ns()<end and origin<=time.monotonic_ns()<mono_end)

    def _check_pins(self):
        super()._check_pins()
        if hasattr(self,'_source_clock'):self._check_source_clock()

    def message(self,value,payload=b''):
        self.context_bytes();packet.require(type(payload) is bytes and len(payload)<=context.bundle.MAX_CONTEXT)
        def send():
            try:self._pumps._send(context.frame(value,protocol.MAX_FRAME)+payload)
            except (OSError,ValueError):self._pumps.errors.append('retained-frame-input')
        writer=threading.Thread(target=send,daemon=True);self._pumps.threads.append(writer);writer.start()
        try:
            while writer.is_alive():self._progress();time.sleep(0.01)
            self._wait_bytes(self._total+4)
            size=context.frame_size(bytes(self._pumps.stdout[self._total:self._total+4]),protocol.MAX_FRAME)
            finish=self._total+4+size;self._wait_bytes(finish);packet.require(len(self._pumps.stdout)==finish)
            raw=bytes(self._pumps.stdout[self._total+4:finish]);self._total=finish
            return raw
        except BaseException:
            self._fence.terminate();writer.join(3);raise

    def _graceful(self):
        self.context_bytes()
        self._pumps._send(context.frame(context.close_request(self._plan['nonce'],self._offer['contextSha256']),context.MAX_CLOSE))
        self._child.stdin.close()
        while not self._exited():
            self._clock_check();packet.require(not self._pumps.errors);time.sleep(0.01)
        return True


class _Resource:
    """Branded own complete RPC reply plus persisted bytes; never reconstructable from a wire record."""
    def __init__(self,owner,reply,intent,observation):
        packet.require(type(owner) is RetainedCleanupGuard and type(reply) is _Reply and reply.token is _TOKEN and reply.client is owner._docker)
        expected=intent['contextSha256'] if reply.kind=='image' else H(C(intent))
        packet.require(reply.input_pin==expected and intent['nonce']==owner._nonce)
        self.owner,self.reply=owner,reply
        self.intent,self.observation=C(intent),bytes(observation)
        self._canonical=C(owned_observation(reply.kind,self.observation,intent,reply.identifier,reply.started,reply.finished))
        self._closed=False
        metadata=dict(schema='fleetory.retained-own-resource.v1',purpose=PURPOSE,nonce=owner._nonce,kind=reply.kind,id=reply.identifier,
            imageId=reply.identifier if reply.kind=='image' else intent['imageId'],replySha256=H(reply.raw),startedNs=reply.started,
            finishedNs=reply.finished,intentSha256=H(self.intent),observationSha256=H(self.observation),
            contextSha256=owner._transport._offer['contextSha256'],controller=owner._transport._controller,
            supervisor=owner._transport._parent,sourcePinsSha256=owner._source_pin)
        self._snapshot=C(metadata);self._record=owner._record(reply.kind,metadata)
        self.check()

    def check(self):
        packet.require(not self._closed and self.reply.token is _TOKEN and self.reply.client is self.owner._docker)
        self._record.check();saved=self._record.report();saved.pop('localConsumedRecordFlushed')
        packet.require(C(saved)==self._snapshot and saved['intentSha256']==H(self.intent) and saved['observationSha256']==H(self.observation) and
            saved['replySha256']==H(self.reply.raw) and self._canonical==C(packet.strict_json(self.observation,container.MAX_OBSERVATION)))

    def facts(self):
        self.check()
        return dict(id=self.reply.identifier,observation=bytes(self.observation),startedNs=self.reply.started,finishedNs=self.reply.finished)

    def fresh(self):
        self.owner._check_owned();self.check()
        raw=self.owner._docker.inspect(self.reply.kind,self.reply.identifier)
        value=owned_observation(self.reply.kind,raw,packet.strict_json(self.intent,context.probe.image.MAX_INTENT),
            self.reply.identifier,self.reply.started,self.reply.finished)
        packet.require(C(value)==self._canonical)
        self.owner._check_owned();self.check()

    def dispose(self):
        self.fresh();client=self.owner._docker;identifier=self.reply.identifier
        if self.reply.kind=='image':
            reply=client._call(['image','rm','--no-prune',identifier])
            packet.require(identifier.encode('ascii') in reply)
            intent=packet.strict_json(self.intent,context.probe.image.MAX_INTENT)
            remaining=client._call(['image','ls','--all','--no-trunc','--filter',
                'label=fleetory.audit.control.reservation='+intent['controlSha256'],'--format','{{.ID}}']).decode('ascii').split()
            for value in remaining:container.image_id(value)
            packet.require(identifier not in remaining)
        else:
            reply=client._call(['container','rm','--force',identifier]);packet.require(reply==identifier.encode('ascii')+b'\n')
            packet.require(client._call(['container','ls','-a','--no-trunc','--filter','id='+identifier,'--format','{{.ID}}'])==b'')
        self.owner._check_owned();self.check()
        self.owner._record(self.reply.kind+'-closed',dict(schema='fleetory.retained-own-resource-closed.v1',nonce=self.owner._nonce,
            id=identifier,receiptSha256=H(self._snapshot),absenceVerified=True))
        self._closed=True


class RetainedCleanupGuard:
    """Independent parent executor for one fixed public probe; serialized receipts are metadata only."""
    def __init__(self,repository,operator_root,native_plan,reference,*,runtime_paths,runtime_pins,source_pins):
        self._held=ExitStack();self._transport=None;self._closed=False;self._resources={};self._records={}
        self._failed,self._unknown,self._prepared,self._cleanup_started=False,False,False,False
        self._result=None;self._caller=os.getpid();self._root=Path(operator_root);self._waiting=threading.Event()
        self._plan=context.restore.plan(bytes(native_plan),H(bytes(native_plan)));self._nonce=self._plan['nonce']
        try:
            self._record('start',dict(schema='fleetory.retained-own-guard-start.v1',nonce=self._nonce,status='START_CONSUMED',
                nativePlanSha256=H(bytes(native_plan)),assertedGuardianPid=self._caller,originalInputsRead=False))
            packet.keys(runtime_paths,'python powershell git dotnet docker');packet.keys(runtime_pins,'python powershell git dotnet docker')
            packet.require(type(source_pins) is dict)
            runtime_paths,runtime_pins,source_pins=dict(runtime_paths),dict(runtime_pins),dict(source_pins)
            docker=self._held.enter_context(context.process.PinnedFile(runtime_paths['docker'],runtime_pins['docker'],True))
            packet.require(type(reference) is context.bundle.HeldProbeBundle and len(reference.pins)==58)
            self._docker=_Docker(docker);self._bases=context.probe.bases([self._docker.base(n) for n in context.probe.BASES])
            self._transport=_Transport(repository,self._root,native_plan,reference,self._bases,
                runtime_paths=runtime_paths,runtime_pins=runtime_pins,source_pins=source_pins)
            self._reference=reference;self._source_pin=H(C(context._header(self._transport._header)[0]['sourcePins']));self._started=time.monotonic_ns()
            self._transport._source_clock_record=self._record('admission',self._transport.clock_snapshot())
            self._check_owned()
        except BaseException:self.close();raise

    def _record(self,kind,value):
        item=self._held.enter_context(guard.attempts._claim_record(self._root,ledger_name(kind,self._nonce),value))
        self._records[kind]=item
        return item

    def _check_owned(self):
        packet.require(not self._closed and os.getpid()==self._caller and self._transport is not None)
        transport=self._transport
        transport._check_source_clock()
        for source in transport._sources:source.check()
        for pinned in transport._runtimes.values():pinned.check()
        packet.require(guard.identity.current_identity(transport._runtimes['python'])==transport._parent)
        for item in self._records.values():item.check()
        self._check_ready()

    def _check_ready(self):
        if not self._prepared:return
        saved=self._records['bound'].report()
        resource=self._resources['runtime']
        packet.require(type(resource) is _Resource and resource.owner is self and C(self._intent)==resource.intent and
            saved['runtimeReceiptSha256']==H(resource._snapshot) and saved['leaseOpenedNs']==self._wall and
            saved['cleanupMonotonicOriginNs']==self._mono and saved['leaseExpiresNs']==self._expiry and
            self._expiry==min(self._wall+LEASE_NS,self._intent['expiresNs']))

    def _create(self,kind,intent,callback):
        try:
            reply=callback();raw=self._docker.inspect(kind,reply.identifier)
            owned_observation(kind,raw,intent,reply.identifier,reply.started,reply.finished)
            resource=_Resource(self,reply,intent,raw);self._resources[kind]=resource
            return resource
        except BaseException:self._unknown=True;raise

    def prepare(self):
        packet.require(not self._prepared and not self._failed and 'build' not in self._records)
        try:
            transport=self._transport;context_bytes=transport.context_bytes()
            self._image_intent=packet.strict_json(packet.decode(transport._offer['imageIntentBase64'],context.probe.image.MAX_INTENT),context.probe.image.MAX_INTENT)
            self._record('build',dict(schema='fleetory.retained-own-build-attempt.v1',nonce=self._nonce,status='BUILD_ATTEMPT_CONSUMED',contextSha256=H(context_bytes)))
            packet.require([self._docker.base(n) for n in context.probe.BASES]==self._bases)
            image=self._create('image',self._image_intent,lambda:self._docker.build(context_bytes));image_observed=time.time_ns()
            transport.context_bytes();copy_intent=dict(self._image_intent,imageId=image.reply.identifier)
            copied=self._create('copy',copy_intent,lambda:self._docker.copy_container(copy_intent))
            archive=self._docker.readback(copied.reply.identifier);context.bundle.verify_readback(archive,self._reference)
            image_facts=image.facts();copy_facts=copied.facts();copy_facts['projection']=copy_projection(packet.strict_json(copied.observation,container.MAX_OBSERVATION))
            facts=dict(imageId=image.reply.identifier,imageObservation=image.observation,imageObservedNs=image_observed,
                copyId=copied.reply.identifier,copyProjection=copy_facts['projection'],readback=archive)
            reply=transport.message(protocol.image_frame(transport._header,transport._offer,image_facts,copy_facts,archive),archive)
            self._intent=protocol.admit_runtime(reply,transport._header,transport._offer,facts,self._reference,time.time_ns())
            self._record('copy-delete',dict(schema='fleetory.retained-own-copy-delete.v1',nonce=self._nonce,id=copied.reply.identifier,status='ATTEMPT_CONSUMED'))
            copied.dispose();transport.context_bytes()
            worker=self._create('runtime',self._intent,lambda:self._docker.worker(self._intent))
            observed=time.time_ns()
            packet.require(worker.reply.finished<=observed and observed-worker.reply.started<10_000_000_000)
            reply=transport.message(protocol.runtime_frame(transport._header,transport._offer,self._intent,worker.facts()))
            bound=protocol.admit_bound(reply,transport._header,transport._offer,self._intent,worker.facts(),time.time_ns())
            self._mono,self._wall=time.monotonic_ns(),time.time_ns()
            packet.require(worker.reply.finished<=self._wall<self._intent['expiresNs'])
            self._expiry=min(self._wall+LEASE_NS,self._intent['expiresNs'])
            self._record('bound',dict(schema='fleetory.retained-own-runtime-ready.v1',nonce=self._nonce,containerId=worker.reply.identifier,
                runtimeReceiptSha256=H(worker._snapshot),backendBindingSha256=bound,leaseOpenedNs=self._wall,
                cleanupMonotonicOriginNs=self._mono,leaseExpiresNs=self._expiry,
                controller=transport._controller,supervisor=transport._parent,typedHandoffVerified=True))
            self._prepared=True
            return self.receipt()
        except BaseException:self._failed=True;raise

    def receipt(self):
        self._check_owned();packet.require(self._prepared)
        value=self._records['bound'].report();value.pop('localConsumedRecordFlushed')
        return value

    def _state(self):
        transport=self._transport
        if transport._exited():return 'exited'
        try:value=guard._process_identity(transport._fence.identity(transport._child,transport._runtimes['python']))
        except (OSError,ValueError):
            # Windows image queries may fail just before the owned process handle signals exit.
            end=time.monotonic_ns()+3_000_000_000
            while not transport._exited():
                if time.monotonic_ns()>=end:raise
                time.sleep(0.01)
            return 'exited'
        packet.require(value==transport._controller)
        return 'live'

    def _elapsed(self):
        mono,wall=time.monotonic_ns()-self._mono,time.time_ns()-self._wall
        packet.require(0<=mono<CLEANUP_NS and 0<=wall<CLEANUP_NS)
        return max(mono,wall)

    def _cleanup_reason(self):
        if self._failed:
            state=self._state()
            reason='controller-exited-before-handoff' if state=='exited' and 'runtime' in self._resources else 'preparation-failed'
            return reason,state
        while True:
            elapsed=self._elapsed();state=self._state()
            if self._wall+elapsed>=self._expiry or state=='exited':break
            self._waiting.set();time.sleep(0.01)
        return ('lease-expired' if self._wall+elapsed>=self._expiry else 'controller-exited'),state

    def _dispose_known(self):
        deleted=0
        for kind in ('runtime','copy','image'):
            resource=self._resources.get(kind)
            if resource is not None and not resource._closed:
                if self._prepared:self._elapsed()
                packet.require(resource.owner is self);resource.dispose();deleted+=1
        return deleted

    def cleanup(self):
        self._check_owned();packet.require(not self._cleanup_started and (self._prepared or self._failed))
        self._cleanup_started=True
        reason,state=self._cleanup_reason()
        self._record('delete',dict(schema='fleetory.retained-own-cleanup-attempt.v1',nonce=self._nonce,status='ATTEMPT_CONSUMED',reason=reason))
        expired=hasattr(self,'_intent') and time.time_ns()>=self._intent['expiresNs']
        deleted=self._dispose_known()
        packet.require([self._docker.base(n) for n in context.probe.BASES]==self._bases)
        packet.require(not self._unknown)
        value=dict(schema='fleetory.retained-independent-cleanup.v1',nonce=self._nonce,reason=reason,ownCreatedResourcesAbsent=True,
            actualCleanupExecuted=deleted>0,ownSuccessfulCreateReplyHeld='runtime' in self._resources,typedRetainedHandoffVerified=self._prepared,
            typedImageReadbackPreparationVerified=hasattr(self,'_intent'),
            actualControllerIdentityVerified=True,controllerExitedBeforeCleanup=state=='exited',guardianAliveDuringCleanup=True,
            independentExpiryEnforcementVerified=reason=='lease-expired',controllerDeathCleanupVerified=reason in ('controller-exited','controller-exited-before-handoff'),
            sourceAdmissionExpiredBeforeCleanup=bool(expired),cleanupIndependentOfLiveChildCapability=True,
            publicationDescriptorsHeld=58,sourceFilesPinned=len(context.SOURCES),sourcePinsSha256=self._source_pin,
            cachedBasesPreserved=True,cleanupAttemptConsumed=True,unknownCreateOutcome=False,retainedCommandLifetimeSeconds=660,
            controller=self._transport._controller,supervisor=self._transport._parent,
            guardianDeathCleanupVerified=False,daemonFailureCleanupVerified=False,preReceiptCrashCleanupVerified=False,
            externalRollbackResistanceVerified=False,nativePublisherOriginIndependentlyAuthenticated=False,
            originalInputsRead=False,originalPrivatePkiUsed=False,sourceVpsAccessed=False,fullSystemRecoveryVerified=False,phase7Complete=False)
        self._record('result',value);self._result=C(value)
        return self.result()

    def result(self):
        self._check_owned();packet.require(self._result is not None)
        saved=self._records['result'].report();saved.pop('localConsumedRecordFlushed')
        packet.require(C(saved)==self._result)
        return packet.strict_json(self._result,8192)

    def close(self):
        if self._closed:return
        packet.require(os.getpid()==self._caller)
        try:
            if self._transport is not None:self._transport.close()
        finally:self._closed=True;self._held.close()

    def run(self):
        with self:
            self.prepare()
            return self.cleanup()

    def __enter__(self):return self
    def __exit__(self,*_):
        try:
            if not self._closed and not self._cleanup_started and (self._prepared or self._failed):self.cleanup()
        finally:self.close()


if __name__=='__main__':raise SystemExit('Fixed own-created public retained cleanup library; no adopted ID, command, service or secret CLI.')
