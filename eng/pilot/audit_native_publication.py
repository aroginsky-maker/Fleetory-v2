"""Fixed public-only publisher under the historical native owner; no backend or private-input API."""
from contextlib import ExitStack
import base64
import json
import os
from pathlib import Path
import sys
import threading

import audit_native_preparation as prep
import audit_publication_namespace as ns

packet,process,control=prep.packet,prep.process,prep.control
SCHEMA='fleetory.native-publication-header.v1'
SDK='10.0.402'
MAX_MANIFEST,MAX_ACTION=12288,40000
SOURCES=(*prep.SOURCES,'eng/pilot/audit_probe_bundle.py','eng/pilot/audit_publication_namespace.py',
    'eng/pilot/audit_native_publication.py','eng/pilot/HistoricalPublicPublication.ps1')


def inputs(data,native_pin):
    value=packet.strict_json(data,prep.MAX_HEADER)
    packet.keys(value,'schema nonce controlSha256 planBase64 gitSha256 dotnetSha256 sdkVersion namespaceBase64 manifestBase64')
    packet.require(value['schema']==SCHEMA and value['sdkVersion']==SDK)
    packet.hex_value(value['dotnetSha256'])
    base={k:value[k] for k in ('nonce','controlSha256','planBase64','gitSha256')}
    info=prep.header(prep.canonical(dict(schema=prep.SCHEMA,**base)),native_pin)
    info['headerSha256']=packet.digest(data)
    intent=packet.decode(value['namespaceBase64'],ns.MAX_FRAME)
    declared=ns.admit(intent,packet.digest(intent))
    packet.require(declared['nonce']==info['nonce'] and declared['controlSha256']==info['controlSha256'])
    manifest=packet.decode(value['manifestBase64'],MAX_MANIFEST)
    measured,entries=ns.bundle.manifest(manifest,declared['manifestSha256'])
    native=prep.restore.plan(packet.decode(value['planBase64'],16384),native_pin)
    packet.require(measured['sha256']==native['probeBundleSha256'] and
        entries['ServerBackendProbe.dll']['sha256']==native['probeSha256'])
    return value,info,intent,manifest


def header(data,native_pin):
    return inputs(data,native_pin)[1]


def authorize(info,ready_pin,decision,namespace_ready=None,release_pin=None):
    packet.require(decision in ('reserve','publish','close'));packet.hex_value(ready_pin)
    if release_pin is not None:packet.hex_value(release_pin)
    packet.require((namespace_ready is None)==(decision=='reserve') and (release_pin is not None)==(decision=='close'))
    return dict(schema='fleetory.native-publication-authorize.v1',nonce=info['nonce'],
        headerSha256=info['headerSha256'],readySha256=ready_pin,decision=decision,
        namespaceReadySha256=None if namespace_ready is None else packet.digest(prep.canonical(namespace_ready)),
        releaseSha256=release_pin)


class _RecordedPublication(ns.OwnedPublication):
    """Reopen only the exact namespace just created for the current native parent."""
    def __init__(self,repository,intent,ready,native_pid):
        packet.require(type(native_pid) is int and 0<native_pid<=0xffffffff and native_pid==os.getppid())
        self.value=ns.admit(intent,packet.digest(intent));self.owner_pid=native_pid
        self._held=ExitStack();self.published=None;self._attempted=False
        try:
            self.parent=self._held.enter_context(control.DirectoryLease(Path(repository)/'artifacts'))
            self.directory=self._held.enter_context(control.DirectoryLease(self.parent.path/ns.name(self.value['nonce'])))
            self.output=self._held.enter_context(control.DirectoryLease(self.directory.path/ns.OUTPUT))
            self.root_pin,self.output_pin=ns.empty.directory_hash(self.directory),ns.empty.directory_hash(self.output)
            raw=prep.canonical(ns.marker(self.value,native_pid,self.root_pin,self.output_pin))
            self.owner_pin=packet.digest(raw)
            self.pin=self._held.enter_context(process.PinnedFile(self.directory.path/ns.MARKER,self.owner_pin))
            packet.require(self.ready()==ready and type(ready['pid']) is int and ready['privateInputsAccepted'] is False)
        except BaseException:self.close();raise


def native_action(data,native_pin,ready_pin,native_pid,mode):
    packet.require(mode in ('reserve','publish','seal','close') and type(native_pid) is int and 0<native_pid<=0xffffffff and native_pid==os.getppid())
    action=packet.strict_json(data,MAX_ACTION)
    packet.keys(action,'schema headerBase64 frameBase64 namespaceReady')
    packet.require(action['schema']=='fleetory.native-publication-action.v1')
    value,info,intent,manifest=inputs(packet.decode(action['headerBase64'],prep.MAX_HEADER),native_pin)
    frame=packet.strict_json(packet.decode(action['frameBase64'],prep.MAX_FRAME),prep.MAX_FRAME)
    ready=action['namespaceReady']
    decision='publish' if mode=='seal' else mode
    expected=authorize(info,ready_pin,decision,ready,frame.get('releaseSha256'))
    packet.require(frame==expected and type(frame.get('namespaceReadySha256')) is (type(None) if mode=='reserve' else str))
    repository=Path(__file__).resolve().parents[2]
    if mode=='reserve':
        with ns.OwnedPublication(repository,intent,packet.digest(intent),native_owner_pid=native_pid) as owned:
            return owned.ready()
    with _RecordedPublication(repository,intent,ready,native_pid) as owned:
        if mode=='publish':
            packet.require(not any(owned.output.path.iterdir()))
            return dict(verified=True)
        receipt=owned.seal(manifest)
        if mode=='seal':
            return dict(schema='fleetory.native-publication-produced.v1',headerSha256=info['headerSha256'],
                readySha256=ready_pin,pid=native_pid,dotnetSha256=value['dotnetSha256'],
                sdkVersion=SDK,receipt=receipt,privateInputsAccepted=False)
        return dict(schema='fleetory.native-publication-closed.v1',nonce=info['nonce'],
            headerSha256=info['headerSha256'],readySha256=ready_pin,releaseSha256=frame['releaseSha256'],
            namespaceRemoved=False,privateInputsAccepted=False)


class _NativePublicationPumps(prep._PreparationPumps):
    source_names=SOURCES
    profile,switch='native-publication','-PublicProbePublicationOnly'
    max_frames=4
    decode_header=staticmethod(header)
    refusal_schema='fleetory.native-publication-refused.v1'

    @classmethod
    def make_header(cls,native_plan,report,session,source_pins,git_pin,*,dotnet_sha256,manifest):
        packet.require(type(manifest) is bytes and 0<len(manifest)<=MAX_MANIFEST)
        value=super().make_header(native_plan,report,session,source_pins,git_pin)
        intent=ns.prepare(session,packet.digest(manifest),packet.digest(prep.canonical(source_pins)))
        value.update(schema=SCHEMA,dotnetSha256=dotnet_sha256,sdkVersion=SDK,
            namespaceBase64=base64.b64encode(intent).decode('ascii'),manifestBase64=base64.b64encode(manifest).decode('ascii'))
        return value

    def __init__(self,*args):
        super().__init__(*args)
        self.value,_,self.intent,self.manifest=inputs(self.data[:-1],self.session._plan['nativePlanSha256'])
        self.namespace_ready,self.produced=threading.Event(),threading.Event()
        self.bound,self.release_pin=None,None

    def _accept_refusal(self,value):
        packet.keys(value,'schema stage privateInputsAccepted backendCreated')
        packet.require(value['stage'] in ('header','git','code','sdk','reserve','publish','seal','close') and
            value['privateInputsAccepted'] is False and value['backendCreated'] is False)
        self.refusal_stage=value['stage'];self.errors.append('native-publication-refused')

    def _bind_ready(self,value,raw):
        declared=ns.admit(self.intent,packet.digest(self.intent))
        packet.require(self.component_pin()==declared['selectedSourcesSha256'] and
            self.command.dotnet.digest==self.value['dotnetSha256'])
        super()._bind_ready(value,raw)

    def _accept_frame(self,value,raw):
        if len(self.frames)==1:
            self.bound=ns.BoundPublication(self.command,self.session,self.process,self.fence,self.intent,packet.digest(self.intent),value)
            packet.require(not any(self.bound.output.path.iterdir()))
            self.frames.append(value);self.namespace_ready.set()
        elif len(self.frames)==2:
            packet.keys(value,'schema headerSha256 readySha256 pid dotnetSha256 sdkVersion receipt privateInputsAccepted')
            packet.require(value==dict(schema='fleetory.native-publication-produced.v1',headerSha256=self.info['headerSha256'],
                readySha256=self.ready_pin,pid=self.process.pid,dotnetSha256=self.value['dotnetSha256'],
                sdkVersion=SDK,receipt=value['receipt'],privateInputsAccepted=False) and type(value['pid']) is int and value['privateInputsAccepted'] is False)
            packet.require(value['receipt']==self.bound.seal(self.manifest))
            self.bound.acknowledge(value['receipt'])
            self.session._write_once('native-publication-receipt.json',dict(schema='fleetory.native-publication-bound.v1',
                nonce=self.info['nonce'],actualOwnedProcess=self.bound.owner_identity(),
                headerSha256=self.info['headerSha256'],readySha256=self.ready_pin,
                producedSha256=packet.digest(raw),dotnetSha256=self.value['dotnetSha256'],sdkVersion=SDK,
                selectedSourcesSha256=self.component_pin(),manifestSha256=packet.digest(self.manifest),
                fileDescriptorsHeld=len(self.bound.published.pins),actualNativePublicationVerified=True,
                compilerClosureAuthenticated=False,originalInputsRead=False,backendCreated=False))
            self.frames.append(value);self.produced.set()
        else:super()._accept_frame(value,raw)

    def _wait(self,event):
        while not event.wait(0.01):
            packet.require(not self.errors and not self.stopping.is_set())
            process._check_deadline(self.start_time,self.seconds)

    def _send_frame(self,value):
        data=prep.canonical(value)+b'\n';self.expected_input_bytes+=len(data);self._send(data)

    def _write(self):
        try:
            self._send(self.data);self._wait(self.ready)
            self._send_frame(authorize(self.info,self.ready_pin,'reserve'))
            self._wait(self.namespace_ready);self.bound.check()
            self._send_frame(authorize(self.info,self.ready_pin,'publish',self.frames[1]))
            self._wait(self.produced);self.release_pin=self.bound.release()
            process._check_deadline(self.start_time,self.seconds)
            self._send_frame(authorize(self.info,self.ready_pin,'close',self.frames[1],self.release_pin))
        except Exception:self.errors.append('native-publication-handoff-refused')
        finally:self._close_input()

    def finalize_binding(self,child,ended,failed):
        self.resource_metadata=dict(schema='fleetory.native-publication-result.v1',actualNativePublicationVerified=False,
            namespaceHandoffVerified=False,nativeReadinessBound=False,selectedSourceFilesPinned=len(SOURCES),
            dotnetExecutablePinned=False,sdkVersion=SDK,compilerClosureAuthenticated=False,namespaceRemoved=False,
            privateInputsAccepted=False,backendCreated=False,backendCleanupAuthorized=False,operationalLeaseAuthorized=False,
            originalInputsRead=False,originalPrivatePkiUsed=False,sourceVpsAccessed=False,fullSystemRecoveryVerified=False,
            phase7Complete=False,refusalStage=self.refusal_stage)
        try:
            packet.require(not failed and child.returncode==0 and ended['noRunningMembersVerified'] and
                not self.pending and len(self.frames)==4 and self.release_pin is not None)
            packet.require(self.frames[-1].get('namespaceRemoved') is False and self.frames[-1].get('privateInputsAccepted') is False)
            packet.require(self.frames[-1]==dict(schema='fleetory.native-publication-closed.v1',nonce=self.info['nonce'],
                headerSha256=self.info['headerSha256'],readySha256=self.ready_pin,releaseSha256=self.release_pin,
                namespaceRemoved=False,privateInputsAccepted=False))
            self.command.check();self.session.check()
            self.resource_metadata.update(actualNativePublicationVerified=True,namespaceHandoffVerified=True,
                nativeReadinessBound=True,dotnetExecutablePinned=True)
        finally:
            if self.bound is not None:self.bound.close()


def publish_owner(repository,powershell,python,git,dotnet,native_plan,source_pins,session,*,git_sha256,dotnet_sha256,manifest):
    return prep._prepare_owner(repository,powershell,python,git,native_plan,source_pins,session,git_sha256,
        _NativePublicationPumps,publication=(dotnet,dotnet_sha256,manifest))


def measure_sources(repository):
    return prep._measure_sources(repository,SOURCES)


if __name__=='__main__':
    try:
        if len(sys.argv)==3 and sys.argv[1]=='header':
            result=header(sys.stdin.buffer.read(prep.MAX_HEADER+1),sys.argv[2])
        else:
            packet.require(len(sys.argv)==5)
            result=native_action(sys.stdin.buffer.read(MAX_ACTION+1),sys.argv[2],sys.argv[3],int(sys.argv[4]),sys.argv[1])
        print(prep.canonical(result).decode('ascii'))
    except Exception:
        print('Native public publication refused.',file=sys.stderr);sys.exit(1)
