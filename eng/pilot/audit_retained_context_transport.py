"""Owned retained-controller public context transport. No adopted ID, Docker or secret API."""
from contextlib import ExitStack
import base64
import os
from pathlib import Path
import sys
import threading
import time
from types import SimpleNamespace

import audit_public_cleanup_guard as guard
import audit_publication_continuation as publication

process,packet=guard.process,guard.packet
C,H=publication.prep.canonical,packet.digest
probe,bundle,restore=publication.probe,publication.ns.bundle,publication.prep.restore
MAX_HEADER,MAX_OFFER,MAX_CLOSE=65536,32768,4096
SECONDS=55
SOURCES=tuple(dict.fromkeys((*publication.SOURCES,*guard.SOURCES)))
SCHEMA='fleetory.retained-context-offer.v1'
ROLES=('powershell','git','dotnet')


def encode(raw):return base64.b64encode(raw).decode('ascii')


def frame(value,bound):
    raw=C(value);packet.require(0<len(raw)<=bound)
    return len(raw).to_bytes(4,'big')+raw


def frame_size(prefix,bound):
    packet.require(type(prefix) is bytes and len(prefix)==4)
    size=int.from_bytes(prefix,'big');packet.require(0<size<=bound)
    return size


def source_measurement(repository):return publication.prep._measure_sources(repository,SOURCES)


def _environment(runtimes):
    # Interpreter directories such as /usr/bin must not shadow the pinned private tools.
    return dict(process.environment(runtimes['powershell'],tuple(runtimes[n] for n in ('git','dotnet','python'))))


def ledger_name(nonce,*,ready=False):
    packet.require(type(ready) is bool)
    return ('retained-context-ready-' if ready else 'retained-context-start-')+packet.identity(nonce)+'.json'


def _header(raw):
    value=packet.strict_json(raw,MAX_HEADER)
    packet.keys(value,'schema parent controller runtimes sourcePins nativePlanBase64 nativePlanSha256 manifestBase64 manifestSha256 bases')
    packet.require(value['schema']=='fleetory.retained-context-header.v1')
    guard.identity.protocol._identity(value['parent']);guard.identity.protocol._identity(value['controller'])
    packet.keys(value['runtimes'],'python powershell git dotnet')
    for digest in value['runtimes'].values():packet.hex_value(digest)
    packet.require(type(value['sourcePins']) is dict and set(value['sourcePins'])==set(SOURCES))
    for digest in value['sourcePins'].values():packet.hex_value(digest)
    plan_raw=packet.decode(value['nativePlanBase64'],16384);plan=restore.plan(plan_raw,value['nativePlanSha256'])
    manifest=packet.decode(value['manifestBase64'],bundle.MAX_MANIFEST)
    measured,entries=bundle.manifest(manifest,value['manifestSha256'])
    packet.require(measured['sha256']==plan['probeBundleSha256'] and entries['ServerBackendProbe.dll']['sha256']==plan['probeSha256'])
    probe.bases(value['bases'])
    return value,plan,plan_raw,manifest


def _intent(raw,plan,reference,bases,reservation,opened,now):
    value=packet.strict_json(raw,probe.image.MAX_INTENT)
    packet.keys(value,'schema purpose nonce revision controlSha256 sourceCodeSha256 probeSha256 bundleManifestSha256 '
        'bundleSha256 bundleFiles bundleBytes bases openedNs expiresNs labels definitionSha256 contextSha256 contextBytes')
    packet.require(value['schema']==probe.SCHEMA and value['purpose']==probe.PURPOSE and value['nonce']==plan['nonce'] and
        value['revision']==plan['revision'] and value['sourceCodeSha256']==plan['codeSha256'] and value['probeSha256']==plan['probeSha256'])
    packet.require(value['controlSha256']==reservation and value['bundleManifestSha256']==reference.pin and
        value['bundleSha256']==reference.value['sha256'] and value['bundleFiles']==reference.value['files'] and
        type(value['bundleFiles']) is int and value['bundleBytes']==reference.value['bytes'] and type(value['bundleBytes']) is int)
    packet.require(value['bases']==bases and value['labels']==dict(bases[2]['labels'],**probe.own_labels(value)))
    packet.require(type(value['openedNs']) is int and type(value['expiresNs']) is int and
        opened<=value['openedNs']<=now<value['expiresNs'] and value['expiresNs']-value['openedNs']==probe.image.WINDOW_NS)
    expected=reference.context(probe.definition(value))
    packet.require(value['definitionSha256']==H(probe.definition(value)) and value['contextSha256']==H(expected) and
        type(value['contextBytes']) is int and value['contextBytes']==len(expected))
    return value,expected


def admit_offer(raw,context,header,reference,opened,now):
    """Pure bounded admission against the parent's own held reference, never a wire reference."""
    for data,bound in ((raw,MAX_OFFER),(context,bundle.MAX_CONTEXT),(header,MAX_HEADER)):
        packet.require(type(data) in (bytes,bytearray) and 0<len(data)<=bound)
    raw,context,header=(bytes(data) for data in (raw,context,header))
    packet.require(type(reference) is bundle.HeldProbeBundle)
    reference.check();value=packet.strict_json(raw,MAX_OFFER)
    packet.keys(value,'schema headerSha256 controller nonce reservationSha256 imageIntentBase64 contextBytes contextSha256 '
        'publicationDescriptorsHeld heldDescriptorsSha256 publicationBindingSha256 nativeOwnerExited nativeOwnedMembersAbsent '
        'retainedOpenedNs retainedExpiresNs')
    declared,plan,_,manifest=_header(header)
    packet.require(value['schema']==SCHEMA and value['headerSha256']==H(header) and value['controller']==declared['controller'] and value['nonce']==plan['nonce'])
    packet.require(H(manifest)==reference.pin and value['publicationDescriptorsHeld']==len(reference.pins) and type(value['publicationDescriptorsHeld']) is int)
    for key in ('reservationSha256','heldDescriptorsSha256','publicationBindingSha256'):packet.hex_value(value[key])
    packet.require(value['nativeOwnerExited'] is value['nativeOwnedMembersAbsent'] is True and
        type(value['retainedOpenedNs']) is int and type(value['retainedExpiresNs']) is int and
        opened<=value['retainedOpenedNs']<=now<value['retainedExpiresNs'] and
        value['retainedExpiresNs']-value['retainedOpenedNs']==publication.WINDOW_NS)
    intent,expected=_intent(packet.decode(value['imageIntentBase64'],probe.image.MAX_INTENT),plan,reference,
        declared['bases'],value['reservationSha256'],opened,now)
    packet.require(type(value['contextBytes']) is int and value['contextBytes']==len(context)==len(expected) and
        value['contextSha256']==H(context)==intent['contextSha256'] and context==expected)
    reference.check()
    return value


def close_request(nonce,context_pin):
    packet.hex_value(context_pin)
    return dict(schema='fleetory.retained-context-close.v1',nonce=packet.identity(nonce),contextSha256=context_pin,decision='close-without-docker')


class RetainedContextTransport:
    """The independent parent owns the controller fence and expected public source bytes."""
    def __init__(self,repository,operator_root,native_plan,reference,bases,*,runtime_paths,runtime_pins,source_pins):
        self._held=ExitStack();self._child=self._fence=self._pumps=None
        self._admitted,self._closed,self._result=False,False,None
        self._caller=os.getpid();self._wall,self._mono=time.time_ns(),time.monotonic_ns()
        packet.require(type(native_plan) in (bytes,bytearray));native_plan=bytes(native_plan)
        self._plan=restore.plan(native_plan,H(native_plan));nonce=self._plan['nonce']
        self._repo=Path(repository).resolve(strict=True);self._root=Path(operator_root)
        try:
            start=dict(schema='fleetory.retained-context-start.v1',nonce=nonce,status='TRANSPORT_ATTEMPT_CONSUMED',
                nativePlanSha256=H(native_plan),assertedParentPid=self._caller,dockerOperationsPerformed=0,cleanupAuthorized=False)
            self._start=self._held.enter_context(guard.attempts._claim_record(self._root,ledger_name(nonce),start))
            packet.require(type(reference) is bundle.HeldProbeBundle and reference.value['sha256']==self._plan['probeBundleSha256'])
            reference.check();self._reference=reference
            self._held.enter_context(process.control.DirectoryLease(self._repo))
            packet.require(type(source_pins) is dict and set(source_pins)==set(SOURCES))
            sources=dict(source_pins)
            self._sources=tuple(self._held.enter_context(publication.prep._RootInputPin(self._repo/name,sources[name])) for name in SOURCES)
            packet.keys(runtime_paths,'python powershell git dotnet');packet.keys(runtime_pins,'python powershell git dotnet')
            runtime_paths,runtime_pins=dict(runtime_paths),dict(runtime_pins)
            bases=packet.strict_json(C(bases),MAX_OFFER)
            self._runtimes={name:self._held.enter_context(process.PinnedFile(runtime_paths[name],runtime_pins[name],True)) for name in runtime_paths}
            packet.require(self._runtimes['python'].path==Path(sys.executable).resolve(strict=True))
            for role in ROLES:
                allowed=('pwsh','pwsh.exe') if role=='powershell' else (role,role+'.exe')
                packet.require(self._runtimes[role].path.name.lower() in allowed)
            self._parent=guard.identity.current_identity(self._runtimes['python'])
            env=_environment(self._runtimes)
            command=SimpleNamespace(executable=self._runtimes['python'],arguments=('-I','-B',str(self._repo/'eng/pilot/RetainedContextController.py')),
                directory=self._repo,env=env)
            self._check_pins()
            self._child=process._spawn(command);self._fence=process._create_fence(self._child)
            self._controller=guard._process_identity(self._fence.identity(self._child,self._runtimes['python']))
            self._header=C(dict(schema='fleetory.retained-context-header.v1',parent=self._parent,controller=self._controller,
                runtimes={n:p.digest for n,p in self._runtimes.items()},sourcePins=sources,nativePlanBase64=encode(bytes(native_plan)),
                nativePlanSha256=H(native_plan),manifestBase64=encode(reference.raw),manifestSha256=reference.pin,bases=probe.bases(bases)))
            packet.require(len(self._header)<=MAX_HEADER)
            self._pumps=process._Pumps(self._child,b'')
            limit=bundle.MAX_CONTEXT+MAX_OFFER+MAX_CLOSE+8
            for stream,target,bound in ((self._child.stdout,self._pumps.stdout,limit),(self._child.stderr,self._pumps.stderr,4096)):
                thread=threading.Thread(target=self._pumps._read,args=(stream,target,bound,'context-output-bound'),daemon=True)
                self._pumps.threads.append(thread);thread.start()
            self._pumps._send(self._header+b'\n')
            self._receive()
        except BaseException:self.close();raise

    def _check_pins(self):
        packet.require(not self._closed and os.getpid()==self._caller)
        process._check_deadline(self._mono,SECONDS)
        packet.require(0<=time.time_ns()-self._wall<SECONDS*1_000_000_000)
        self._start.check();self._reference.check()
        for source in self._sources:source.check()
        for runtime_pin in self._runtimes.values():runtime_pin.check()
        packet.require(guard.identity.current_identity(self._runtimes['python'])==self._parent)

    def _exited(self):return self._child.poll() is not None if os.name=='nt' else self._fence.exited()

    def _live(self):
        self._check_pins()
        packet.require(not self._pumps.errors and not self._pumps.stderr and not self._exited())
        packet.require(guard._process_identity(self._fence.identity(self._child,self._runtimes['python']))==self._controller)

    def _progress(self):
        packet.require(not self._closed and os.getpid()==self._caller)
        process._check_deadline(self._mono,SECONDS)
        packet.require(0<=time.time_ns()-self._wall<SECONDS*1_000_000_000 and
            not self._pumps.errors and not self._pumps.stderr and not self._exited())

    def _wait_bytes(self,count):
        while len(self._pumps.stdout)<count:
            self._progress();time.sleep(0.01)
        self._live()

    def _receive(self):
        self._wait_bytes(4);size=frame_size(bytes(self._pumps.stdout[:4]),MAX_OFFER)
        self._wait_bytes(4+size);raw=bytes(self._pumps.stdout[4:4+size])
        offered=packet.strict_json(raw,MAX_OFFER)
        count=offered.get('contextBytes');packet.require(type(count) is int and 0<count<=bundle.MAX_CONTEXT)
        self._total=4+size+count;self._wait_bytes(self._total)
        packet.require(len(self._pumps.stdout)==self._total)
        context=bytes(self._pumps.stdout[4+size:self._total])
        self._offer=admit_offer(raw,context,self._header,self._reference,self._wall,time.time_ns())
        self._context=context;self._live()
        ready=dict(schema='fleetory.retained-context-ready.v1',nonce=self._plan['nonce'],status='PUBLIC_CONTEXT_TRANSPORT_BOUND',
            parent=self._parent,controller=self._controller,headerSha256=H(self._header),offerSha256=H(raw),contextSha256=H(context),
            contextBytes=len(context),expectedManifestSha256=self._reference.pin,sourcePinsSha256=H(C(_header(self._header)[0]['sourcePins'])),
            dockerOperationsPerformed=0,buildAuthorized=False,cleanupAuthorized=False)
        self._ready=self._held.enter_context(guard.attempts._claim_record(self._root,ledger_name(self._plan['nonce'],ready=True),ready))
        self._admitted=True;self.context_bytes()

    def context_bytes(self):
        packet.require(self._admitted);self._live();self._ready.check()
        packet.require(len(self._pumps.stdout)==self._total and H(self._context)==self._offer['contextSha256'])
        return bytes(self._context)

    def _graceful(self):
        self.context_bytes();self._pumps._send(C(close_request(self._plan['nonce'],self._offer['contextSha256']))+b'\n')
        self._child.stdin.close()
        while not self._exited():
            process._check_deadline(self._mono,SECONDS);packet.require(not self._pumps.errors);time.sleep(0.01)
        return True

    def close(self):
        if self._closed:return
        packet.require(os.getpid()==self._caller)
        graceful=False;failure=None;ended=None
        try:
            if self._admitted and not self._exited():graceful=self._graceful()
        except Exception:failure='context-close-refused'
        finally:
            ended,closing=process._finish_owned(self._child,self._fence,self._pumps)
            failure=closing or failure
            try:
                if self._admitted:
                    packet.require(ended is not None and ended['noRunningMembersVerified'] is True)
                    if graceful:
                        raw=bytes(self._pumps.stdout[self._total:]);packet.require(len(raw)>=4)
                        size=frame_size(raw[:4],MAX_CLOSE);packet.require(len(raw)==4+size and not self._pumps.errors and not self._pumps.stderr and self._child.returncode==0)
                        value=packet.strict_json(raw[4:],MAX_CLOSE)
                        packet.require(value==dict(schema='fleetory.retained-context-closed.v1',nonce=self._plan['nonce'],
                            contextSha256=self._offer['contextSha256'],sourceDescriptorsClosed=self._offer['publicationDescriptorsHeld'],
                            originalInputsRead=False,dockerOperationsPerformed=0))
                    self._result=C(dict(schema='fleetory.retained-context-transport-result.v1',nonce=self._plan['nonce'],parent=self._parent,
                        controller=self._controller,contextSha256=self._offer['contextSha256'],contextBytes=len(self._context),
                        referenceManifestSha256=self._reference.pin,publicationDescriptorsHeld=self._offer['publicationDescriptorsHeld'],
                        heldDescriptorsSha256=self._offer['heldDescriptorsSha256'],sourceFilesPinned=len(SOURCES),
                        sourcePins=_header(self._header)[0]['sourcePins'],controllerOwnedAndFenced=True,parentAliveAfterControllerExit=True,
                        publicContextMatchesIndependentReference=True,gracefulDescriptorClosureVerified=graceful,
                        controllerDeathObserved=not graceful,ownedControllerMembersAbsent=True,transportAttemptConsumed=True,
                        nativePublisherOriginIndependentlyAuthenticated=False,escapedSessionContainmentVerified=False,
                        dockerOperationsPerformed=0,imageBuildPerformed=False,ownCreateReceiptAvailable=False,cleanupAuthorized=False,
                        retainedControllerDeathCleanupVerified=False,originalInputsRead=False,originalPrivatePkiUsed=False,
                        sourceVpsAccessed=False,fullSystemRecoveryVerified=False,phase7Complete=False))
            except Exception:failure='context-closure-unverified'
            finally:self._closed=True;self._held.close()
        packet.require(failure is None)

    def result(self):
        packet.require(self._closed and self._result is not None and os.getpid()==self._caller)
        return packet.strict_json(self._result,32768)

    def __enter__(self):return self
    def __exit__(self,*_):self.close()


if __name__=='__main__':raise SystemExit('Owned public context transport library; no command, Docker, service, ID-adoption or secret CLI.')
