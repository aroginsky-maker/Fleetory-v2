"""OS-fenced Python fixture owner for a public namespace, not a native compiler or historical launcher."""
from contextlib import ExitStack
import base64
import json
import os
from pathlib import Path
import queue
import shutil
import sys
import tempfile
import threading
import time
import uuid
from unittest.mock import patch
from types import SimpleNamespace

REPO=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(REPO/'eng/pilot'))
import audit_publication_namespace as ns

packet,process=ns.packet,ns.process
ENTRY='tests/Fleetory.Tools.Tests/native_publication_namespace.py'
SOURCES=(*ns.SOURCES,ENTRY)
MANIFEST_FRAME=132096


def source_pins(repository):
    return ns.bundle.prep._measure_sources(repository,SOURCES)


def frame(value):return ns.bundle.prep.canonical(value)+b'\n'


def read_frame(bound):
    raw=sys.stdin.buffer.readline(bound+1)
    packet.require(0<len(raw)<=bound and raw.endswith(b'\n'))
    return packet.strict_json(raw[:-1],bound)


def worker(expected):
    data=sys.stdin.buffer.readline(ns.MAX_FRAME+1)
    packet.require(data.endswith(b'\n'));raw=data[:-1]
    value=ns.admit(raw,expected)
    packet.require(value['selectedSourcesSha256']==packet.digest(ns.bundle.prep.canonical(source_pins(REPO))))
    with ns.OwnedPublication(REPO,raw,expected) as owned:
        sys.stdout.buffer.write(frame(owned.ready()));sys.stdout.buffer.flush()
        value=read_frame(MANIFEST_FRAME);packet.keys(value,'schema manifestBase64')
        packet.require(value['schema']=='fleetory.publication-fixture-seal.v1')
        manifest=packet.decode(value['manifestBase64'],ns.bundle.MAX_MANIFEST)
        if packet.digest(manifest)!=owned.value['manifestSha256']:
            try:owned.seal(manifest)
            except packet.PairError:
                owned.check()
                sys.stdout.buffer.write(frame(dict(schema='fleetory.publication-fixture-refused.v1',nonce=owned.value['nonce'],
                    stage='manifest-pin',expectedManifestSha256=owned.value['manifestSha256'],observedManifestSha256=packet.digest(manifest),
                    pid=os.getpid(),privateInputsAccepted=False,actualNativePublicationVerified=False)))
                sys.stdout.buffer.flush();return 1
            raise AssertionError('Wrong public manifest pin accepted.')
        sys.stdout.buffer.write(frame(owned.seal(manifest)));sys.stdout.buffer.flush()
        value=read_frame(ns.MAX_FRAME);packet.keys(value,'schema nonce releaseSha256')
        packet.require(value['schema']=='fleetory.publication-fixture-release.v1' and value['nonce']==owned.value['nonce'])
        packet.hex_value(value['releaseSha256']);packet.require(sys.stdin.buffer.read(1)==b'')
        owned.check()
        sys.stdout.buffer.write(frame(dict(schema='fleetory.publication-fixture-closed.v1',nonce=value['nonce'],
            releaseSha256=value['releaseSha256'],namespaceRemoved=False,actualNativePublicationVerified=False)))
        sys.stdout.buffer.flush()


def owner_exited(child,fence):
    # POSIX must keep the leader unreaped until group-ID/birth-checked cleanup.
    return child.poll() is not None if os.name=='nt' else fence.exited()


def wait_owner_exit(child,fence,start):
    while not owner_exited(child,fence):
        process._check_deadline(start,30);time.sleep(0.01)


class Frames(process._Pumps):
    def __init__(self,child,fence):
        super().__init__(child,b'');self.fence=fence;self.pending=bytearray();self.frames=[];self.received=queue.Queue()

    def _on_output(self,category,data):
        if category!='stdout-bound':return
        self.pending.extend(data);packet.require(len(self.pending)<=ns.MAX_FRAME)
        while b'\n' in self.pending:
            raw,_,rest=self.pending.partition(b'\n');self.pending[:]=rest
            value=packet.strict_json(bytes(raw),ns.MAX_FRAME);packet.require(len(self.frames)<3)
            self.frames.append(value);self.received.put(value)

    def start_readers(self):
        for stream,target,bound,category in ((self.process.stdout,self.stdout,process.MAX_STDOUT,'stdout-bound'),
                (self.process.stderr,self.stderr,process.MAX_STDERR,'stderr-bound')):
            thread=threading.Thread(target=self._read,args=(stream,target,bound,category),daemon=True)
            self.threads.append(thread);thread.start()

    def receive(self,start):
        while True:
            packet.require(not self.errors);process._check_deadline(start,30)
            try:return self.received.get(timeout=0.01)
            except queue.Empty:
                if owner_exited(self.process,self.fence):
                    self.finish()
                    return self.received.get_nowait()


def copy_public(held,output):
    held.check();output.check()
    packet.require(not any(output.path.iterdir()))
    for name,item in held.entries.items():
        path=output.path/name
        if item['kind']=='d':path.mkdir(mode=0o700)
        else:
            with path.open('xb') as stream:
                stream.write(held._content(name));stream.flush();os.fsync(stream.fileno())
    held.check();output.check()


def handoff(root,held,case='positive'):
    from audit_probe_image_tests import control_plan
    packet.require(case in ('positive','bad-manifest','owner-exit'))
    replica=root/'repository';replica.mkdir();(replica/'artifacts').mkdir()
    controls=root/'controls';controls.mkdir()
    actual=source_pins(REPO)
    for name in SOURCES:
        source=REPO/name;target=replica/name;target.parent.mkdir(parents=True,exist_ok=True)
        with process.PinnedFile(source,actual[name]) as pinned:
            shutil.copyfile(pinned.path,target);pinned.check()
    packet.require(source_pins(replica)==actual)
    python=Path(sys.executable).resolve(strict=True);python_pin=packet.digest(python.read_bytes())
    plan=control_plan(str(uuid.uuid4()))
    plan.update(probeSha256=held.entries['ServerBackendProbe.dll']['sha256'],runtimes=dict(python=python_pin,powershell=python_pin))
    raw=ns.bundle.prep.canonical(plan)
    with ExitStack() as stack:
        executable=stack.enter_context(process.PinnedFile(python,python_pin,True))
        pins=tuple(stack.enter_context(process.PinnedFile(replica/name,actual[name])) for name in SOURCES)
        directory=stack.enter_context(ns.control.DirectoryLease(replica))
        session=stack.enter_context(ns.control.claim(controls,raw,packet.digest(raw)))
        intent=ns.prepare(session,held.pin,packet.digest(ns.bundle.prep.canonical(actual)));intent_pin=packet.digest(intent)
        def check():
            executable.check();directory.check()
            for pin in pins:pin.check()
        command=SimpleNamespace(executable=executable,directory=replica,check=check,
            arguments=('-B',str(replica/ENTRY),'--worker',intent_pin),env=process.environment(executable))
        session.consume_launch_attempt();start=time.monotonic_ns();started_wall=time.time_ns()
        child=process._spawn(command);fence=None;pumps=None;bound=None;accepted=False;injected=False;live_kill=False
        try:
            fence=process._create_fence(child);identity=fence.identity(child,executable);check()
            session.bind_assertion(child.pid,started_wall,executable.digest)
            pumps=Frames(child,fence);pumps.start_readers();pumps._send(frame(json.loads(intent)))
            ready=pumps.receive(start)
            bound=stack.enter_context(ns.BoundPublication(command,session,child,fence,intent,intent_pin,ready))
            copy_public(held,bound.output)
            expected=bound.seal(held.raw)
            if case=='owner-exit':
                packet.require(not owner_exited(child,fence) and fence.identity(child,executable)==identity)
                injected=True;live_kill=True;child.kill()
            else:
                manifest=held.raw if case=='positive' else held.raw+b' '
                injected=case=='bad-manifest'
                pumps._send(frame(dict(schema='fleetory.publication-fixture-seal.v1',manifestBase64=base64.b64encode(manifest).decode())))
                if case=='positive':
                    response=pumps.receive(start);packet.require(response==expected)
                    bound.acknowledge(response);release=bound.release()
                    pumps._send(frame(dict(schema='fleetory.publication-fixture-release.v1',nonce=plan['nonce'],releaseSha256=release)))
                    pumps._close_input();last=pumps.receive(start)
                    packet.require(last==dict(schema='fleetory.publication-fixture-closed.v1',nonce=plan['nonce'],releaseSha256=release,
                        namespaceRemoved=False,actualNativePublicationVerified=False));accepted=True
                else:
                    response=pumps.receive(start)
                    packet.require(response==dict(schema='fleetory.publication-fixture-refused.v1',nonce=plan['nonce'],stage='manifest-pin',
                        expectedManifestSha256=held.pin,observedManifestSha256=packet.digest(manifest),pid=child.pid,
                        privateInputsAccepted=False,actualNativePublicationVerified=False) and type(response['pid']) is int)
            wait_owner_exit(child,fence,start);pumps.finish()
            packet.require(not pumps.errors and not pumps.pending)
            if case=='positive':packet.require(pumps.stderr==b'' and len(pumps.frames)==3)
            else:packet.require(injected and not accepted and len(pumps.frames)==(2 if case=='bad-manifest' else 1) and 'publication-release.json' not in session._records)
        finally:
            if fence is not None:ended=fence.terminate()
            else:
                child.kill();ended=None
            child.wait(timeout=3)
            if pumps:pumps.finish()
            process._close_transport(child,fence)
        packet.require(ended is not None and ended['noRunningMembersVerified'] is True)
        packet.require(child.returncode==0 if case=='positive' else child.returncode!=0)
        if not accepted:bound._check_tree()
        path=replica/'artifacts'/ns.name(plan['nonce'])
        packet.require(path.is_dir() and (path/ns.MARKER).is_file() and ns.bundle.tree(path/ns.OUTPUT)=={n:v['kind'] for n,v in held.entries.items()})
        with ns.bundle.HeldProbeBundle(path/ns.OUTPUT,held.raw,held.pin) as after:after.check()
        before=dict(session._records)
        with patch.object(process,'_spawn') as spawn:
            refused=False
            try:session.consume_launch_attempt()
            except ValueError:refused=True
            packet.require(refused);spawn.assert_not_called()
        packet.require(before==session._records and source_pins(replica)==actual)
        record=json.loads(session._records['publication-binding.json'][1])
        return dict(case=case,accepted=accepted,expectedInjectionReached=injected,liveOwnerObservedBeforeKill=live_kill,typedManifestPinRefusalVerified=case=='bad-manifest',
            actualOwnedProcess=identity,ownerBirthAndImageVerified=True,ownedProcessMembersAbsent=True,
            fileDescriptorsHeld=record['fileDescriptorsHeld'],files=held.value['files'],bytes=held.value['bytes'],manifestSha256=held.pin,
            controllerBindingSha256=packet.digest(session._records['publication-binding.json'][1]),
            namespaceReceipt=json.loads(session._records['publication-namespace.json'][1]),
            ownerAckRecorded='publication-owner-ack.json' in session._records,releaseRecorded='publication-release.json' in session._records,
            nonce=plan['nonce'],namespacePreservedBeforeFixtureDisposal=True,publicBytesUnchanged=True,consumedLaunchReplayRefused=True,
            selectedSourcesHeld=len(SOURCES),fixtureOwnerPython=True,historicalPowerShellOwnerIntegrated=False,
            actualNativePublicationVerified=False,backendCleanupAuthorized=False,originalInputsRead=False,originalPrivatePkiUsed=False,
            sourceVpsAccessed=False,fullSystemRecoveryVerified=False,phase7Complete=False)


def run(real=False):
    from audit_probe_image_tests import public_files,measure
    from native_audit_preparation import active_sdk_input
    with tempfile.TemporaryDirectory(prefix='fleetory-publication-namespace-') as temp:
        root=Path(temp).resolve();public=root/'public-input';publication=None
        if real:
            from native_probe_image import publication as publish
            public.mkdir()
            with active_sdk_input():publication=publish(public)
            source=Path(publication['published']) if 'published' in publication else public/'publish'
            raw=ns.bundle.prep.canonical(publication['bundle'])
        else:
            public_files(public);source=public;raw=ns.bundle.prep.canonical(measure(source))
        with ns.bundle.HeldProbeBundle(source,raw,packet.digest(raw)) as held:
            cases=('positive',) if real else ('positive','bad-manifest','owner-exit')
            outcomes=[]
            for case in cases:
                directory=root/case;directory.mkdir();outcomes.append(handoff(directory,held,case))
    packet.require(not root.exists())
    return dict(schema='fleetory.publication-namespace-fixture.v1',verified=True,realPublicBuild=real,cases=outcomes,
        publication=publication,ownPublicFixtureDisposed=True,actualNativePublicationVerified=False,historicalPowerShellOwnerIntegrated=False,
        backendServicesStarted=0,backendCleanupAuthorized=False,originalInputsRead=False,originalPrivatePkiUsed=False,
        sourceVpsAccessed=False,fullSystemRecoveryVerified=False,phase7Complete=False)


if __name__=='__main__':
    try:
        if len(sys.argv)==3 and sys.argv[1]=='--worker':sys.exit(worker(sys.argv[2]) or 0)
        else:
            packet.require(sys.argv[1:] in ([],['--real-public']))
            print('PUBLICATION NAMESPACE PASS: '+json.dumps(run(bool(sys.argv[1:])),sort_keys=True))
    except Exception:
        if '--worker' in sys.argv:
            print('Public namespace fixture worker refused.',file=sys.stderr);sys.exit(1)
        raise
