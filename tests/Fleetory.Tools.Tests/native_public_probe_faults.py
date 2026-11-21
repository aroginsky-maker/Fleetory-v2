"""Real public probe owner-fault cleanup on a bounded disposable copy of one public Git commit."""
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import uuid
from unittest.mock import patch

from native_public_probe_receipt import NativeReceiptFixture, policy
from native_probe_image import run as build_probe
from native_audit_preparation import active_sdk_input, sha, REPO
from native_audit_resource_binding import NativeBinding, binding, control, control_plan
from private_runtime_fixture import private_git, private_powershell, windows_git_core

packet=policy.packet
CASES=('bad-offer','owner-exit')
MAX_TREE=262144
MAX_FILES=2048
MAX_FILE=4*1024**2
MAX_BYTES=64*1024**2


def public_tree(data):
    packet.require(type(data) is bytes and 0<len(data)<=MAX_TREE and data.endswith(b'\0'))
    rows=data[:-1].split(b'\0');packet.require(0<len(rows)<=MAX_FILES)
    result,aliases,directories={},set(),{}
    for row in rows:
        metadata,name=row.split(b'\t',1);mode,kind,oid,size=metadata.split()
        path=name.decode('ascii');parts=path.split('/')
        packet.require(mode in (b'100644',b'100755') and kind==b'blob' and re.fullmatch(b'[a-f0-9]{40}',oid) is not None)
        packet.require(size.isdigit() and str(int(size)).encode()==size and 0<=int(size)<=MAX_FILE and 0<len(path)<=240 and len(parts)<=16)
        packet.require(all(re.fullmatch('[A-Za-z0-9_.-]{1,128}',p) and p not in ('.','..') and p.casefold()!='.git' and
            not p.endswith('.') and p.split('.')[0].upper() not in ('CON','PRN','AUX','NUL',*[f'COM{i}' for i in range(1,10)],*[f'LPT{i}' for i in range(1,10)]) for p in parts))
        packet.require(path.casefold() not in aliases);aliases.add(path.casefold())
        for i in range(1,len(parts)):
            parent='/'.join(parts[:i]);key=parent.casefold()
            packet.require(key not in directories or directories[key]==parent);directories[key]=parent
        result[path]=dict(mode=mode.decode(),oid=oid.decode(),bytes=int(size))
    packet.require(not (aliases & set(directories)) and sum(v['bytes'] for v in result.values())<=MAX_BYTES)
    return result


def classify_fault(evidence,case,reached,live_kill=False):
    packet.require(case in CASES and reached is True and evidence['launchAttemptConsumed'] is True and
        evidence['processIdentityAuthenticated'] is True and evidence['fence']['noRunningMembersVerified'] is True)
    packet.require(live_kill is (case=='owner-exit'))
    value=evidence['payload'];packet.require(value['selectedSourceFilesPinned']==45 and value['emptyPayloadRemovedVerified'] is False)
    for key in ('nativeOwnerResourceAcknowledged','actualProbeNativeOwnerAcknowledged','actualProbeNativeBuildCreateVerified',
            'operationalLeaseAuthorized','runtimeContinuityVerified','backendCreated','backendNamespaceBound','privateInputsAccepted',
            'backendControlAuthorized','backendCleanupAuthorized','originalInputsRead','originalPrivatePkiUsed','fullSystemRecoveryVerified','phase7Complete'):
        packet.require(value[key] is False)
    if case=='bad-offer':packet.require(value['refusalStage']=='resources')
    return dict(case=case,expectedInjectionReached=True,launchAttemptConsumed=True,actualOwnerIdentityVerified=True,
        ownedProcessMembersAbsent=True,invalidOrInterruptedNativeAckNotAccepted=True,nativeOwnerObservedAliveBeforeKill=live_kill)


class PublicCopy:
    def __init__(self,git,source,root):
        self.git,self.source,self.root=git,source,root
        self.directory=root/'repository';self.empty=root/'empty-git-config';self.empty.write_bytes(b'')
        self.template=root/'empty-git-template';self.template.mkdir(mode=0o700)
        self.environment={k:v for k,v in os.environ.items() if not k.startswith('GIT_')}
        self.environment.update(GIT_CONFIG_NOSYSTEM='1',GIT_CONFIG_GLOBAL=str(self.empty),GIT_ALLOW_PROTOCOL='file',GIT_TERMINAL_PROMPT='0')
        self.revision=self.command(['-C',str(source),'rev-parse','HEAD']).decode().strip()
        packet.require(re.fullmatch('[a-f0-9]{40}',self.revision) is not None)
        self.tree_id=self.command(['-C',str(source),'rev-parse','HEAD^{tree}']).decode().strip()
        packet.require(re.fullmatch('[a-f0-9]{40}',self.tree_id) is not None)
        self.entries=public_tree(self.command(['-C',str(source),'ls-tree','-rlz',self.revision]))
        for path in self.entries:
            if path.endswith('.gitattributes'):
                packet.require(self.command(['-C',str(source),'show',self.revision+':'+path]).strip()==b'* text eol=lf')
        packet.require(not self.directory.exists() and self.directory.parent==root and self.directory.name=='repository')
        self.command(['init','--quiet','--template='+str(self.template),str(self.directory)])
        packet.require(set(p.name for p in self.directory.iterdir())=={'.git'})
        self.command(['-C',str(self.directory),'fetch','--quiet','--no-tags','--depth=1',str(source),self.revision])
        self.command(['-C',str(self.directory),'checkout','--quiet','--detach',self.revision])
        packet.require(self.command(['-C',str(self.directory),'rev-parse','HEAD^{tree}']).decode().strip()==self.tree_id and
            self.command(['-C',str(self.directory),'rev-list','--count','HEAD']).strip()==b'1')
        self.check()

    def command(self,args):
        command=[str(self.git),'-c','core.autocrlf=false','-c','core.attributesFile='+str(self.empty),
            '-c','core.hooksPath='+str(self.template),'-c','protocol.allow=never','-c','protocol.file.allow=always',*args]
        result=subprocess.run(command,capture_output=True,timeout=30,env=self.environment)
        packet.require(result.returncode==0 and len(result.stdout)<=MAX_TREE and len(result.stderr)<=4096)
        return result.stdout

    def check(self):
        packet.require(self.directory.resolve(strict=True)==self.root/'repository' and
            self.command(['-C',str(self.directory),'rev-parse','HEAD']).decode().strip()==self.revision)
        for name,item in self.entries.items():
            path=self.directory/name
            for parent in path.relative_to(self.directory).parents:
                policy.prep.files.ordinary_directory(self.directory/parent)
            packet.require(policy.prep.files.regular_single_file(path.lstat()))
            with path.open('rb') as stream:data=stream.read(item['bytes']+1)
            packet.require(len(data)==item['bytes'] and hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data,usedforsecurity=False).hexdigest()==item['oid'])

    def restore(self):
        with active_sdk_input(self.directory):
            result=subprocess.run(['dotnet','restore',str(self.directory/'eng/ServerBackendProbe/ServerBackendProbe.csproj'),
                '--disable-parallel','--configfile',str(self.directory/'NuGet.Config'),'--verbosity','quiet'],
                cwd=self.directory,capture_output=True,timeout=180)
            packet.require(result.returncode==0 and len(result.stdout)<=262144 and len(result.stderr)<=4096)
        self.check()


class ExpectedPublicFault(RuntimeError):
    pass


class FaultFixture(NativeReceiptFixture):
    expected_sleep_workers=1
    def __init__(self,powershell,python,git,repository,case):
        super().__init__(powershell,python,git,repository)
        packet.require(case in CASES);self.case=case;self.injected=False;self.live_kill=False;self.outcome=None;self.image_id=None;self.reservation=None

    def on_bound(self,session,source,target):
        self.image_id=source.report()['imageId'];self.reservation=source.intent['controlSha256']
        publication=dict(sourceRevision=session._plan['revision'],codeSnapshotSha256=session._plan['codeSha256'],
            probeSha256=session._plan['probeSha256'],imageId=self.image_id,bundleManifestSha256=source.intent['bundleManifestSha256'],
            bundleSha256=source.intent['bundleSha256'],files=source.intent['bundleFiles'],bytes=source.intent['bundleBytes'],
            contextSha256=source.intent['contextSha256'],contextBytes=source.intent['contextBytes'],runtimeProfileSha256=target.intent['runtimeProfileSha256'])
        original_send=policy._NativeProbePumps._send;original_wait=policy._NativeProbePumps._wait
        def send(pump,data):
            value=json.loads(data)
            if self.case=='bad-offer' and value.get('schema')==policy.OFFER_SCHEMA:
                self.injected=True;value.update(decision='restore-private-data',archiveBase64='GENERATED_REFUSED_BODY')
                changed=policy.prep.canonical(value)+b'\n';pump.expected_input_bytes+=len(changed)-len(data);data=changed
            return original_send(pump,data)
        def wait(pump,event):
            original_wait(pump,event)
            if self.case=='owner-exit' and event is pump.resource_ack:
                packet.require(pump.process.poll() is None and pump.resource_ack.is_set())
                self.live_kill=True;self.injected=True;pump.process.kill();raise ValueError('Generated public native owner exit after receipt ACK.')
        with patch.object(policy._NativeProbePumps,'_send',send),patch.object(policy._NativeProbePumps,'_wait',wait):
            try:self.exchange(session,source,target)
            except policy.process.LaunchError as error:
                evidence=json.loads(error.evidence)
                if not self.injected:
                    print('PUBLIC FAULT PRE-INJECTION DIAGNOSTIC: '+json.dumps(dict(case=self.case,reason=str(error),payload=evidence.get('payload'),processIdentityAuthenticated=evidence.get('processIdentityAuthenticated'),fence=evidence.get('fence')),sort_keys=True),file=sys.stderr)
                self.outcome=classify_fault(evidence,self.case,self.injected,self.live_kill)
            else:raise AssertionError('Expected public native fault was accepted.')
        packet.require(('native-resource-ack.json' in session._records)==(self.case=='owner-exit'))
        path=self.repository/'artifacts'/policy.payload.binding.payload_name(session._plan['nonce'])
        packet.require(path.is_dir() and set(os.listdir(path))=={policy.payload.binding.MARKER})
        packet.require(sha(path/policy.payload.binding.MARKER)==json.loads(session._records['payload-binding.json'][1])['ownerSha256'])
        with patch.object(policy.process,'_spawn') as spawn:
            refused=False
            try:self.exchange(session,source,target)
            except ValueError:refused=True
            packet.require(refused);spawn.assert_not_called()
        source.report();target.report()
        self.outcome.update(publication=publication,runtimeContainerId=self.receipts[0][0],unknownNativeReservationPreserved=True,sourceReceiptRecordsUnchanged=True,
            consumedNativeLaunchReplayRefused=True,sharedAdmissionStillValid=True)
        raise ExpectedPublicFault(self.case)


class StoppedSentinel(NativeBinding):
    def arguments(self,intent):
        args=super().arguments(intent);args[0]='create';args.remove('-d');args.remove('--rm');return args


def operator_state(git):
    values=[]
    for args in (['rev-parse','HEAD'],['status','--porcelain'],['diff','--binary','HEAD']):
        result=subprocess.run([str(git),'-C',str(REPO),*args],capture_output=True,timeout=15)
        packet.require(result.returncode==0 and len(result.stdout)<=2*1024**2);values.append(result.stdout)
    return packet.digest(b'\0'.join(values))


def run(callback_factory=FaultFixture,cases=CASES):
    packet.require(type(cases) is tuple and len(cases)==2 and len(set(cases))==2)
    powershell=Path(shutil.which('pwsh') or '').resolve(strict=True);python=Path(sys.executable).resolve(strict=True)
    git=Path(shutil.which('git') or '').resolve(strict=True)
    if os.name=='nt':git=windows_git_core(git)
    copy_git=git
    original=operator_state(git);global_path=REPO/'global.json';global_before=global_path.read_bytes() if global_path.exists() else None
    outcomes=[];workers=0;sentinel=StoppedSentinel();version=sentinel.preflight()
    with tempfile.TemporaryDirectory(prefix='fleetory-public-probe-native-faults-') as temp,ExitStack() as held:
        root=Path(temp).resolve();held.enter_context(policy.prep.control.DirectoryLease(root))
        powershell=private_powershell(powershell,root);git=private_git(git,root)
        copied=PublicCopy(copy_git,REPO,root);copied.restore()
        artifacts=copied.directory/'artifacts';packet.require(not artifacts.exists());artifacts.mkdir(mode=0o700)
        controls=root/'sentinel-control';controls.mkdir(mode=0o700)
        raw=binding.canonical(control_plan(str(uuid.uuid4())));session=held.enter_context(control.claim(controls,raw,packet.digest(raw)))
        base_id=sentinel.call(['image','inspect','--format','{{.Id}}',binding.IMAGE]).decode().strip();binding.image_id(base_id)
        intent=json.loads(binding.prepare(session,base_id));foreign=sentinel.create(intent);before=sentinel.observed(foreign)
        try:
            for case in cases:
                callback=callback_factory(powershell,python,git,copied.directory,case)
                try:build_probe(runtime_check=callback,control_factory=callback.control,repository=copied.directory)
                except ExpectedPublicFault as error:packet.require(str(error)==case)
                else:raise AssertionError('Expected public native fault was not reached.')
                count=callback.expected_sleep_workers
                packet.require(type(count) is int and count in (0,1) and callback.outcome is not None and len(callback.receipts)==count)
                packet.require(all(callback.listed_id(identifier)==[] for identifier,_ in callback.receipts))
                workers+=count
                selected=sentinel.call(['image','ls','-a','--no-trunc','--filter','label=fleetory.audit.control.reservation='+callback.reservation,'--format','{{.ID}}']).decode().split()
                packet.require(callback.image_id not in selected and sentinel.observed(foreign)==before)
                copied.check()
                callback.outcome.update(ownedSleepWorkerAbsent=True,ownedImageReceiptAbsent=True,stoppedCopyAndBaseCleanupChecksCompleted=True,
                    foreignStoppedSentinelPreserved=True,publicGitTreeUnchanged=True)
                outcomes.append(callback.outcome)
                print('PUBLIC PROBE OWNER FAULT CASE PASS: '+case,flush=True)
        finally:sentinel.cleanup()
        packet.require(sentinel.listed_id(foreign)==[] and copied.directory.is_relative_to(root))
        public_facts=dict(revision=copied.revision,tree=copied.tree_id,files=len(copied.entries),bytes=sum(v['bytes'] for v in copied.entries.values()),singleCommitCopy=True,allTrackedBlobBytesMatched=True,gitNetworkProtocolsDisabled=True,softwareOriginAuthenticated=False,gitProcessIdentityAuthenticated=False)
    packet.require(not root.exists() and operator_state(Path(shutil.which('git')).resolve())==original)
    packet.require((global_path.read_bytes() if global_path.exists() else None)==global_before)
    return dict(schema='fleetory.generated-public-probe-owner-faults.v1',verified=True,dockerVersion=version,cases=outcomes,
        publicCopy=public_facts,actualNativeOwnerCases=2,actualNativeOwnerKills=sum(v['nativeOwnerObservedAliveBeforeKill'] for v in outcomes),typedOfferRefusals=1,
        publicProbeImagesBuilt=2,ownStoppedReadbackContainers=2,ownSleepWorkers=workers,foreignStoppedSentinels=1,
        ownPublicFixtureDisposed=True,operatorCheckoutAndRefUnchanged=True,operatorSdkInputUnchanged=True,
        publicReceiptFixtureOwnerFaultCleanupVerified=True,cleanupActor='trusted-fixture-parent',
        backendServicesStarted=0,actualProbeNativeBuildCreateVerified=False,operationalLeaseAuthorized=False,
        backendCleanupAuthorized=False,abruptOwnerDeathBackendCleanupVerified=False,intermediateBuildCacheCleanupVerified=False,
        originalInputsRead=False,originalPrivatePkiUsed=False,sourceVpsAccessed=False,fullSystemRecoveryVerified=False,phase7Complete=False)


if __name__=='__main__':
    packet.require(len(sys.argv)==1)
    print('PUBLIC PROBE OWNER FAULTS PASS: '+json.dumps(run(),sort_keys=True))
