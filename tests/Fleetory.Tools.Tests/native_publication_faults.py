"""Actual public native publisher failures; no private material, backend, image or operational lease."""
from contextlib import ExitStack
import copy
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import time
import uuid
from unittest.mock import patch

import native_publication as public
from native_public_probe_faults import PublicCopy
from historical_audit_restore_tests import fixture
from native_audit_preparation import active_sdk_input,claim_plan,sha,REPO
from private_runtime_fixture import private_git,private_powershell,private_dotnet,windows_git_core
import publication_child_observer as observer

policy=public.policy
packet=policy.packet
CASES=('owner-before-publish','owner-during-publish','corrupt-receipt')
FORBIDDEN=('publication-owner-ack.json','native-publication-receipt.json','publication-release.json','native-close.json')
FACTS='reached ownerKilled liveOwnerObserved compilerObserved compilerExited nativeBytesObserved receiptCorrupted fileBindingPresent'.split()


def classify_fault(evidence,case,facts):
    packet.require(case in CASES);packet.keys(facts,' '.join(FACTS))
    expected=dict(reached=True,ownerKilled=case!='corrupt-receipt',liveOwnerObserved=True,
        compilerObserved=case=='owner-during-publish',compilerExited=case=='owner-during-publish',
        nativeBytesObserved=case=='corrupt-receipt',receiptCorrupted=case=='corrupt-receipt',fileBindingPresent=case=='corrupt-receipt')
    packet.require(all(facts[key] is value for key,value in expected.items()))
    packet.require(evidence['profile']=='native-publication' and evidence['launchAttemptConsumed'] is True and
        evidence['processIdentityAuthenticated'] is True and evidence['entrypointPinsMatched'] is True and
        evidence['fence']['noRunningMembersVerified'] is True)
    value=evidence['payload']
    packet.require(type(value['selectedSourceFilesPinned']) is int and value['selectedSourceFilesPinned']==36 and value['refusalStage'] is None)
    for key in ('actualNativePublicationVerified','namespaceHandoffVerified','nativeReadinessBound','dotnetExecutablePinned',
            'compilerClosureAuthenticated','namespaceRemoved','privateInputsAccepted','backendCreated','backendCleanupAuthorized',
            'operationalLeaseAuthorized','originalInputsRead','originalPrivatePkiUsed','sourceVpsAccessed','fullSystemRecoveryVerified','phase7Complete'):
        packet.require(value[key] is False)
    return dict(case=case,**facts,actualOwnerIdentityVerified=True,launchAttemptConsumed=True,ownedProcessMembersAbsent=True,
        interruptedPublicationNotAccepted=True,controllerAckAndReleaseAbsent=True,controllerDeathCleanupVerified=False)


class Fault:
    def __init__(self,case):
        packet.require(case in CASES)
        self.case=case;self.facts=dict.fromkeys(FACTS,False)
        self.child=None;self.child_record=None;self.owner=None;self.process=None
        self.original_receipt_pin=None;self.injected_receipt_pin=None

    def observe_owner(self,pump):
        identity=pump.fence.identity(pump.process,pump.command.executable)
        packet.require(self.owner is None or self.owner==identity)
        self.owner=identity;self.process=pump.process
        self.facts['liveOwnerObserved']=True

    def kill(self,pump):
        self.observe_owner(pump)
        if self.child is not None:self.child.check_alive()
        pump.process.kill();self.facts.update(ownerKilled=True,reached=True)
        raise ValueError('Injected public native owner death.')

    def send(self,original,pump,value):
        if value.get('decision')!='publish' or self.case=='corrupt-receipt':
            return original(pump,value)
        pump.bound.check()
        packet.require(not any(pump.bound.output.path.iterdir()) and not any(n in pump.session._records for n in FORBIDDEN))
        if self.case=='owner-before-publish':self.kill(pump)
        preexisting=observer.find_dotnet(pump)
        if preexisting is not None:
            preexisting.close();raise AssertionError('Unexpected dotnet child before publication authorization.')
        original(pump,value)
        end=time.monotonic_ns()+10_000_000_000
        while time.monotonic_ns()<end:
            policy.process._check_deadline(pump.start_time,pump.seconds)
            packet.require(not pump.errors and not pump.stopping.is_set())
            found=observer.find_dotnet(pump)
            if found is not None:
                self.child=found;self.child_record=found.report();self.facts['compilerObserved']=True
                self.kill(pump)
            time.sleep(0.005)
        raise AssertionError('Actual owned dotnet publisher was not observed; injection not reached.')

    def accept(self,original,pump,value,raw):
        if len(pump.frames)!=2:return original(pump,value,raw)
        # In the owner-death case, a too-fast publication must not turn a missed injection into success.
        if self.case!='corrupt-receipt':
            raise ValueError('Publication completed before expected live compiler observation.')
        self.observe_owner(pump);packet.require(not any(n in pump.session._records for n in FORBIDDEN))
        packet.require(value['pid']==pump.process.pid and value['headerSha256']==pump.info['headerSha256'] and
            value['dotnetSha256']==pump.command.dotnet.digest and value['readySha256']==pump.ready_pin)
        with policy.ns.bundle.HeldProbeBundle(pump.bound.output.path,pump.manifest,packet.digest(pump.manifest)) as held:
            packet.require(value['receipt']['bundleSha256']==held.value['sha256'] and
                value['receipt']['files']==len(held.pins)==58 and value['receipt']['bytes']==held.value['bytes'])
            self.facts['nativeBytesObserved']=True
        self.original_receipt_pin=packet.digest(raw)
        altered=copy.deepcopy(value);altered['receipt']['bundleSha256']='0'*64
        changed=policy.prep.canonical(altered);self.injected_receipt_pin=packet.digest(changed)
        packet.require(self.original_receipt_pin!=self.injected_receipt_pin)
        self.facts.update(reached=True,receiptCorrupted=True)
        return original(pump,altered,changed)

    def finish(self,evidence,session,error):
        packet.require(error.category in ('native-publication-handoff-refused','output-io','payload-binding-unverified'))
        packet.require(self.process is not None and type(self.process.returncode) is int and self.process.returncode!=0)
        packet.require(self.owner==evidence['osIdentity'] and not any(n in session._records for n in FORBIDDEN))
        self.facts['fileBindingPresent']='publication-binding.json' in session._records
        if self.child is not None:
            packet.require(self.child.exited());self.facts['compilerExited']=True
        outcome=classify_fault(evidence,self.case,self.facts)
        outcome.update(actualOwnedProcess=self.owner,nativeOwnerExitCode=self.process.returncode,compilerChild=self.child_record,
            nativeFrameBeforeInjectionSha256=self.original_receipt_pin,injectedFrameSha256=self.injected_receipt_pin)
        if self.facts['fileBindingPresent']:
            record=json.loads(session._records['publication-binding.json'][1])
            packet.require(record['fileDescriptorsHeld']==58 and record['actualOwnedProcess']==self.owner)
            outcome['fileDescriptorsHeldBeforeRefusal']=record['fileDescriptorsHeld']
        else:outcome['fileDescriptorsHeldBeforeRefusal']=0
        return outcome

    def close(self):
        if self.child is not None:self.child.close()


def run():
    powershell=Path(shutil.which('pwsh') or '').resolve(strict=True);python=Path(sys.executable).resolve(strict=True)
    git=Path(shutil.which('git') or '').resolve(strict=True);dotnet=Path(shutil.which('dotnet') or '').resolve(strict=True)
    if os.name=='nt':git=windows_git_core(git)
    root=Path(tempfile.mkdtemp(prefix='fleetory-public-publication-fault-')).resolve()
    # Keep unknown/failed outcomes for diagnosis. Only full success disposes this whole own public copy.
    with ExitStack() as held:
        copied=PublicCopy(git,REPO,root);repository=copied.directory
        powershell=private_powershell(powershell,root);git=private_git(git,root);dotnet=private_dotnet(dotnet,root)
        held.enter_context(public.public_sdk_environment(dotnet));held.enter_context(active_sdk_input(repository))
        with patch.object(public,'REPO',repository):public.restore_public(dotnet)
        reference=root/'reference';reference.mkdir();published=public.publication(reference,repository=repository)
        packet.require(published['sdkVersion']==policy.SDK and published['dotnetSha256']==sha(dotnet))
        artifacts=repository/'artifacts';artifacts.mkdir(mode=0o700)
        sentinel=artifacts/'foreign-public-sentinel';sentinel.mkdir();(sentinel/'keep.txt').write_bytes(b'UNRELATED_PUBLIC_FIXTURE')
        before=(sentinel/'keep.txt').read_bytes();manifest=policy.prep.canonical(published['bundle'])
        pins=policy.measure_sources(repository);outcomes=[]
        for case in CASES:
            plan,_=fixture();plan.update(nonce=str(uuid.uuid4()),revision=published['source']['revision'],codeSha256=published['source']['sha256'],
                probeBundleSha256=published['bundle']['sha256'],probeSha256=next(e['sha256'] for e in published['bundle']['entries'] if e['path']=='ServerBackendProbe.dll'))
            raw,claimed=claim_plan(root,plan,powershell,python);fault=Fault(case)
            with claimed as session:
                send=policy._NativePublicationPumps._send_frame;accept=policy._NativePublicationPumps._accept_frame
                try:
                    with patch.object(policy._NativePublicationPumps,'_send_frame',lambda pump,v:fault.send(send,pump,v)),\
                            patch.object(policy._NativePublicationPumps,'_accept_frame',lambda pump,v,r:fault.accept(accept,pump,v,r)):
                        try:policy.publish_owner(repository,powershell,python,git,dotnet,raw,pins,session,
                            git_sha256=sha(git),dotnet_sha256=sha(dotnet),manifest=manifest)
                        except policy.process.LaunchError as error:
                            evidence=json.loads(error.evidence)
                            if not fault.facts['reached']:print('PUBLICATION FAULT NOT REACHED: '+json.dumps(dict(case=case,evidence=evidence),sort_keys=True),file=sys.stderr)
                            outcome=fault.finish(evidence,session,error)
                        else:raise AssertionError('Injected publication fault was accepted.')
                    path=artifacts/policy.ns.name(plan['nonce'])
                    with policy.control.DirectoryLease(path) as directory:
                        packet.require(set(os.listdir(path))=={policy.ns.MARKER,policy.ns.OUTPUT})
                        marker=json.loads((path/policy.ns.MARKER).read_bytes())
                        packet.require(marker['ownerPid']==fault.owner['pid'] and marker['nonce']==plan['nonce'] and
                            marker['namespaceDirectorySha256']==policy.ns.empty.directory_hash(directory))
                    replay=False
                    try:session.consume_launch_attempt()
                    except ValueError:replay=True
                    packet.require(replay and (sentinel/'keep.txt').read_bytes()==before and policy.measure_sources(repository)==pins)
                    outcome.update(consumedLaunchReplayRefused=True,failedNamespacePreservedBeforeFixtureDisposal=True,
                        unrelatedSentinelPreserved=True,namespaceNonce=plan['nonce'],controlRecords=sorted(session._records))
                    outcomes.append(outcome);print('NATIVE PUBLICATION FAULT CASE PASS: '+case,flush=True)
                finally:fault.close()
        copied.check()
        tree=copied.tree_id;revision=copied.revision
    packet.require(root.is_absolute() and root.name.startswith('fleetory-public-publication-fault-') and repository.parent==root)
    def readonly_file(function,path,error):
        target=Path(path)
        packet.require(os.name=='nt' and isinstance(error,PermissionError) and target.is_relative_to(root) and
            policy.ns.files.regular_single_file(target.lstat()))
        target.chmod(0o600);function(path)
    shutil.rmtree(root,onexc=readonly_file);packet.require(not root.exists())
    return dict(schema='fleetory.generated-native-publication-faults.v1',verified=True,cases=outcomes,
        referencePublication=published,revision=revision,tree=tree,selectedSourceFilesPinned=36,nativeSeconds=30,
        ownPublicFixtureDisposed=True,actualCompilerChildObservedAndExited=True,compilerChildObservationSource='owned Job or process group plus held process handle/pidfd and pinned dotnet image',
        controllerDeathCleanupVerified=False,operationalLeaseAuthorized=False,nativeImageBuildVerified=False,
        backendServicesStarted=0,originalInputsRead=False,originalPrivatePkiUsed=False,sourceVpsAccessed=False,fullSystemRecoveryVerified=False,phase7Complete=False)


if __name__=='__main__':print('NATIVE PUBLICATION FAULTS PASS: '+json.dumps(run(),sort_keys=True))
