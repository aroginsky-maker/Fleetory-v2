"""Actual generated native-create refusal and owner death after durable create receipt, before ACK."""
import json
from pathlib import Path
import shutil
import sys
import time
from unittest.mock import patch

from native_public_probe_create import NativeCreateFixture, native_create_receipt, policy, packet, runtime
from native_public_probe_faults import run as shared_run, ExpectedPublicFault
from native_audit_preparation import sha

CASES=('bad-create','owner-exit')


def classify_fault(evidence,case,reached,live_kill,has_receipt):
    packet.require(case in CASES and reached is True and live_kill is (case=='owner-exit') and has_receipt is (case=='owner-exit'))
    packet.require(evidence['launchAttemptConsumed'] is True and evidence['processIdentityAuthenticated'] is True and
        evidence['fence']['noRunningMembersVerified'] is True)
    value=evidence['payload']
    packet.require(value['selectedSourceFilesPinned']==46 and value['emptyReservationObserved'] is True and value['emptyPayloadRemovedVerified'] is False)
    for key in ('nativeOwnerResourceAcknowledged','actualProbeNativeOwnerAcknowledged','actualNativeContainerCreateVerified',
            'actualProbeNativeBuildCreateVerified','nativePublicationBuildVerified','nativeCreatePreReceiptCrashGapVerified',
            'controllerDeathCleanupVerified','operationalLeaseAuthorized','runtimeContinuityVerified','backendCreated','backendNamespaceBound',
            'privateInputsAccepted','backendControlAuthorized','backendCleanupAuthorized','originalInputsRead','originalPrivatePkiUsed',
            'fullSystemRecoveryVerified','phase7Complete'):
        packet.require(value[key] is False)
    packet.require(value['refusalStage']==('create' if case=='bad-create' else None))
    return dict(case=case,expectedInjectionReached=True,actualOwnerIdentityVerified=True,launchAttemptConsumed=True,
        ownedProcessMembersAbsent=True,invalidOrInterruptedNativeResultNotAccepted=True,nativeOwnerObservedAliveBeforeKill=live_kill,
        durableNativeCreateReceiptPresent=has_receipt,nativeReceiptAckAbsent=True)


class NativeCreateFaultFixture(NativeCreateFixture):
    def __init__(self,powershell,python,git,repository,case):
        super().__init__(powershell,python,git,repository)
        packet.require(case in CASES)
        self.case=case;self.injected=False;self.live_kill=False;self.outcome=None;self.created_receipt=None
        self.image_id=None;self.reservation=None

    @property
    def expected_sleep_workers(self):
        return 1 if self.case=='owner-exit' else 0

    def __call__(self,session,source,fresh_session):
        raw=runtime.prepare(session,source)
        target=runtime.ProbeRuntimeBinding(session,raw,packet.digest(raw),source)
        self.image_id=source.report()['imageId'];self.reservation=source.intent['controlSha256']
        publication=dict(sourceRevision=session._plan['revision'],codeSnapshotSha256=session._plan['codeSha256'],
            probeSha256=session._plan['probeSha256'],imageId=self.image_id,bundleManifestSha256=source.intent['bundleManifestSha256'],
            bundleSha256=source.intent['bundleSha256'],files=source.intent['bundleFiles'],bytes=source.intent['bundleBytes'],
            contextSha256=source.intent['contextSha256'],contextBytes=source.intent['contextBytes'],runtimeProfileSha256=runtime.PROFILE_SHA256)
        image_record=session._records['image-binding.json'][1]
        pins=policy.measure_sources(self.repository);docker=Path(shutil.which('docker') or '').resolve(strict=True)
        packet.require(not self.receipts and not self.by_name(target.intent['name']))
        original_send=policy._NativeCreatePumps._send;original_wait=policy._NativeCreatePumps._wait
        def send(pump,data):
            value=json.loads(data)
            if self.case=='bad-create' and value.get('schema')==policy.CREATE_SCHEMA:
                packet.require(not self.injected and target._bound is None and 'native-probe-create-binding.json' not in session._records)
                value.update(decision='create-with-private-inputs',privateInputRequested=True)
                changed=policy.prep.canonical(value)+b'\n';pump.expected_input_bytes+=len(changed)-len(data);data=changed;self.injected=True
            return original_send(pump,data)
        def wait(pump,event):
            original_wait(pump,event)
            if self.case=='owner-exit' and event is pump.created_event:
                packet.require(pump.process.poll() is None and event.is_set() and 'native-resource-intent.json' not in session._records and
                    'native-resource-ack.json' not in session._records)
                saved=native_create_receipt(session,target)
                packet.require(saved['actualOwnedProcess']==pump.fence.identity(pump.process,pump.command.executable))
                self.created_receipt=saved;self.live_kill=True;self.injected=True
                pump.process.kill();raise ValueError('Generated native owner exit after durable create receipt before ACK.')
        def exchange():
            return policy.create_owner(self.repository,self.powershell,self.python,self.git,self.plans[session._plan['nonce']],pins,
                session,(source,target),git_sha256=sha(self.git),docker=docker,docker_sha256=sha(docker))
        try:
            with patch.object(policy._NativeCreatePumps,'_send',send),patch.object(policy._NativeCreatePumps,'_wait',wait):
                try:exchange()
                except policy.process.LaunchError as error:
                    evidence=json.loads(error.evidence)
                    if not self.injected:
                        print('NATIVE CREATE FAULT PRE-INJECTION DIAGNOSTIC: '+json.dumps(dict(case=self.case,payload=evidence.get('payload'),reason=str(error)),sort_keys=True),file=sys.stderr)
                    self.outcome=classify_fault(evidence,self.case,self.injected,self.live_kill,'native-probe-create-binding.json' in session._records)
                else:raise AssertionError('Expected native create fault was accepted.')
            packet.require('native-resource-intent.json' not in session._records and 'native-resource-ack.json' not in session._records)
            if self.case=='bad-create':
                packet.require(not target._attempted and target._bound is None and 'backend-binding-attempt.json' not in session._records and
                    'backend-binding.json' not in session._records and not self.by_name(target.intent['name']))
                self.outcome.update(nativeCreatedSleepWorkers=0,noWorkerCreatedOnMalformedOffer=True,workerSurvivedOwnerDeath=False,nativeCreateReceipt=None)
            else:
                saved=native_create_receipt(session,target);packet.require(saved==self.created_receipt)
                identifier=saved['receipt']['containerId'];observed=self.observed(identifier)
                runtime.ProbeRuntimeBinding._observe(runtime.container.canonical(observed),target.intent,identifier,time.time_ns())
                packet.require(observed['running'] is True and self.listed_id(identifier)==[identifier])
                self.outcome.update(nativeCreatedSleepWorkers=1,noWorkerCreatedOnMalformedOffer=False,workerSurvivedOwnerDeath=True,
                    nativeCreateReceipt=saved,runtimeContainerId=identifier)
            path=self.repository/'artifacts'/policy.payload.binding.payload_name(session._plan['nonce'])
            with policy.prep.control.DirectoryLease(path) as directory:
                packet.require(set(policy.payload.os.listdir(path))=={policy.payload.binding.MARKER})
                digest,_,_=policy.prep.files.inspect_file(directory.path,directory.fd,policy.payload.binding.MARKER,4096)
                packet.require(digest==json.loads(session._records['payload-binding.json'][1])['ownerSha256'])
            with patch.object(policy.process,'_spawn') as spawn:
                refused=False
                try:exchange()
                except ValueError:refused=True
                packet.require(refused);spawn.assert_not_called()
            packet.require(session._records['image-binding.json'][1]==image_record and policy.measure_sources(self.repository)==pins)
            source.report()
            self.outcome.update(publication=publication,unknownNativeReservationPreserved=True,sourceReceiptRecordsUnchanged=True,
                consumedNativeLaunchReplayRefused=True,sharedAdmissionStillValid=True,sourceFilesHeld=46)
        finally:
            # A failure without a durable native receipt grants no resource adoption.
            if 'native-probe-create-binding.json' in session._records:
                saved=native_create_receipt(session,target)
                self.receipts.append((saved['receipt']['containerId'],target.intent))
            self.cleanup()
        raise ExpectedPublicFault(self.case)

    def by_name(self,name):
        packet.require(type(name) is str and policy.re.fullmatch('fleetory-probe-runtime-[a-f0-9]{32}',name))
        return self.call(['container','ls','-a','--no-trunc','--filter','name=^/'+name+'$','--format','{{.ID}}']).decode().split()


def run():
    result=shared_run(NativeCreateFaultFixture,CASES)
    result.pop('publicReceiptFixtureOwnerFaultCleanupVerified')
    result.update(schema='fleetory.generated-public-native-create-faults.v1',nativeCreateFaultCleanupVerified=True,
        malformedCreateOfferRefusals=1,nativeCreatedSleepWorkers=1,fixturePrecreatedSleepWorkers=0,
        nativeOwnerKillsAfterCreateBeforeAck=1,cleanupActor='trusted-fixture-parent-from-native-create-receipt',
        preReceiptCrashGapVerified=False,controllerDeathCleanupVerified=False,nativePublicationBuildVerified=False)
    packet.require(result['ownSleepWorkers']==1 and result['actualNativeOwnerKills']==1)
    return result


if __name__=='__main__':
    packet.require(len(sys.argv)==1)
    print('PUBLIC NATIVE CREATE FAULTS PASS: '+json.dumps(run(),sort_keys=True))
