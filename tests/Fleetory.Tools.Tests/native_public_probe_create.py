"""Actual fenced native public container production, parent binding and receipt-only fixture cleanup."""
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile

from audit_native_create_tests import policy, packet, runtime
from native_public_probe_receipt import NativeReceiptFixture
from native_probe_image import run as build_probe
from native_audit_preparation import sha, REPO
from private_runtime_fixture import private_git, private_powershell, windows_git_core


class NativeCreateFixture(NativeReceiptFixture):
    def __call__(self, session, source, fresh_session):
        raw = runtime.prepare(session,source)
        target = runtime.ProbeRuntimeBinding(session,raw,packet.digest(raw),source)
        image_record = session._records['image-binding.json'][1]
        pins=policy.measure_sources(self.repository)
        docker=Path(shutil.which('docker') or '').resolve(strict=True)
        try:
            packet.require(target._bound is None and not self.receipts)
            result=policy.create_owner(self.repository,self.powershell,self.python,self.git,self.plans[session._plan['nonce']],pins,
                session,(source,target),git_sha256=sha(self.git),docker=docker,docker_sha256=sha(docker))
            evidence=json.loads(result.evidence);value=evidence['payload']
            packet.require(evidence['processIdentityAuthenticated'] is True and evidence['launchAttemptConsumed'] is True and
                evidence['fence']['noRunningMembersVerified'] is True and value['selectedSourceFilesPinned']==46)
            for key in ('nativeReadinessBound','emptyPayloadNamespaceBound','emptyPayloadRemovedVerified','actualProbeNativeOwnerAcknowledged','actualNativeContainerCreateVerified'):
                packet.require(value[key] is True)
            for key in ('actualProbeNativeBuildCreateVerified','nativePublicationBuildVerified','operationalLeaseAuthorized',
                    'nativeCreatePreReceiptCrashGapVerified','controllerDeathCleanupVerified','backendControlAuthorized','backendCleanupAuthorized',
                    'originalInputsRead','originalPrivatePkiUsed','fullSystemRecoveryVerified','phase7Complete'):
                packet.require(value[key] is False)
            bound=json.loads(session._records['native-probe-create-binding.json'][1])
            intent=json.loads(session._records['native-probe-create-intent.json'][1])
            identifier=target.report()['containerId']
            packet.require(bound['actualOwnedProcess']['pid']==bound['receipt']['pid']==evidence['osIdentity']['pid'] and
                bound['receipt']['containerId']==identifier and bound['createIntentSha256']==packet.digest(session._records['native-probe-create-intent.json'][1]) and
                intent['runtimeIntentSha256']==packet.digest(raw) and intent['dockerSha256']==sha(docker))
            first=self.observed(identifier)
            kernel=self.kernel(identifier)
            packet.require(self.observed(identifier)==first and policy.measure_sources(self.repository)==pins and
                session._records['image-binding.json'][1]==image_record)
            path=self.repository/'artifacts'/policy.payload.binding.payload_name(session._plan['nonce'])
            packet.require(not path.exists())
            refused=False
            try:
                policy.create_owner(self.repository,self.powershell,self.python,self.git,self.plans[session._plan['nonce']],pins,
                    session,(source,target),git_sha256=sha(self.git),docker=docker,docker_sha256=sha(docker))
            except ValueError:refused=True
            packet.require(refused)
        except policy.process.LaunchError as error:
            print('Public native create refusal: '+str(json.loads(error.evidence).get('payload')),file=sys.stderr);raise
        finally:
            # Only the durable, live-fenced native create receipt conveys ownership to this fixture.
            if 'native-probe-create-binding.json' in session._records:
                saved=json.loads(session._records['native-probe-create-binding.json'][1])
                receipt=saved['receipt'];packet.require(saved['schema']=='fleetory.native-probe-create-binding.v1' and
                    receipt['containerId']==target._bound and receipt['pid']==saved['actualOwnedProcess']['pid'] and
                    receipt['runtimeIntentSha256']==packet.digest(raw))
                self.receipts.append((receipt['containerId'],target.intent))
            self.cleanup()
        packet.require(len(self.receipts)==1 and self.listed_id(identifier)==[])
        source.report()
        return dict(schema='fleetory.public-native-probe-create-proof.v1',verified=True,**kernel,sourceFilesHeld=46,
            actualNativeContainerCreateVerified=True,fixturePrecreatedSleepWorkers=0,nativeCreatedSleepWorkers=1,
            actualOwnerOsIdentityVerified=True,immutableCreateIntentAndDockerPinned=True,liveOwnerReceiptBoundBeforeAck=True,
            nativeReceiptAckVerified=True,independentEmptyNamespaceRemoved=True,sourceImageRecordPreserved=True,
            runtimeProfileSha256=runtime.PROFILE_SHA256,consumedCreateReplayRefused=True,ownNativeCreatedWorkerAbsent=True,
            cleanupActor='trusted-fixture-parent-from-native-create-receipt',cleanupBeforeAdmissionExpiry=True,
            nativePublicationBuildVerified=False,actualProbeNativeBuildCreateVerified=False,operationalLeaseAuthorized=False,
            nativeCreatePreReceiptCrashGapVerified=False,controllerDeathCleanupVerified=False,backendServicesStarted=0,
            backendCleanupAuthorized=False,originalInputsRead=False,originalPrivatePkiUsed=False,sourceVpsAccessed=False,
            fullSystemRecoveryVerified=False,phase7Complete=False)


def run():
    powershell=Path(shutil.which('pwsh') or '').resolve(strict=True);python=Path(sys.executable).resolve(strict=True)
    git=Path(shutil.which('git') or '').resolve(strict=True)
    if os.name=='nt':git=windows_git_core(git)
    with tempfile.TemporaryDirectory(prefix='fleetory-public-native-create-') as temp:
        root=Path(temp).resolve();powershell=private_powershell(powershell,root);git=private_git(git,root)
        callback=NativeCreateFixture(powershell,python,git)
        image=build_probe(runtime_check=callback,control_factory=callback.control)
        native=image.pop('runtimeObservation')
    return dict(schema='fleetory.generated-public-native-probe-create.v1',verified=True,imageAndStoppedCopy=image,native=native,
        actualNativeContainerCreateVerified=True,nativePublicationBuildVerified=False,backendServicesStarted=0,
        originalInputsRead=False,originalPrivatePkiUsed=False,sourceVpsAccessed=False,fullSystemRecoveryVerified=False,phase7Complete=False)


if __name__=='__main__':print('PUBLIC NATIVE PROBE CREATE PASS: '+json.dumps(run(),sort_keys=True))
