"""Actual public probe Docker receipts acknowledged by the actual fenced native owner; no backend data."""
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile

from audit_native_probe_tests import policy
from native_probe_image import run as build_probe
from native_probe_runtime import RuntimeFixture
from native_audit_preparation import sha, REPO
from historical_audit_restore_tests import fixture
from native_empty_payload import record
from private_runtime_fixture import private_git, private_powershell, windows_git_core


class NativeReceiptFixture(RuntimeFixture):
    def __init__(self, powershell, python, git):
        super().__init__()
        self.powershell, self.python, self.git = powershell, python, git
        self.plans = {}

    def control(self, value):
        plan,_ = fixture()
        for name in ('nonce','revision','codeSha256','probeSha256'):plan[name] = value[name]
        raw = policy.prep.canonical(plan)
        self.plans[value['nonce']] = raw
        return dict(value, nativePlanSha256=policy.packet.digest(raw),
            runtimes=dict(powershell=sha(self.powershell), python=sha(self.python)))

    def on_bound(self, session, source, target):
        pins = policy.measure_sources(REPO)
        before = {n:session._records[n][1] for n in ('image-binding.json','backend-binding.json')}
        raw = self.plans[session._plan['nonce']]
        try:
            result = policy.acknowledge_owner(REPO,self.powershell,self.python,self.git,raw,pins,session,
                (source,target),git_sha256=sha(self.git))
        except policy.process.LaunchError as error:
            evidence=json.loads(error.evidence)
            print('Public probe native receipt refusal: '+str(evidence.get('payload')),file=sys.stderr)
            raise
        evidence=json.loads(result.evidence);value=evidence['payload']
        policy.packet.require(evidence['processIdentityAuthenticated'] is True and evidence['launchAttemptConsumed'] is True and
            evidence['fence']['noRunningMembersVerified'] is True and value['selectedSourceFilesPinned']==45)
        for name in ('nativeReadinessBound','emptyPayloadNamespaceBound','emptyPayloadRemovedVerified','nativeOwnerResourceAcknowledged','actualProbeNativeOwnerAcknowledged'):
            policy.packet.require(value[name] is True)
        for name in ('actualProbeNativeBuildCreateVerified','operationalLeaseAuthorized','runtimeContinuityVerified',
                'backendControlAuthorized','backendCleanupAuthorized','originalInputsRead','originalPrivatePkiUsed','fullSystemRecoveryVerified','phase7Complete'):
            policy.packet.require(value[name] is False)
        intent=record(session,'native-resource-intent.json');bound=record(session,'native-resource-ack.json')
        policy.packet.require(intent['schema']==policy._NativeProbePumps._intent_schema and bound['schema']==policy._NativeProbePumps._bound_schema and
            intent['receipt']==policy.pair_receipt(session,(source,target)) and
            bound['actualOwnedProcess']['pid']==bound['acknowledgement']['pid']==evidence['osIdentity']['pid'] and
            bound['resourceIntentSha256']==policy.packet.digest(session._records['native-resource-intent.json'][1]))
        policy.packet.require(all(session._records[n][1]==data for n,data in before.items()) and policy.measure_sources(REPO)==pins)
        path=REPO/'artifacts'/policy.payload.binding.payload_name(session._plan['nonce'])
        policy.packet.require(not path.exists())
        refused=False
        try:policy.acknowledge_owner(REPO,self.powershell,self.python,self.git,raw,pins,session,(source,target),git_sha256=sha(self.git))
        except ValueError:refused=True
        policy.packet.require(refused)
        return dict(schema='fleetory.public-probe-native-receipt-proof.v1',verified=True,sourceFilesHeld=45,
            actualOwnerCases=1,actualOwnerOsIdentityVerified=True,publicProbeReceiptAcknowledged=True,
            bundleSourceAndRuntimeProfilePinsMatched=True,independentEmptyNamespaceBoundAndRemoved=True,
            bothSourceRecordsUnchanged=True,consumedNativeLaunchReplayRefused=True,ownedProcessMembersAbsent=True,
            actualProbeNativeBuildCreateVerified=False,operationalLeaseAuthorized=False,runtimeContinuityVerified=False,
            backendServicesStarted=0,backendControlAuthorized=False,backendCleanupAuthorized=False,
            abruptOwnerDeathBackendCleanupVerified=False,originalInputsRead=False,originalPrivatePkiUsed=False,
            sourceVpsAccessed=False,fullSystemRecoveryVerified=False,phase7Complete=False)


def run():
    powershell=Path(shutil.which('pwsh') or '').resolve(strict=True)
    python=Path(sys.executable).resolve(strict=True);git=Path(shutil.which('git') or '').resolve(strict=True)
    if os.name=='nt':git=windows_git_core(git)
    with tempfile.TemporaryDirectory(prefix='fleetory-public-probe-native-receipt-') as temp:
        root=Path(temp).resolve();powershell=private_powershell(powershell,root);git=private_git(git,root)
        callback=NativeReceiptFixture(powershell,python,git)
        image=build_probe(runtime_check=callback,control_factory=callback.control)
        runtime=image.pop('runtimeObservation');native=runtime.pop('nativeReceiptAcknowledgement')
    return dict(schema='fleetory.generated-public-probe-native-receipt-ack.v1',verified=True,
        imageAndStoppedCopy=image,runtime=runtime,native=native,totalCreatedContainers=2,backendServicesStarted=0,
        actualProbeNativeReceiptOwnerAcknowledged=True,actualProbeNativeBuildCreateVerified=False,
        backendCleanupAuthorized=False,abruptOwnerDeathBackendCleanupVerified=False,
        originalInputsRead=False,originalPrivatePkiUsed=False,sourceVpsAccessed=False,
        fullSystemRecoveryVerified=False,phase7Complete=False)


if __name__=='__main__':print('PUBLIC PROBE NATIVE RECEIPT ACK PASS: '+json.dumps(run(),sort_keys=True))
