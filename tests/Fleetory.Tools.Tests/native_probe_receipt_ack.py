"""Actual native probe receipt acknowledgement on disposable copied public sources; no Docker/secrets."""
import json
from types import SimpleNamespace

from audit_native_probe_tests import policy, generated_pair, PROBE_BYTES
from native_resource_ack import run as shared_run


def check(kind,value):
    policy.packet.require(value['actualProbeNativeOwnerAcknowledged'] is (kind == 'positive'))
    for key in ('actualProbeNativeBuildCreateVerified','operationalLeaseAuthorized','runtimeContinuityVerified',
            'backendControlAuthorized','backendCleanupAuthorized','originalInputsRead','originalPrivatePkiUsed','fullSystemRecoveryVerified','phase7Complete'):
        policy.packet.require(value[key] is False)


def run():
    adapter = SimpleNamespace(**policy.__dict__, _NativeResourcePumps=policy._NativeProbePumps)
    result = shared_run(pair_factory=generated_pair, protocol=adapter,
        plan_changes=dict(probeSha256=policy.packet.digest(PROBE_BYTES)), proof_check=check)
    result.update(schema='fleetory.generated-native-probe-receipt-ack.v1',
        publicProbeTypedReceiptAcknowledged=True, bundleSourceAndRuntimeProfilePinsVerified=True,
        oldPythonReceiptProtocolUnchanged=True, actualProbeNativeBuildCreateVerified=False,
        operationalLeaseAuthorized=False, runtimeContinuityVerified=False)
    return result


if __name__=='__main__':print('NATIVE PROBE RECEIPT ACK PASS: '+json.dumps(run(),sort_keys=True))
