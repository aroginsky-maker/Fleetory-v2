"""Fixed native acknowledgement of public probe runtime receipts; no build/create or private-input API."""
import sys

import audit_native_resources as base
import audit_probe_runtime as runtime

payload, prep, packet, process = base.payload, base.prep, base.packet, base.process
SOURCES = (*base.SOURCES, 'eng/pilot/audit_probe_bundle.py', 'eng/pilot/audit_probe_image.py',
    'eng/pilot/audit_probe_runtime.py', 'eng/pilot/probe-runtime-profile.json', 'eng/pilot/audit_native_probe_runtime.py')
RECEIPT_SCHEMA = 'fleetory.native-probe-runtime-receipt.v1'
OFFER_SCHEMA = 'fleetory.native-probe-runtime-offer.v1'
ACK_SCHEMA = 'fleetory.native-probe-runtime-ack.v1'
ACTION_SCHEMA = 'fleetory.native-probe-runtime-action.v1'


def receipt(value, nonce, reservation):
    extra = ('bundleManifestSha256', 'sourceCodeSha256', 'runtimeProfileSha256')
    packet.keys(value, 'schema nonce controlSha256 imageId imageBindingSha256 imageIntentSha256 containerId containerBindingSha256 containerIntentSha256 expiresNs ' + ' '.join(extra))
    packet.require(value['schema'] == RECEIPT_SCHEMA and value['runtimeProfileSha256'] == runtime.PROFILE_SHA256)
    for key in extra:packet.hex_value(value[key])
    original = {key:item for key,item in value.items() if key not in extra}
    original['schema'] = base.RECEIPT_SCHEMA
    base.receipt(original, nonce, reservation)
    return value


def pair_receipt(session, pair):
    return base._pair_receipt(session, pair, runtime.probe.ProbeImageBinding, runtime.ProbeRuntimeBinding, runtime.anchor,
        'fleetory.audit-probe-runtime-binding.v1',
        lambda value: receipt(dict(schema=RECEIPT_SCHEMA, **value), value['nonce'], value['controlSha256']))


def offer(info, ready_pin, ready, value, intent_pin):
    packet.require(value['sourceCodeSha256'] == info['codeSha256'])
    return base._offer(info, ready_pin, ready, value, intent_pin, OFFER_SCHEMA, receipt)


def acknowledgement(info, ready_pin, ready, value, intent_pin, native_pid):
    return base._acknowledgement(info, ready_pin, ready, value, intent_pin, native_pid, ACK_SCHEMA)


def native_acknowledge(data, native_pin, ready_pin, native_pid):
    return base._native_acknowledge(data, native_pin, ready_pin, native_pid, ACTION_SCHEMA, offer, acknowledgement, receipt)


class _NativeProbePumps(base._NativeResourcePumps):
    source_names = SOURCES
    profile, switch = 'native-probe-runtime-ack', '-ProbeRuntimeAcknowledgementOnly'
    refusal_schema = 'fleetory.native-probe-runtime-refused.v1'
    _pair_receipt = staticmethod(pair_receipt)
    _offer, _acknowledgement = staticmethod(offer), staticmethod(acknowledgement)
    _intent_schema = 'fleetory.native-probe-runtime-intent.v1'
    _bound_schema = 'fleetory.native-probe-runtime-bound.v1'
    _result_schema = 'fleetory.native-probe-runtime-result.v1'
    _ack_schema = ACK_SCHEMA

    def finalize_binding(self, child, ended, failed):
        try:
            super().finalize_binding(child, ended, failed)
        finally:
            self.resource_metadata.update(actualProbeNativeOwnerAcknowledged=self.resource_metadata.get('nativeOwnerResourceAcknowledged', False),
                actualProbeNativeBuildCreateVerified=False, operationalLeaseAuthorized=False, runtimeContinuityVerified=False)


def acknowledge_owner(repository, powershell, python, git, native_plan, source_pins, session, pair, *, git_sha256):
    pair_receipt(session, pair)
    return prep._prepare_owner(repository, powershell, python, git, native_plan, source_pins, session,
        git_sha256, _NativeProbePumps, linked_pair=pair)


def measure_sources(repository):
    return prep._measure_sources(repository, SOURCES)


if __name__ == '__main__':
    try:
        packet.require(len(sys.argv) == 5 and sys.argv[1] == 'acknowledge')
        result = native_acknowledge(sys.stdin.buffer.read(payload.MAX_ACTION + 1), sys.argv[2], sys.argv[3], int(sys.argv[4]))
        print(prep.canonical(result).decode('ascii'))
    except Exception:
        print('Native public probe runtime acknowledgement refused.', file=sys.stderr)
        sys.exit(1)
