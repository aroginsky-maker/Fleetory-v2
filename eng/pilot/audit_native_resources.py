"""Typed native acknowledgement of generated receipts; no Docker, data or cleanup API."""
import json
import re
import sys
import threading
import time

import audit_native_payload as payload
import audit_linked_binding as linked

prep, packet, process = payload.prep, payload.packet, payload.process
SOURCES = (*payload.SOURCES, 'eng/pilot/audit_native_resources.py',
    'eng/pilot/HistoricalResourceAcknowledgement.ps1', 'eng/pilot/audit_linked_binding.py',
    'eng/pilot/audit_backend_binding.py', 'eng/pilot/audit_image_binding.py', 'eng/pilot/recovery_isolation.py')
RECEIPT_SCHEMA = 'fleetory.native-linked-resource-receipt.v1'


def receipt(value, nonce, reservation):
    packet.keys(value, 'schema nonce controlSha256 imageId imageBindingSha256 imageIntentSha256 containerId containerBindingSha256 containerIntentSha256 expiresNs')
    packet.require(value['schema'] == RECEIPT_SCHEMA and value['nonce'] == packet.identity(nonce) and
        value['controlSha256'] == reservation)
    packet.hex_value(reservation)
    linked.container.image_id(value['imageId'])
    packet.require(type(value['containerId']) is str and re.fullmatch('[a-f0-9]{64}', value['containerId']))
    for name in ('imageBindingSha256', 'imageIntentSha256', 'containerBindingSha256', 'containerIntentSha256'):
        packet.hex_value(value[name])
    packet.require(type(value['expiresNs']) is int and 0 < value['expiresNs'] - time.time_ns() <= linked.container.WINDOW_NS)
    return value


def pair_receipt(session, pair):
    packet.require(type(pair) is tuple and len(pair) == 2)
    source, target = pair
    packet.require(type(source) is linked.image.ImageBinding and type(target) is linked.LinkedContainerBinding and
        source.session is target.session is session and target._source is source)
    anchor = linked.anchor(session, source)
    report = target.report()
    packet.require(report['generatedImageContainerPairBound'] is True)
    raw = session._records['backend-binding.json'][1]
    record = json.loads(raw)
    packet.require(record['schema'] == 'fleetory.audit-linked-container-binding.v1' and
        record['containerId'] == report['containerId'] and record['imageId'] == anchor['imageId'] and
        record['imageBindingSha256'] == anchor['imageBindingSha256'] and
        record['imageIntentSha256'] == anchor['imageIntentSha256'] and
        record['intentSha256'] == report['intentSha256'] and
        record['reservationSha256'] == session.report()['reservationSha256'])
    value = dict(schema=RECEIPT_SCHEMA, nonce=target.intent['nonce'], controlSha256=target.intent['controlSha256'],
        **anchor, containerId=report['containerId'], containerBindingSha256=packet.digest(raw),
        containerIntentSha256=report['intentSha256'], expiresNs=target.intent['expiresNs'])
    return receipt(value, target.intent['nonce'], target.intent['controlSha256'])


def offer(info, ready_pin, ready, value, intent_pin):
    receipt(value, info['nonce'], info['controlSha256'])
    for pin in (ready_pin, ready['ownerSha256'], ready['payloadDirectorySha256'], ready['intentSha256'], intent_pin):
        packet.hex_value(pin)
    return dict(schema='fleetory.native-linked-resource-offer.v1', nonce=info['nonce'],
        headerSha256=info['headerSha256'], readySha256=ready_pin, ownerSha256=ready['ownerSha256'],
        payloadDirectorySha256=ready['payloadDirectorySha256'], payloadIntentSha256=ready['intentSha256'],
        receipt=value, intentSha256=intent_pin, decision='acknowledge-generated-receipts')


def acknowledgement(info, ready_pin, ready, value, intent_pin, native_pid):
    packet.require(type(native_pid) is int and 0 < native_pid <= 0xffffffff)
    return dict(schema='fleetory.native-linked-resource-ack.v1', nonce=info['nonce'],
        headerSha256=info['headerSha256'], readySha256=ready_pin, ownerSha256=ready['ownerSha256'],
        payloadDirectorySha256=ready['payloadDirectorySha256'], receiptSha256=packet.digest(prep.canonical(value)),
        intentSha256=intent_pin, imageId=value['imageId'], containerId=value['containerId'], pid=native_pid,
        privateInputsAccepted=False, backendControlAuthorized=False)


def native_acknowledge(data, native_pin, ready_pin, native_pid):
    # Direct helper delegation is the same restricted parent/marker check as empty removal,
    # but this operation only reads the marker and returns typed metadata.
    packet.require(type(native_pid) is int and native_pid == payload.os.getppid())
    wrapped = packet.strict_json(data, payload.MAX_ACTION)
    packet.keys(wrapped, 'schema headerBase64 frameBase64 ownerSha256 payloadDirectorySha256 intentSha256')
    packet.require(wrapped['schema'] == 'fleetory.native-linked-resource-action.v1')
    raw = packet.decode(wrapped['headerBase64'], prep.MAX_HEADER)
    info = payload.header(raw, native_pin)
    value = packet.strict_json(packet.decode(wrapped['frameBase64'], prep.MAX_FRAME), prep.MAX_FRAME)
    packet.keys(value, 'schema nonce headerSha256 readySha256 ownerSha256 payloadDirectorySha256 payloadIntentSha256 receipt intentSha256 decision')
    packet.require(value == offer(info, ready_pin, wrapped, value['receipt'], value['intentSha256']))
    repository = payload.Path(__file__).resolve().parents[2]
    with payload._RecordedEmpty(repository, payload.reservation(raw, native_pin), wrapped, native_pid) as owned:
        owned.check()
        result = acknowledgement(info, ready_pin, wrapped, value['receipt'], value['intentSha256'], native_pid)
        receipt(value['receipt'], info['nonce'], info['controlSha256'])
        return result


class _NativeResourcePumps(payload._NativePayloadPumps):
    source_names = SOURCES
    profile, switch = 'native-resource-ack', '-ResourceAcknowledgementOnly'
    max_frames = 4
    refusal_schema = 'fleetory.native-linked-resource-refused.v1'

    def __init__(self, *args):
        super().__init__(*args)
        self.pair = self.command.linked_pair
        self.receipt = pair_receipt(self.session, self.pair)
        self.resource_ack = threading.Event()
        self.resource_intent_pin, self.ack_pin = None, None

    def _accept_refusal(self, value):
        packet.keys(value, 'schema stage privateInputsAccepted emptyPayloadState backendCreated')
        packet.require(value['stage'] in ('header', 'git', 'code', 'reserve', 'resources', 'remove') and
            value['emptyPayloadState'] in ('not-attempted', 'unknown', 'reserved') and
            value['privateInputsAccepted'] is False and value['backendCreated'] is False)
        self.refusal_stage = value['stage']
        self.errors.append('native-linked-resource-refused')

    def _check_pair(self):
        packet.require(pair_receipt(self.session, self.pair) == self.receipt)
        self.command.check()
        self.bound.check()
        process._check_deadline(self.start_time, self.seconds)

    def _after_payload_bound(self):
        self._check_pair()
        owner = self.fence.identity(self.process, self.command.executable)
        ready = self.frames[1]
        self.session._write_once('native-resource-intent.json', dict(schema='fleetory.native-linked-resource-intent.v1',
            nonce=self.info['nonce'], headerSha256=self.info['headerSha256'], readySha256=self.ready_pin,
            payloadBindingSha256=packet.digest(self.session._records['payload-binding.json'][1]),
            actualOwnedProcess=owner, receipt=self.receipt, backendControlAuthorized=False, privateInputReleaseAuthorized=False))
        self._check_pair()
        self.resource_intent_pin = packet.digest(self.session._records['native-resource-intent.json'][1])
        self._send_frame(offer(self.info, self.ready_pin, ready, self.receipt, self.resource_intent_pin))
        self._wait(self.resource_ack)
        self._check_pair()

    def _accept_frame(self, value, raw):
        if len(self.frames) != 2:
            return super()._accept_frame(value, raw)
        self._check_pair()
        packet.require(self.resource_intent_pin is not None and not self.resource_ack.is_set())
        expected = acknowledgement(self.info, self.ready_pin, self.frames[1], self.receipt,
            self.resource_intent_pin, self.process.pid)
        packet.require(value == expected and type(value['pid']) is int and
            value['privateInputsAccepted'] is False and value['backendControlAuthorized'] is False)
        # The pipe peer is re-observed at acceptance; a copied PID field is insufficient.
        owner = self.fence.identity(self.process, self.command.executable)
        self.session._write_once('native-resource-ack.json', dict(schema='fleetory.native-linked-resource-bound.v1',
            nonce=self.info['nonce'], actualOwnedProcess=owner, acknowledgement=value,
            acknowledgementSha256=packet.digest(raw), resourceIntentSha256=self.resource_intent_pin,
            backendControlAuthorized=False, privateInputReleaseAuthorized=False))
        self._check_pair()
        self.ack_pin = packet.digest(self.session._records['native-resource-ack.json'][1])
        self.frames.append(value)
        self.resource_ack.set()

    def finalize_binding(self, child, ended, failed):
        try:
            super().finalize_binding(child, ended, failed)
            self.resource_metadata.update(schema='fleetory.native-linked-resource-result.v1', nativeOwnerResourceAcknowledged=False)
            packet.require(self.resource_ack.is_set() and self.ack_pin is not None and
                packet.digest(self.session._records['native-resource-ack.json'][1]) == self.ack_pin and
                pair_receipt(self.session, self.pair) == self.receipt)
            process._check_deadline(self.start_time, self.seconds)
            self.resource_metadata.update(nativeOwnerResourceAcknowledged=True, resourceAcknowledgementSha256=self.ack_pin)
        finally:
            self.resource_metadata.update(schema='fleetory.native-linked-resource-result.v1',
                nativeOwnerResourceAcknowledged=self.resource_metadata.get('nativeOwnerResourceAcknowledged', False),
                generatedReceiptMetadataOnly=True, legacyApplicationImageVerified=False, dockerObservationAuthenticated=False,
                backendControlAuthorized=False, backendCleanupAuthorized=False, legacyNativeOwnerIntegrated=False)


def acknowledge_owner(repository, powershell, python, git, native_plan, source_pins, session, pair, *, git_sha256):
    pair_receipt(session, pair)
    return prep._prepare_owner(repository, powershell, python, git, native_plan, source_pins, session,
        git_sha256, _NativeResourcePumps, linked_pair=pair)


def measure_sources(repository):
    return prep._measure_sources(repository, SOURCES)


if __name__ == '__main__':
    try:
        packet.require(len(sys.argv) == 5 and sys.argv[1] == 'acknowledge')
        result = native_acknowledge(sys.stdin.buffer.read(payload.MAX_ACTION + 1), sys.argv[2], sys.argv[3], int(sys.argv[4]))
        print(prep.canonical(result).decode('ascii'))
    except Exception:
        print('Native generated resource acknowledgement refused.', file=sys.stderr)
        sys.exit(1)
