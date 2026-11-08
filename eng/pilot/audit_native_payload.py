"""Actual native owner's empty metadata reservation; no original payload/backend API."""
from contextlib import ExitStack
import json
import os
from pathlib import Path
import sys
import threading

import audit_native_preparation as prep
import audit_payload_binding as binding

packet, process, control = prep.packet, prep.process, prep.control
SCHEMA = 'fleetory.native-empty-payload-header.v1'
SOURCES = (*prep.SOURCES, 'eng/pilot/audit_native_payload.py', 'eng/pilot/HistoricalPayloadReservation.ps1')
MAX_ACTION = 40000


def header(data, native_pin):
    value = packet.strict_json(data, prep.MAX_HEADER)
    packet.keys(value, 'schema nonce controlSha256 planBase64 gitSha256 controlDirectorySha256 selectedSourcesSha256')
    packet.require(value['schema'] == SCHEMA)
    for name in ('controlDirectorySha256', 'selectedSourcesSha256'):
        packet.hex_value(value[name])
    base = {k: value[k] for k in ('nonce', 'controlSha256', 'planBase64', 'gitSha256')}
    info = prep.header(prep.canonical(dict(schema=prep.SCHEMA, **base)), native_pin)
    info['headerSha256'] = packet.digest(data)
    return info


def reservation(data, native_pin):
    info = header(data, native_pin)
    value = packet.strict_json(data, prep.MAX_HEADER)
    return dict(schema='fleetory.audit-payload-reservation.v1', nonce=info['nonce'], controlSha256=info['controlSha256'],
        controlDirectorySha256=value['controlDirectorySha256'], bundleSha256=value['selectedSourcesSha256'])


def authorize(info, ready_pin, intent_pin):
    for pin in (ready_pin, intent_pin):
        packet.hex_value(pin)
    return dict(schema='fleetory.native-empty-payload-authorize.v1', nonce=info['nonce'], controlSha256=info['controlSha256'],
        headerSha256=info['headerSha256'], readySha256=ready_pin, intentSha256=intent_pin, decision='reserve-empty-metadata')


def closing(info, ready_pin, owner_pin, intent_pin, release_pin):
    for pin in (ready_pin, owner_pin, intent_pin, release_pin):
        packet.hex_value(pin)
    return dict(schema='fleetory.native-empty-payload-remove.v1', nonce=info['nonce'], headerSha256=info['headerSha256'],
        readySha256=ready_pin, ownerSha256=owner_pin, intentSha256=intent_pin,
        releaseSha256=release_pin, decision='remove-empty-metadata')


def _action(data, native_pin, ready_pin, mode, decode_header=header, decode_reservation=reservation):
    value = packet.strict_json(data, MAX_ACTION)
    fields = 'schema headerBase64 frameBase64'
    if mode == 'remove':
        fields += ' ownerSha256 payloadDirectorySha256 intentSha256'
    packet.keys(value, fields)
    packet.require(value['schema'] == 'fleetory.native-empty-payload-action.v1')
    raw = packet.decode(value['headerBase64'], prep.MAX_HEADER)
    info = decode_header(raw, native_pin)
    body = packet.strict_json(packet.decode(value['frameBase64'], prep.MAX_FRAME), prep.MAX_FRAME)
    if mode == 'reserve':
        packet.require(body == authorize(info, ready_pin, body.get('intentSha256')))
    else:
        for key in ('ownerSha256', 'payloadDirectorySha256', 'intentSha256'):
            packet.hex_value(value[key])
        packet.require(body == closing(info, ready_pin, value['ownerSha256'], value['intentSha256'], body.get('releaseSha256')))
    return value, info, decode_reservation(raw, native_pin), body


class _RecordedEmpty(binding.OwnedPayload):
    """Reopen only the exact empty reservation just returned to this native parent."""
    def __init__(self, repository, value, ready, native_pid):
        packet.require(type(native_pid) is int and native_pid == os.getppid())
        self.value, self._held = value, ExitStack()
        self.parent, self.directory, self.pin = None, None, None
        try:
            self.parent = self._held.enter_context(control.DirectoryLease(Path(repository) / 'artifacts'))
            self.path = self.parent.path / binding.payload_name(value['nonce'])
            self.directory = self._held.enter_context(control.DirectoryLease(self.path))
            directory = binding.directory_hash(self.directory)
            packet.require(directory == ready['payloadDirectorySha256'])
            expected = packet.digest(prep.canonical(binding.marker(value, native_pid, directory)))
            packet.require(expected == ready['ownerSha256'])
            self.pin = self._held.enter_context(process.PinnedFile(self.path / binding.MARKER, expected))
            self.check()
        except BaseException:
            self.close()
            raise


def _native_action(data, native_pin, ready_pin, native_pid, mode, decode_header, decode_reservation):
    packet.require(mode in ('reserve', 'remove') and type(native_pid) is int and 0 < native_pid <= 0xffffffff and native_pid == os.getppid())
    value, info, declared, body = _action(data, native_pin, ready_pin, mode, decode_header, decode_reservation)
    repository = Path(__file__).resolve().parents[2]
    if mode == 'reserve':
        with binding.OwnedPayload(repository, declared, native_pid) as owned:
            owned.check()
            return dict(schema='fleetory.native-empty-payload-ready.v1', nonce=info['nonce'],
                headerSha256=info['headerSha256'], readySha256=ready_pin, intentSha256=body['intentSha256'],
                ownerSha256=owned.record_sha, payloadDirectorySha256=owned.directory_sha,
                privateInputsAccepted=False, backendCreated=False)
    with _RecordedEmpty(repository, declared, value, native_pid) as owned:
        owned.remove()
    return dict(schema='fleetory.native-empty-payload-closed.v1', nonce=info['nonce'], headerSha256=info['headerSha256'],
        readySha256=ready_pin, ownerSha256=value['ownerSha256'], removalRequested=True,
        privateInputsAccepted=False, backendCreated=False)


def native_action(data, native_pin, ready_pin, native_pid, mode):
    return _native_action(data, native_pin, ready_pin, native_pid, mode, header, reservation)


class _NativePayloadPumps(prep._PreparationPumps):
    source_names = SOURCES
    profile, switch = 'native-empty-payload', '-PayloadReservationOnly'
    max_frames = 3
    refusal_schema = 'fleetory.native-empty-payload-refused.v1'
    decode_header = staticmethod(header)
    decode_reservation = staticmethod(reservation)

    @classmethod
    def make_header(cls, native_plan, report, session, source_pins, git_pin):
        value = super().make_header(native_plan, report, session, source_pins, git_pin)
        value.update(schema=SCHEMA, controlDirectorySha256=binding.directory_hash(session._directory),
            selectedSourcesSha256=packet.digest(prep.canonical(source_pins)))
        return value

    def __init__(self, *args):
        super().__init__(*args)
        self.value = self.decode_reservation(self.data[:-1], self.session._plan['nativePlanSha256'])
        self.payload_ready = threading.Event()
        self.bound, self.intent_pin = None, None

    def _accept_refusal(self, value):
        packet.keys(value, 'schema stage privateInputsAccepted emptyPayloadState backendCreated')
        packet.require(value['stage'] in ('header', 'git', 'code', 'reserve', 'remove') and
            value['emptyPayloadState'] in ('not-attempted', 'unknown', 'reserved') and
            value['privateInputsAccepted'] is False and value['backendCreated'] is False)
        self.refusal_stage = value['stage']
        self.errors.append('native-empty-payload-refused')

    def _bind_ready(self, value, raw):
        packet.require(self.component_pin() == self.value['bundleSha256'])
        super()._bind_ready(value, raw)

    def _accept_frame(self, value, raw):
        if len(self.frames) != 1:
            return super()._accept_frame(value, raw)
        packet.keys(value, 'schema nonce headerSha256 readySha256 intentSha256 ownerSha256 payloadDirectorySha256 privateInputsAccepted backendCreated')
        packet.require(value['schema'] == 'fleetory.native-empty-payload-ready.v1' and value['nonce'] == self.info['nonce'] and
            value['headerSha256'] == self.info['headerSha256'] and value['readySha256'] == self.ready_pin and
            self.intent_pin is not None and value['intentSha256'] == self.intent_pin and
            value['privateInputsAccepted'] is False and value['backendCreated'] is False)
        for key in ('ownerSha256', 'payloadDirectorySha256'):
            packet.hex_value(value[key])
        self.bound = binding.BoundPayload(self.command, self.session, self.process, self.fence, value, self.value)
        self.frames.append(value)
        self.payload_ready.set()

    def _wait(self, event):
        while not event.wait(0.01):
            packet.require(not self.errors and not self.stopping.is_set())
            process._check_deadline(self.start_time, self.seconds)

    def _send_frame(self, value):
        data = prep.canonical(value) + b'\n'
        self.expected_input_bytes += len(data)
        self._send(data)

    def _after_payload_bound(self):
        # The original fixed profile offers no resource metadata.
        return None

    def _write(self):
        try:
            self._send(self.data)
            self._wait(self.ready)
            self.command.check()
            self.session.check()
            process._check_deadline(self.start_time, self.seconds)
            self.session._write_once('native-payload-intent.json', dict(schema='fleetory.native-empty-payload-intent.v1',
                nonce=self.info['nonce'], headerSha256=self.info['headerSha256'], readySha256=self.ready_pin,
                selectedSourcesSha256=self.value['bundleSha256'], privateInputReleaseAuthorized=False, backendCreationAuthorized=False))
            process._check_deadline(self.start_time, self.seconds)
            self.intent_pin = packet.digest(self.session._records['native-payload-intent.json'][1])
            self._send_frame(authorize(self.info, self.ready_pin, self.intent_pin))
            self._wait(self.payload_ready)
            self.bound.check()
            self._after_payload_bound()
            self.bound.check()
            release = self.bound.release()
            process._check_deadline(self.start_time, self.seconds)
            self.session._write_once('native-close.json', dict(schema='fleetory.native-empty-payload-close-request.v1',
                nonce=self.info['nonce'], readySha256=self.ready_pin, ownerSha256=self.frames[1]['ownerSha256'],
                payloadReleaseSha256=release, privateInputReleaseAuthorized=False, backendCleanupAuthorized=False))
            process._check_deadline(self.start_time, self.seconds)
            self._send_frame(closing(self.info, self.ready_pin, self.frames[1]['ownerSha256'], self.intent_pin, release))
        except Exception:
            self.errors.append('native-empty-payload-close-refused')
        finally:
            self._close_input()

    def finalize_binding(self, child, ended, failed):
        self.resource_metadata = dict(schema='fleetory.native-empty-payload-result.v1', nativeReadinessBound=False,
            emptyPayloadNamespaceBound=False, emptyPayloadRemovedVerified=False, selectedSourceFilesPinned=len(self.source_names),
            emptyReservationObserved=self.bound is not None, privateInputsAccepted=False, backendCreated=False,
            backendNamespaceBound=False, originalInputsRead=False, originalPrivatePkiUsed=False, cleanupAuthorized=False,
            fullLegacyExecutionContinuityVerified=False, fullSystemRecoveryVerified=False, phase7Complete=False,
            refusalStage=self.refusal_stage)
        try:
            packet.require(not failed and child.returncode == 0 and ended['noRunningMembersVerified'])
            packet.require(not self.pending and len(self.frames) == self.max_frames and self.bound is not None)
            final = self.frames[-1]
            packet.require(final == dict(schema='fleetory.native-empty-payload-closed.v1', nonce=self.info['nonce'],
                headerSha256=self.info['headerSha256'], readySha256=self.ready_pin, ownerSha256=self.frames[1]['ownerSha256'],
                removalRequested=True, privateInputsAccepted=False, backendCreated=False))
            self.bound.verify_removed()
            self.command.check()
            self.session.check()
            self.resource_metadata.update(nativeReadinessBound=True, emptyPayloadNamespaceBound=True, emptyPayloadRemovedVerified=True)
        finally:
            if self.bound is not None:
                self.bound.close()


def reserve_owner(repository, powershell, python, git, native_plan, source_pins, session, *, git_sha256):
    return prep._prepare_owner(repository, powershell, python, git, native_plan, source_pins, session, git_sha256, _NativePayloadPumps)


def measure_sources(repository):
    return prep._measure_sources(repository, SOURCES)


if __name__ == '__main__':
    try:
        if len(sys.argv) == 3 and sys.argv[1] == 'header':
            result = header(sys.stdin.buffer.read(prep.MAX_HEADER + 1), sys.argv[2])
        else:
            packet.require(len(sys.argv) == 5 and sys.argv[1] in ('reserve', 'remove'))
            result = native_action(sys.stdin.buffer.read(MAX_ACTION + 1), sys.argv[2], sys.argv[3], int(sys.argv[4]), sys.argv[1])
        print(prep.canonical(result).decode('ascii'))
    except Exception:
        print('Native empty metadata reservation refused.', file=sys.stderr)
        sys.exit(1)
