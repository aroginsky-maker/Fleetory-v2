"""Live consumed four-input use; trusted host callback only, no permission or native CLI."""
from contextlib import ExitStack, contextmanager
import os
from pathlib import Path
import re
import sys
import threading
import time
import weakref

import audit_cleanup_attempt as attempts
import audit_supervisor_identity as identity
import audit_use_admission as gates
from historical import retained_service_inputs as inputs
from historical import retained_service_payload as private

packet, C, H = inputs.packet, attempts.C, inputs.packet.digest
SCHEMA = 'fleetory.retained-service-use-plan.v1'
PURPOSE = 'retained-four-input-private-consumer.v1'
MAX_PLAN, MAX_RESULT, LIFETIME_NS = 32768, 262144, 108_000_000_000
SOURCES = ('historical/retained_service_use.py', 'historical/retained_service_inputs.py',
           'historical/retained_service_payload.py', 'historical/postgres_pair_capture.py',
           'audit_archive_input.py', 'audit_expectation_source.py', 'retained_input_selection.py',
           'recovery_files.py', 'audit_cleanup_attempt.py', 'audit_control_identity.py',
           'audit_use_transaction.py', 'audit_use_admission.py', 'audit_supervisor_identity.py',
           'audit_process_fence.py')
_LIVE = weakref.WeakKeyDictionary()


def _freeze(value, bound):
    packet.require(type(value) in (bytes, bytearray) and 0 < len(value) <= bound)
    return bytes(value)


def _admit(raw, expected, metadata, root):
    packet.require(H(raw) == packet.hex_value(expected))
    plan = packet.strict_json(raw, MAX_PLAN)
    packet.keys(plan, 'schema purpose nonce revision root pins sourcePins pythonSha256 imageId probeSha256 configurationSha256')
    packet.require(plan['schema'] == SCHEMA and plan['purpose'] == PURPOSE)
    packet.identity(plan['nonce'])
    packet.require(type(plan['revision']) is str and re.fullmatch('[a-f0-9]{40}', plan['revision']))
    packet.require(plan['root'] == str(Path(root).absolute()))
    packet.keys(plan['pins'], 'selection manifest checkpoint ci local')
    for name, data in metadata.items():
        packet.require(H(data) == packet.hex_value(plan['pins'][name]))
    packet.keys(plan['sourcePins'], ' '.join(SOURCES))
    for value in (*plan['sourcePins'].values(), plan['pythonSha256'], plan['probeSha256'], plan['configurationSha256']):
        packet.hex_value(value)
    packet.require(type(plan['imageId']) is str and re.fullmatch('sha256:[a-f0-9]{64}', plan['imageId']))
    ci = packet.strict_json(metadata['ci'], 524288)
    packet.require(ci['schema'] == 'fleetory.retained-inflight-native-acceptance.v1'
                   and ci['revision'] == plan['revision'] and ci['codeCi'] == ci['localSonar'] == 'PASS')
    packet.require(ci['overallCi'] == 'success' or
                   (ci['overallCi'] == 'failure' and ci['officialSonar'] == 'COMPUTE_FAILED_DETAIL_UNAVAILABLE'))
    gates.percentage(ci['nativeCiCoverage'], 90)
    packet.require(ci['phase7Complete'] is False and ci['fullSystemRecoveryVerified'] is False)
    gates.local_gate(packet.strict_json(metadata['local'], 16384), plan['revision'])
    inputs._metadata(metadata['selection'], plan['pins']['selection'],
                     {n: metadata[n] for n in ('manifest', 'checkpoint')},
                     {n: plan['pins'][n] for n in ('manifest', 'checkpoint')}, plan['nonce'])
    return plan


class LiveServiceUse:
    """Only this live instance can capture and consume once; reports cannot recreate it."""
    def _state(self):
        packet.require(self in _LIVE)
        state = _LIVE[self]
        packet.require(state['pid'] == os.getpid() and state['thread'] == threading.get_ident())
        packet.require(0 <= time.monotonic_ns() - state['mono'] < LIFETIME_NS
                       and state['wall'] <= time.time_ns() < state['wall'] + LIFETIME_NS)
        state['root'].check()
        state['attempt'].check()
        packet.require(state['peer'].snapshot()['state'] == 'live')
        for source in state['sources']:
            source.check()
        return state

    def capture(self):
        s = self._state()
        packet.require(s['stage'] == 'ready')
        s['stage'] = 'capture-consumed'  # Failure or lost response never permits another open.
        p, m = s['plan'], s['metadata']
        value = inputs.capture(s['root'].path, m['selection'], p['pins']['selection'],
                               {n: m[n] for n in ('manifest', 'checkpoint')},
                               {n: p['pins'][n] for n in ('manifest', 'checkpoint')}, p['nonce'],
                               maximum_input=private.MAX_INPUT)
        self._state()
        s['payload'] = private.payload(value)
        s['stage'] = 'captured'

    def dispatch(self):
        s = self._state()
        packet.require(s['stage'] == 'captured')
        s['stage'] = 'dispatch-consumed'
        # The callback is supplied by trusted host code, never a field in the plan.
        # It receives frozen serialized bytes, not a mutable admission/authority object.
        result = s['consumer'](C(s['payload']))
        frozen = _freeze(result, MAX_RESULT)
        self._state()
        s['stage'] = 'returned-unverified'
        return frozen

    def report(self):
        s = self._state()
        return dict(schema='fleetory.retained-service-use.v1', nonce=s['plan']['nonce'],
                    stage=s['stage'], planSha256=H(s['raw']), heldProcessIdentity=s['peer'].snapshot()['identity'],
                    consumedAttemptFlushed=True, listedSourcePinsMatched=True,
                    transitiveCodeContinuityVerified=False, gateOriginAuthenticated=False,
                    existingDataConsentAuthenticated=False, nativeConsumerProcessAuthenticated=False,
                    nativeResultAuthenticated=False, nativeLaunchAuthorized=False,
                    executionAuthorized=False, fullSystemRecoveryVerified=False, phase7Complete=False)


@contextmanager
def use(trusted_operator_root, trusted_input_root, trusted_repository, plan_bytes, expected_plan,
        metadata, trusted_consumer):
    operator, root_path, repository = (Path(p).absolute() for p in
                                      (trusted_operator_root, trusted_input_root, trusted_repository))
    raw = _freeze(plan_bytes, MAX_PLAN)
    packet.keys(metadata, 'selection manifest checkpoint ci local')
    frozen = {n: _freeze(v, 524288 if n == 'ci' else 131072 if n in ('manifest', 'checkpoint') else 16384)
              for n, v in metadata.items()}
    plan = _admit(raw, expected_plan, frozen, root_path)
    packet.require(callable(trusted_consumer))
    mono, wall = time.monotonic_ns(), time.time_ns()
    record = dict(schema='fleetory.retained-service-use-attempt.v1', purpose=PURPOSE,
                  nonce=plan['nonce'], planSha256=H(raw), status='ATTEMPT_CONSUMED',
                  restartReplayRefusedWhileRecordRetained=True, independentRollbackResistance=False,
                  originalPermissionGranted=False, nativeLaunchAuthorized=False, phase7Complete=False)
    with ExitStack() as held:
        attempt = held.enter_context(attempts._claim_record(
            operator, 'retained-service-use-' + plan['nonce'] + '.json', record))
        root = held.enter_context(attempts.control.DirectoryLease(root_path))
        pinned = held.enter_context(identity.process.PinnedFile(Path(sys.executable).resolve(), plan['pythonSha256'], True))
        peer = held.enter_context(identity.HeldLocalPeer('self', pinned, identity.current_identity(pinned)))
        sources = [held.enter_context(identity.process.PinnedFile(
            repository / 'eng/pilot' / name, plan['sourcePins'][name])) for name in SOURCES]
        value = LiveServiceUse()
        _LIVE[value] = dict(pid=os.getpid(), thread=threading.get_ident(), mono=mono, wall=wall, raw=raw, plan=plan,
                            metadata=frozen, root=root, attempt=attempt, peer=peer,
                            sources=sources, consumer=trusted_consumer, payload=None, stage='ready')
        try:
            value._state()
            yield value
        finally:
            _LIVE.pop(value, None)


if __name__ == '__main__':
    raise SystemExit('Retained service use is a library; no root, reset, permission or native command CLI.')
