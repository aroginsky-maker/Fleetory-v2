"""Historical audit comparison and its private, fenced CLI."""
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import sys
import threading
import time
from types import SimpleNamespace

if __name__ == '__main__' and sys.flags.isolated and sys.flags.no_site:
    sys.path.append(str(Path(__file__).resolve().parent))

import audit_observation as core
import fresh_server_pair as packet

EXPECTED = 'fleetory.historical-audit-observation-expectation.v1'
OBSERVED = 'fleetory.historical-audit-native-observation.v1'
PROFILE = 'historical-one-null-member-readonly.v1'
FALSE_FLAGS = ('sourceOriginAuthenticated sourceIndependenceAuthenticated realBackendContacted sourceFileOpened signaturesVerified '
    'executionAuthorized fullSystemRecoveryVerified phase7Complete strictContextValueTypesCompatible writerAdmissionVerified '
    'stateMutationAuthorized originalExpectationsAccepted').split()
COMPARISON_FIELDS = ('profile sourceExpectationSha256 snapshotSha256 sourceNonce knownValuesCommitment '
    'nullContextMembersPreserved historicalComparisonOnly writerAdmissionVerified stateMutationAuthorized '
    'sourceOriginAuthenticated sourceIndependenceAuthenticated executionAuthorized fullSystemRecoveryVerified phase7Complete')


def commitment(events):
    lines = ['fleetory.historical.known-values.v1']
    for item in events:
        lines.extend((item['eventId'], item['key'], str(item['revision']), item['valueSha256']))
    return hashlib.sha256(('\n'.join(lines) + '\n').encode('ascii')).hexdigest()


def comparison(value, events):
    packet.keys(value, COMPARISON_FIELDS)
    packet.require(value['profile'] == PROFILE and value['historicalComparisonOnly'] is True)
    core.integer(value['nullContextMembersPreserved'], 1, 1)
    for name in ('sourceExpectationSha256', 'snapshotSha256', 'knownValuesCommitment'):
        packet.hex_value(value[name])
    packet.identity(value['sourceNonce'])
    packet.require(value['knownValuesCommitment'] == commitment(events))
    packet.require(all(value[name] is False for name in ('writerAdmissionVerified', 'stateMutationAuthorized', 'sourceOriginAuthenticated',
        'sourceIndependenceAuthenticated', 'executionAuthorized', 'fullSystemRecoveryVerified', 'phase7Complete')))
    ids = [item['eventId'] for item in events]
    packet.require(ids == sorted(ids))


def source_values(data, pin):
    packet.require(type(data) in (bytes, bytearray) and 0 < len(data) <= core.MAX_EXPECTED)
    frozen = bytes(data)
    digest = packet.hex_value(pin)
    packet.require(packet.digest(frozen) == digest)
    value = packet.strict_json(frozen, core.MAX_EXPECTED)
    packet.keys(value, ('category schema nonce snapshotSha256 knownEvents eventFields inMemoryRequests productionSinkSerializationUsed '
        'profile nullContextMembersPreserved productionPumpDeserializationUsed historicalComparisonOnly ' + ' '.join(FALSE_FLAGS)))
    packet.require(value['category'] == 'audit-history-expectations' and value['schema'] == 'fleetory.audit-historical-expectations.v1')
    packet.require(value['profile'] == PROFILE)
    packet.identity(value['nonce'])
    packet.hex_value(value['snapshotSha256'])
    for name, number in (('eventFields', 10), ('inMemoryRequests', 16), ('nullContextMembersPreserved', 1)):
        core.integer(value[name], number, number)
    packet.require(all(value[name] is True for name in ('productionSinkSerializationUsed', 'productionPumpDeserializationUsed', 'historicalComparisonOnly')))
    packet.require(all(value[name] is False for name in FALSE_FLAGS))
    return value, digest


def build(source_bytes, source_pin, nonce, point, producer):
    value, pin = source_values(source_bytes, source_pin)
    # Round-trip external objects once; no mutable caller object is retained.
    expected = json.loads(core.canonical(dict(schema=core.EXPECTATION, nonce=packet.identity(nonce),
        point=point, producer=producer, knownEvents=value['knownEvents'])))
    core.expectation(expected)
    expected['schema'] = EXPECTED
    expected['comparison'] = dict(profile=PROFILE, sourceExpectationSha256=pin, snapshotSha256=value['snapshotSha256'],
        sourceNonce=value['nonce'], knownValuesCommitment=commitment(expected['knownEvents']), nullContextMembersPreserved=1,
        historicalComparisonOnly=True, writerAdmissionVerified=False, stateMutationAuthorized=False,
        sourceOriginAuthenticated=False, sourceIndependenceAuthenticated=False, executionAuthorized=False,
        fullSystemRecoveryVerified=False, phase7Complete=False)
    expectation(expected)
    packet.require(len(core.canonical(expected)) <= core.MAX_EXPECTED)
    return expected


def expectation(value):
    packet.keys(value, 'schema nonce point knownEvents producer comparison')
    packet.require(value['schema'] == EXPECTED)
    projected = {name: item for name, item in value.items() if name != 'comparison'}
    projected['schema'] = core.EXPECTATION
    core.expectation(projected)
    comparison(value['comparison'], value['knownEvents'])
    return projected


def observe(expected_bytes, expected_pin, observed_bytes):
    packet.require(type(expected_bytes) in (bytes, bytearray) and 0 < len(expected_bytes) <= core.MAX_EXPECTED)
    packet.require(type(observed_bytes) in (bytes, bytearray) and 0 < len(observed_bytes) <= core.MAX_OBSERVED)
    pin, frozen_expected, frozen_observed = packet.hex_value(expected_pin), bytes(expected_bytes), bytes(observed_bytes)
    packet.require(packet.digest(frozen_expected) == pin)
    expected = packet.strict_json(frozen_expected, core.MAX_EXPECTED)
    observed = packet.strict_json(frozen_observed, core.MAX_OBSERVED)
    projected_expected = expectation(expected)
    packet.keys(observed, 'category schema nonce stateBefore stateAfter scan transactions executionAuthorized independentInclusionProofsVerified producer comparison')
    packet.require(observed['category'] == 'observation-history-read' and observed['schema'] == OBSERVED)
    comparison(observed['comparison'], expected['knownEvents'])
    packet.require(observed['comparison'] == expected['comparison'])
    projected_observed = {name: item for name, item in observed.items() if name != 'comparison'}
    projected_observed.update(category='observation-read', schema=core.SCHEMA)
    # Reuse bounded data witnesses internally; no strict receipt is exposed by this API.
    body = core.canonical(projected_expected)
    checked = core.observe(body, packet.digest(body), core.canonical(projected_observed))
    checked.update(schema=OBSERVED, expectedSha256=pin, comparison=dict(expected['comparison']),
        historicalComparisonOnly=True, writerAdmissionVerified=False, stateMutationAuthorized=False,
        originalStrictExpectationsAccepted=False, sourceOriginAuthenticated=False, sourceIndependenceAuthenticated=False)
    return checked


def evaluate_request(operation, request):
    packet.require(operation in ('build', 'observe'))
    body = packet.strict_json(request, core.MAX_BODY)
    if operation == 'build':
        packet.keys(body, 'sourceBase64 sourceSha256 nonce point producer')
        return build(packet.decode(body['sourceBase64'], core.MAX_EXPECTED), body['sourceSha256'], body['nonce'], body['point'], body['producer'])
    packet.keys(body, 'expectedBase64 expectedSha256 observedBase64')
    return observe(packet.decode(body['expectedBase64'], core.MAX_EXPECTED), body['expectedSha256'], packet.decode(body['observedBase64'], core.MAX_OBSERVED))


def run():
    packet.require(len(sys.argv) == 2)
    return evaluate_request(sys.argv[1], sys.stdin.buffer.read(core.MAX_BODY + 1))


DIRECTORY = Path(__file__).resolve().parent
SOURCES = ('historical_audit_observation', 'audit_observation',
           'audit_process_fence', 'audit_process_posix', 'audit_process_windows',
           'audit_control_identity', 'recovery_files', 'fresh_server_pair', 'audit_archive')
OPERATIONS = ('build', 'observe')
FAULTS = ('none', 'early-eof', 'abrupt-exit')
READY = b'fleetory historical comparison ready\n'
EARLY_EOF = b'fleetory historical comparison input incomplete\n'
WORK_LIMIT_SECONDS = 7


def _read_worker_input(stream, maximum):
    header = stream.read(4)
    if len(header) != 4:
        raise EOFError
    size = int.from_bytes(header, 'big')
    if not 0 < size <= maximum:
        raise ValueError('Historical comparison frame size refused.')
    body = stream.read(size)
    if len(body) != size:
        raise EOFError
    if stream.read(1):
        raise ValueError('Historical comparison frame has trailing data.')
    return body


def _serve_worker(operation):
    output = sys.stdout.buffer
    output.write(READY)
    output.flush()
    try:
        request = _read_worker_input(sys.stdin.buffer, core.MAX_BODY)
    except EOFError:
        sys.stderr.buffer.write(EARLY_EOF)
        return 2
    output.write(json.dumps(evaluate_request(operation, request), sort_keys=True).encode('ascii'))
    output.flush()
    return 0


def _capture(engine, child, request, fault):
    class FramedPumps(engine._Pumps):
        def __init__(self):
            super().__init__(child, request)
            self.release = threading.Event()
            self.expected_input_bytes = 4 + (len(request) if fault == 'none' else 0)

        def _write(self):
            while not self.release.wait(0.02):
                if self.stopping.is_set():
                    return
            try:
                self._send(len(self.data).to_bytes(4, 'big'))
                if fault == 'none':
                    self._send(self.data)
            except OSError:
                self.errors.append('input-io')
            finally:
                self._close_input()

    return FramedPumps()


def _hold(held, engine, executable_pin, source_pins):
    tool = held.enter_context(engine.PinnedFile(sys.executable, executable_pin, executable=True))
    if len(source_pins) != len(SOURCES):
        raise ValueError('Historical comparison source set refused.')
    pins = tuple(held.enter_context(engine.PinnedFile(DIRECTORY / (name + '.py'), digest))
                 for name, digest in zip(SOURCES, source_pins))
    return tool, pins


def _await_ready(engine, child, fence, pumps, start):
    while len(pumps.stdout) < len(READY):
        engine._check_deadline(start, WORK_LIMIT_SECONDS)
        if pumps.errors or pumps.stderr or (child.poll() is not None if os.name == 'nt' else fence.exited()):
            raise engine.LaunchError('historical-worker-ready')
        time.sleep(0.01)
    if pumps.stdout != READY or pumps.stderr or pumps.errors:
        raise engine.LaunchError('historical-worker-ready')


def _run_worker(engine, operation, fault, request, executable_pin, source_pins):
    start = time.monotonic_ns()
    child = fence = pumps = None
    with ExitStack() as held:
        tool, pins = _hold(held, engine, executable_pin, source_pins)
        command = SimpleNamespace(executable=tool, arguments=('-I', '-S', '-B', str(pins[0].path), '--child', operation),
                                  directory=DIRECTORY, env=engine.environment(tool))
        try:
            child = engine._spawn(command)
            fence = engine._create_fence(child)
            identity = fence.identity(child, tool)
            pumps = _capture(engine, child, request, fault)
            pumps.start()
            _await_ready(engine, child, fence, pumps, start)
            packet.require(fence.identity(child, tool) == identity)
            for pin in pins:
                pin.check()
            engine._check_deadline(start, WORK_LIMIT_SECONDS)
            if fault != 'abrupt-exit':
                pumps.release.set()
                # An exact early EOF emits its own refusal on stderr. It is not a pipe failure.
                engine._wait_for_owner(child, fence, pumps, start, WORK_LIMIT_SECONDS)
        finally:
            end, close_error = engine._finish_owned(child, fence, pumps)
            packet.require(close_error is None and (child is None or end is not None and end['noRunningMembersVerified']))
        for pin in pins:
            pin.check()
        packet.require(not pumps.errors)
        if fault == 'abrupt-exit':
            packet.require(child.returncode != 0 and not pumps.input_written and pumps.stdout == READY and not pumps.stderr)
            result = None
        elif fault == 'early-eof':
            packet.require(child.returncode == 2 and pumps.input_written == 4 and pumps.stdout == READY and pumps.stderr == EARLY_EOF)
            result = None
        else:
            packet.require(child.returncode == 0 and pumps.input_written == pumps.expected_input_bytes and not pumps.stderr)
            result = packet.strict_json(bytes(pumps.stdout[len(READY):]), engine.MAX_STDOUT)
        return dict(schema='fleetory.historical-comparison-worker.v1', operation=operation, fault=fault,
                    childImageAndBirthVerified=True, childMembersAbsent=True, childExitCode=child.returncode,
                    fence=end['kind'], requestBytes=pumps.input_written, result=result)


def _fenced_cli():
    packet.require(sys.flags.isolated and sys.flags.no_site)
    if len(sys.argv) == 3 and sys.argv[1] == '--child' and sys.argv[2] in OPERATIONS:
        return _serve_worker(sys.argv[2])
    import audit_process_fence as engine
    packet.require(len(sys.argv) == 6 and sys.argv[1] == '--fenced')
    operation, fault, executable_pin, source_pins = sys.argv[2:]
    packet.require(operation in OPERATIONS and fault in FAULTS and (fault == 'none' or operation == 'build'))
    request = sys.stdin.buffer.read(core.MAX_BODY + 1)
    packet.require(0 < len(request) <= core.MAX_BODY)
    result = _run_worker(engine, operation, fault, request, executable_pin, source_pins.split(','))
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    try:
        if len(sys.argv) > 1 and sys.argv[1] in ('--fenced', '--child'):
            sys.exit(_fenced_cli())
        result = run()
    except Exception:
        print('Historical observation refused; no paths, values or credentials logged.', file=sys.stderr)
        sys.exit(1)
    print(json.dumps(result, sort_keys=True))
