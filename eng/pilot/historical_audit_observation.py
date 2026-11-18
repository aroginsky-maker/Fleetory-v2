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



# A separate application controller for one generated historical observation.
# These private frames convey data and a fixed observation request only.
CREATOR_LIMIT_SECONDS = 55
HANDOFF_EXIT = 'between-operations-exit'
RESTART_UNCONFIRMED = 'restart-unconfirmed'
CREATOR_FLOWS = ('complete', 'controller-exit', 'lease-expired', HANDOFF_EXIT, RESTART_UNCONFIRMED)
OBSERVE_REQUEST = b'observe'
AUTH_REQUEST = b'authenticate'
READER_REQUEST = b'check-reader'
RESTART_REQUEST = b'restart'
POST_RESTART_REQUEST = b'observe-after-restart'
LIVE_STATUS = b'alive'


def _creator_frame(data):
    packet.require(0 < len(data) <= core.MAX_BODY)
    return len(data).to_bytes(4, 'big') + data


def _creator_exact(stream, count):
    result = bytearray()
    while len(result) < count:
        chunk = stream.read(count - len(result))
        packet.require(bool(chunk))
        result.extend(chunk)
    return bytes(result)


def _creator_read(stream):
    header = _creator_exact(stream, 4)
    packet.require(len(header) == 4)
    size = int.from_bytes(header, 'big')
    packet.require(0 < size <= core.MAX_BODY)
    return _creator_exact(stream, size)


def _creator_write(stream, data):
    stream.write(_creator_frame(data))
    stream.flush()


def _native_payload(frame, stage, nonce):
    prefix = b'R:' + stage + b':' + nonce.encode('ascii') + b'\n'
    packet.require(frame.startswith(prefix))
    return frame[len(prefix):]


def _request_native_value(source, sink, stage, nonce):
    _creator_write(sink, stage)
    return _native_payload(_creator_read(source), stage, nonce)


def _finish_history_observation(source, sink, nonce, expected_bytes, reply):
    pin = packet.digest(expected_bytes)
    before = observe(expected_bytes, pin, _native_payload(reply, OBSERVE_REQUEST, nonce))
    auth = packet.strict_json(_request_native_value(source, sink, AUTH_REQUEST, nonce), 512)
    packet.keys(auth, 'category errorType authenticationDenied controlStatus')
    packet.require(auth['category'] == 'unexpected' and auth['errorType'] == 'InvalidOperationException' and
                   auth['authenticationDenied'] is True and type(auth['controlStatus']) is int and auth['controlStatus'] == 500)
    reader = packet.strict_json(_request_native_value(source, sink, READER_REQUEST, nonce), 512)
    packet.keys(reader, 'category readerWriteRefused')
    packet.require(reader['category'] == 'observation-reader-denial' and reader['readerWriteRefused'] is True)
    restart = packet.strict_json(_request_native_value(source, sink, RESTART_REQUEST, nonce), 512)
    packet.keys(restart, 'stopped ready')
    packet.require(restart['stopped'] is True and restart['ready'] is True)
    after = observe(expected_bytes, pin, _request_native_value(source, sink, POST_RESTART_REQUEST, nonce))
    packet.require(before['observationSha256'] == after['observationSha256'] and not source.read(1))
    return dict(before=before, after=after, authenticationRefused=True, readerWriteRefused=True, restartPreservedObservation=True)


def _application_controller(nonce):
    packet.identity(nonce)
    source, sink = sys.stdin.buffer, sys.stdout.buffer
    _creator_write(sink, READY)
    expected_bytes = _creator_read(source)
    expected = packet.strict_json(expected_bytes, core.MAX_EXPECTED)
    expectation(expected)
    packet.require(expected['nonce'] == nonce)
    _creator_write(sink, OBSERVE_REQUEST)
    reply = _creator_read(source)
    if reply == b'replay':
        _creator_write(sink, OBSERVE_REQUEST)
        packet.require(_creator_read(source) == b'refuse' and not source.read(1))
        response = b'refused'
    else:
        response = core.canonical(_finish_history_observation(source, sink, nonce, expected_bytes, reply))
    _creator_write(sink, response)
    return 0


class _CreatorControllerLink:
    """Owns the measured application's private streams and process-fence handle."""

    def __init__(self, engine, child, fence, tool):
        self.child, self.fence, self.tool = child, fence, tool
        self.identity = fence.identity(child, tool)
        self.started = time.monotonic()
        self.offset = 0
        self.pumps = engine._Pumps(child, b'')

    def start(self):
        for stream, target, limit in (
            (self.child.stdout, self.pumps.stdout, core.MAX_BODY + 1024),
            (self.child.stderr, self.pumps.stderr, 512),
        ):
            thread = threading.Thread(target=self.pumps._read,
                args=(stream, target, limit, 'creator-output-bound'), daemon=True)
            self.pumps.threads.append(thread)
            thread.start()

    def _remaining(self):
        remaining = CREATOR_LIMIT_SECONDS - (time.monotonic() - self.started)
        packet.require(remaining > 0 and not self.pumps.errors and not self.pumps.stderr)
        return remaining

    def _exited(self):
        return self.child.poll() is not None if os.name == 'nt' else self.fence.exited()

    def live(self):
        self._remaining()
        packet.require(not self._exited() and self.fence.identity(self.child, self.tool) == self.identity)

    def _thread(self, operation):
        thread = threading.Thread(target=operation, daemon=True)
        thread.start()
        thread.join(self._remaining())
        packet.require(not thread.is_alive())

    def receive_owner(self):
        values = []

        def read():
            try:
                values.append(_creator_read(sys.stdin.buffer.raw))
            except (ValueError, OSError):
                pass

        self._thread(read)
        packet.require(len(values) == 1)
        return values[0]

    def send_application(self, data):
        def write():
            try:
                self.pumps._send(_creator_frame(data))
            except (OSError, ValueError):
                self.pumps.errors.append('creator-input-io')

        self._thread(write)
        self._remaining()

    def _wait_bytes(self, count):
        while len(self.pumps.stdout) < count:
            self._remaining()
            if self._exited():
                self.pumps.finish()
                packet.require(len(self.pumps.stdout) >= count)
                break
            time.sleep(0.01)

    def receive_application(self):
        self._wait_bytes(self.offset + 4)
        start = self.offset + 4
        size = int.from_bytes(self.pumps.stdout[self.offset:start], 'big')
        packet.require(0 < size <= core.MAX_BODY)
        self._wait_bytes(start + size)
        self.offset = start + size
        return bytes(self.pumps.stdout[start:self.offset])

    def terminal_code(self):
        while not self._exited():
            self._remaining()
            time.sleep(0.01)
        code = self.child.returncode if os.name == 'nt' else self.fence.exit_code()
        self.pumps.finish()
        packet.require(len(self.pumps.stdout) == self.offset)
        self._remaining()
        return code


def _creator_dialog(link, flow, nonce):
    output = sys.stdout.buffer
    packet.require(link.receive_application() == READY)
    link.live()
    _creator_write(output, b'ready:' + nonce.encode('ascii'))
    expected = link.receive_owner()
    packet.require(len(expected) <= core.MAX_EXPECTED)
    link.send_application(expected)
    packet.require(link.receive_application() == OBSERVE_REQUEST)
    link.live()
    _creator_write(output, OBSERVE_REQUEST)
    decision = link.receive_owner()
    if flow == 'controller-exit':
        packet.require(decision == b'terminate')
        link.live()
        return None
    if flow == 'lease-expired':
        packet.require(decision == b'status')
        link.live()
        _creator_write(output, LIVE_STATUS)
        packet.require(link.receive_owner() == b'replay')
        link.live()
        link.send_application(b'replay')
        packet.require(link.receive_application() == OBSERVE_REQUEST)
        _creator_write(output, b'late-observe')
        packet.require(link.receive_owner() == b'refuse')
        link.send_application(b'refuse')
        link.child.stdin.close()
        packet.require(link.receive_application() == b'refused')
        return None
    return _relay_history_sequence(link, flow, nonce, decision)


def _relay_history_sequence(link, flow, nonce, first_reply):
    _native_payload(first_reply, OBSERVE_REQUEST, nonce)
    link.send_application(first_reply)
    for stage in (AUTH_REQUEST, READER_REQUEST, RESTART_REQUEST, POST_RESTART_REQUEST):
        packet.require(link.receive_application() == stage)
        link.live()
        _creator_write(sys.stdout.buffer, stage)
        reply = link.receive_owner()
        if flow == RESTART_UNCONFIRMED and stage == RESTART_REQUEST:
            packet.require(reply == b'no-native-restart')
            link.live()
            return None
        _native_payload(reply, stage, nonce)
        if flow == HANDOFF_EXIT and stage == AUTH_REQUEST:
            # The checked controller still awaits the reply. Consume this attempt without delivery or retry.
            link.live()
            return None
        link.send_application(reply)
    link.child.stdin.close()
    return packet.strict_json(link.receive_application(), core.MAX_BODY)


def _run_creator_controller(engine, flow, nonce, executable_pin, source_pins):
    packet.require(flow in CREATOR_FLOWS)
    interrupted_stage = {HANDOFF_EXIT: AUTH_REQUEST, RESTART_UNCONFIRMED: RESTART_REQUEST}.get(flow)
    stops_controller = flow == 'controller-exit' or interrupted_stage is not None
    packet.identity(nonce)
    child = fence = link = end = None
    with ExitStack() as held:
        tool, pins = _hold(held, engine, executable_pin, source_pins)
        command = SimpleNamespace(executable=tool,
            arguments=('-I', '-S', '-B', str(pins[0].path), '--independent-controller', nonce),
            directory=DIRECTORY, env=engine.environment(tool))
        try:
            child = engine._spawn(command)
            fence = engine._create_fence(child)
            link = _CreatorControllerLink(engine, child, fence, tool)
            link.start()
            result = _creator_dialog(link, flow, nonce)
            if stops_controller:
                end = fence.terminate()
            code = link.terminal_code()
        finally:
            if end is None:
                end, failure = engine._finish_owned(child, fence, link.pumps if link is not None else None)
            else:
                # The group is already checked, and terminal_code observed Linux exit with WNOWAIT.
                try:
                    child.wait(timeout=3)
                    link.pumps.finish()
                finally:
                    failure = engine._close_transport(child, fence)
            packet.require(failure is None and (child is None or end is not None and end['noRunningMembersVerified']))
        for pin in (tool, *pins):
            pin.check()
        packet.require(child.returncode == code and (code != 0) == stops_controller)
        proof = dict(schema='fleetory.historical-independent-controller.v2', nonce=nonce, flow=flow,
            controllerPid=child.pid, supervisorPid=os.getpid(), childIdentityVerified=True,
            controllerMembersAbsent=True, controllerExitObservedHeld=True, fence=end['kind'], controllerExitCode=code,
            applicationResult=result, lateApplicationRequestRefused=flow == 'lease-expired',
            interruptedNativeOperation=interrupted_stage.decode('ascii') if interrupted_stage is not None else None)
        _creator_write(sys.stdout.buffer, core.canonical(proof))
    return 0


def _fenced_cli():
    packet.require(sys.flags.isolated and sys.flags.no_site)
    if len(sys.argv) == 3 and sys.argv[1] == '--child' and sys.argv[2] in OPERATIONS:
        return _serve_worker(sys.argv[2])
    if len(sys.argv) == 3 and sys.argv[1] == '--independent-controller':
        return _application_controller(sys.argv[2])
    import audit_process_fence as engine
    if len(sys.argv) == 6 and sys.argv[1] == '--independent-owner':
        flow, nonce, executable_pin, source_pins = sys.argv[2:]
        return _run_creator_controller(engine, flow, nonce, executable_pin, source_pins.split(','))
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
        if len(sys.argv) > 1 and sys.argv[1] in ('--fenced', '--child', '--independent-owner', '--independent-controller'):
            sys.exit(_fenced_cli())
        result = run()
    except Exception:
        print('Historical observation refused; no paths, values or credentials logged.', file=sys.stderr)
        sys.exit(1)
    print(json.dumps(result, sort_keys=True))
