"""Fixed native child for historical audit comparison, with no backend access."""
from contextlib import ExitStack
import json
import os
from pathlib import Path
import sys
import threading
import time
from types import SimpleNamespace

DIRECTORY = Path(__file__).resolve().parent
SOURCES = ('historical_observation_worker', 'historical_audit_observation', 'audit_observation',
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


def _serve(operation, history):
    output = sys.stdout.buffer
    output.write(READY)
    output.flush()
    try:
        request = _read_worker_input(sys.stdin.buffer, history.core.MAX_BODY)
    except EOFError:
        sys.stderr.buffer.write(EARLY_EOF)
        return 2
    output.write(json.dumps(history.evaluate_request(operation, request), sort_keys=True).encode('ascii'))
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


def _run(engine, packet, operation, fault, request, executable_pin, source_pins):
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


def main():
    # -I -S excludes user site and PYTHONPATH. Only this fixed source directory supplies local modules.
    sys.path.append(str(DIRECTORY))
    import historical_audit_observation as history
    if len(sys.argv) == 3 and sys.argv[1] == '--child' and sys.argv[2] in OPERATIONS:
        return _serve(sys.argv[2], history)
    import audit_process_fence as engine
    import fresh_server_pair as packet
    packet.require(sys.flags.isolated and sys.flags.no_site and len(sys.argv) == 5)
    operation, fault, executable_pin, source_pins = sys.argv[1:]
    packet.require(operation in OPERATIONS and fault in FAULTS and (fault == 'none' or operation == 'build'))
    request = sys.stdin.buffer.read(history.core.MAX_BODY + 1)
    packet.require(0 < len(request) <= history.core.MAX_BODY)
    print(json.dumps(_run(engine, packet, operation, fault, request, executable_pin, source_pins.split(',')), sort_keys=True))
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception:
        print('Historical comparison worker refused.', file=sys.stderr)
        sys.exit(1)
