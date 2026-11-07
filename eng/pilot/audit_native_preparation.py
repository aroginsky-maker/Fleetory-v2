"""Fixed close-only readiness for the actual historical owner; no private payload or backend."""
from contextlib import ExitStack
import base64
import json
import os
from pathlib import Path
import sys
import threading
from types import SimpleNamespace

import audit_control_identity as control
import audit_process_fence as process
import fresh_server_pair as packet
import historical_audit_restore as restore
import recovery_files as files

MAX_HEADER, MAX_FRAME = 24576, 2048
SCHEMA = 'fleetory.native-preparation-header.v1'
PYTHON_SOURCES = ('audit_archive audit_control_identity audit_launch_bundle audit_native_preparation audit_observation '
    'audit_payload_binding audit_payload_launch audit_payload_owner audit_process_fence audit_process_posix '
    'audit_process_windows fresh_server_pair historical_audit_observation historical_audit_restore recovery_files').split()
POWERSHELL_SOURCES = ('Invoke-HistoricalAuditObservation PilotNativeProcess PilotCaptureStream ProviderRecoveryPolicy '
    'ProviderRecoveryCredential ImmuDataRoundtripPolicy HistoricalAuditControllerPolicy HistoricalAuditInputPins HistoricalPreparation').split()
ROOTS = ('.config/dotnet-tools.json', '.editorconfig', 'Directory.Build.props', 'Directory.Packages.props',
    'Directory.Solution.targets', 'Fleetory.sln', 'NuGet.Config', 'global.json')
SOURCES = tuple('eng/pilot/' + n + '.py' for n in PYTHON_SOURCES) + tuple('eng/pilot/' + n + '.ps1' for n in POWERSHELL_SOURCES) + ROOTS


def _editor_open(parent):
    """One fixed public build input; the generic recovery path grammar stays unchanged."""
    parent.check()
    path = parent.path / '.editorconfig'
    packet.require(files.regular_single_file(path.lstat()))
    fd = files.windows_open(path) if os.name == 'nt' else os.open('.editorconfig',
        os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent.fd)
    try:
        parent.check()
        held, current = os.fstat(fd), path.lstat()
        packet.require(files.regular_single_file(held) and files.regular_single_file(current) and
            (held.st_dev, held.st_ino) == (current.st_dev, current.st_ino))
        return fd
    except BaseException:
        os.close(fd)
        raise


class _RootInputPin(process.PinnedFile):
    def _open(self):
        if self.path.name == '.editorconfig':
            return _editor_open(self.parent)
        return super()._open()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode('ascii')


def header(data, native_pin):
    value = packet.strict_json(data, MAX_HEADER)
    packet.keys(value, 'schema nonce controlSha256 planBase64')
    packet.require(value['schema'] == SCHEMA)
    packet.identity(value['nonce'])
    packet.hex_value(value['controlSha256'])
    native = restore.plan(packet.decode(value['planBase64'], 16384), native_pin)
    packet.require(native['nonce'] == value['nonce'])
    return dict(nonce=value['nonce'], revision=native['revision'], controlSha256=value['controlSha256'],
        nativePlanSha256=native_pin, codeSha256=native['codeSha256'], headerSha256=packet.digest(data))


def close_frame(data, info, ready_pin):
    value = packet.strict_json(data, MAX_FRAME)
    packet.keys(value, 'schema nonce controlSha256 headerSha256 readySha256 decision')
    packet.hex_value(ready_pin)
    packet.require(value == dict(schema='fleetory.native-preparation-close.v1', nonce=info['nonce'],
        controlSha256=info['controlSha256'], headerSha256=info['headerSha256'], readySha256=ready_pin,
        decision='close-without-input'))
    return dict(verified=True)


def measure_sources(repository):
    """Trusted-host measurement only; this inventory does not authenticate its origin."""
    result = {}
    root = Path(repository).resolve(strict=True)
    for name in SOURCES:
        path = root / name
        with control.DirectoryLease(path.parent) as parent:
            if path.name == '.editorconfig':
                with os.fdopen(_editor_open(parent), 'rb') as stream:
                    before = files.file_state(os.fstat(stream.fileno()))
                    data = stream.read(512 * 1024 + 1)
                    packet.require(len(data) <= 512 * 1024 and before == files.file_state(os.fstat(stream.fileno())))
                    result[name] = packet.digest(data)
            else:
                result[name] = files.inspect_file(parent.path, parent.fd, path.name, 512 * 1024)[0]
    return result


class _PreparationPumps(process._Pumps):
    def __init__(self, child, data, command, session, fence, start, seconds):
        super().__init__(child, data)
        self.command, self.session, self.fence = command, session, fence
        self.start_time, self.seconds = start, seconds
        self.info = header(data[:-1], session._plan['nativePlanSha256'])
        self.ready = threading.Event()
        self.frames, self.pending = [], bytearray()
        self.ready_pin = None
        self.refusal_stage = None

    def component_pin(self):
        values = {name: source.digest for name in SOURCES for source in self.command.sources
            if isinstance(source, process.PinnedFile) and source.path == self.command.directory / name}
        packet.require(set(values) == set(SOURCES))
        return packet.digest(canonical(values))

    def _on_output(self, category, data):
        if category != 'stdout-bound':
            return
        self.pending.extend(data)
        packet.require(len(self.pending) <= MAX_FRAME)
        while b'\n' in self.pending:
            raw, _, rest = self.pending.partition(b'\n')
            self.pending[:] = rest
            value = packet.strict_json(bytes(raw), MAX_FRAME)
            packet.require(len(self.frames) < 2)
            if value.get('schema') == 'fleetory.native-preparation-refused.v1':
                packet.keys(value, 'schema stage privateInputsAccepted payloadCreated backendCreated')
                packet.require(value['stage'] in ('header', 'code', 'close') and
                    all(value[n] is False for n in ('privateInputsAccepted', 'payloadCreated', 'backendCreated')))
                self.refusal_stage = value['stage']
                self.errors.append('native-preparation-refused')
                return
            if not self.frames:
                self._bind_ready(value, bytes(raw))
            else:
                self.frames.append(value)

    def _bind_ready(self, value, raw):
        packet.keys(value, 'schema nonce revision controlSha256 nativePlanSha256 codeSha256 headerSha256 pid privateInputsAccepted payloadCreated backendCreated')
        packet.require(value['schema'] == 'fleetory.native-preparation-ready.v1')
        for name, expected in self.info.items():
            packet.require(value[name] == expected)
        packet.require(type(value['pid']) is int and value['pid'] == self.process.pid)
        packet.require(all(value[n] is False for n in ('privateInputsAccepted', 'payloadCreated', 'backendCreated')))
        self.command.check()
        observed = self.fence.identity(self.process, self.command.executable)
        self.session.check()
        process._check_deadline(self.start_time, self.seconds)
        self.ready_pin = packet.digest(raw)
        self.session._write_once('native-ready.json', dict(schema='fleetory.native-preparation-bound.v1',
            nonce=self.info['nonce'], reservationSha256=self.info['controlSha256'], headerSha256=self.info['headerSha256'],
            readySha256=self.ready_pin, selectedSourcesSha256=self.component_pin(), selectedSourceFiles=len(SOURCES),
            actualOwnedProcess=observed, privateInputsAccepted=False, backendNamespaceBound=False))
        process._check_deadline(self.start_time, self.seconds)
        self.frames.append(value)
        self.ready.set()

    def _write(self):
        try:
            self._send(self.data)
            while not self.ready.wait(0.01):
                if self.errors or self.stopping.is_set():
                    return
                process._check_deadline(self.start_time, self.seconds)
            self.command.check()
            self.session.check()
            process._check_deadline(self.start_time, self.seconds)
            value = dict(schema='fleetory.native-preparation-close.v1', nonce=self.info['nonce'],
                controlSha256=self.info['controlSha256'], headerSha256=self.info['headerSha256'],
                readySha256=self.ready_pin, decision='close-without-input')
            self.session._write_once('native-close.json', dict(schema='fleetory.native-preparation-close-request.v1',
                nonce=self.info['nonce'], readySha256=self.ready_pin, privateInputReleaseAuthorized=False))
            process._check_deadline(self.start_time, self.seconds)
            data = canonical(value) + b'\n'
            self.expected_input_bytes += len(data)
            self._send(data)
        except Exception:
            self.errors.append('preparation-close-refused')
        finally:
            self._close_input()

    def finalize_binding(self, child, ended, failed):
        self.resource_metadata = dict(schema='fleetory.native-preparation-result.v1', nativeReadinessBound=False,
            closeOnlyVerified=False, privateInputsAccepted=False, payloadCreated=False, backendCreated=False,
            backendNamespaceBound=False, selectedSourceFilesPinned=len(SOURCES), transitiveLegacyContinuityVerified=False, gitRuntimeAuthenticated=False,
            originalInputsRead=False, refusalStage=self.refusal_stage, cleanupAuthorized=False, fullSystemRecoveryVerified=False, phase7Complete=False)
        packet.require(not failed and child.returncode == 0 and ended['noRunningMembersVerified'])
        packet.require(not self.pending and len(self.frames) == 2)
        final = self.frames[1]
        packet.keys(final, 'schema nonce headerSha256 readySha256 privateInputsAccepted payloadCreated backendCreated')
        packet.require(final['schema'] == 'fleetory.native-preparation-closed.v1' and final['nonce'] == self.info['nonce'] and
            final['headerSha256'] == self.info['headerSha256'] and final['readySha256'] == self.ready_pin and
            all(final[n] is False for n in ('privateInputsAccepted', 'payloadCreated', 'backendCreated')))
        self.command.check()
        self.session.check()
        self.resource_metadata.update(nativeReadinessBound=True, closeOnlyVerified=True)


def prepare_owner(repository, powershell_path, python_path, git_path, native_plan, source_pins, session):
    """Fixed trusted-host close-only launcher. No archive, key, endpoint, command or root wire input."""
    root = Path(repository).resolve(strict=True)
    packet.require(type(source_pins) is dict and set(source_pins) == set(SOURCES))
    native_pin = session._plan['nativePlanSha256']
    declared = restore.plan(native_plan, native_pin)
    report = session.report()
    packet.require(declared['nonce'] == report['nonce'] and declared['revision'] == session._plan['revision'] and
        declared['codeSha256'] == session._plan['codeSha256'] and declared['probeSha256'] == session._plan['probeSha256'])
    value = dict(schema=SCHEMA, nonce=report['nonce'], controlSha256=report['reservationSha256'],
        planBase64=base64.b64encode(native_plan).decode('ascii'))
    data = canonical(value)
    header(data, native_pin)
    git = Path(git_path).resolve(strict=True)
    packet.require(git.name.lower() in ('git', 'git.exe') and git.is_file())
    with ExitStack() as held:
        directory = held.enter_context(control.DirectoryLease(root))
        held.enter_context(control.DirectoryLease(git.parent))
        powershell = held.enter_context(process.PinnedFile(powershell_path, session._plan['runtimes']['powershell'], True))
        python = held.enter_context(process.PinnedFile(python_path, session._plan['runtimes']['python'], True))
        sources = tuple(held.enter_context(_RootInputPin(root / name, source_pins[name])) for name in SOURCES)
        entry = root / 'eng/pilot/Invoke-HistoricalAuditObservation.ps1'
        arguments = ('-NoLogo', '-NoProfile', '-NonInteractive', '-File', str(entry), '-PreparationOnly',
            '-ExpectedPlanSha256', native_pin, '-Python', str(python.path))
        command = process._Command(powershell, (python, *sources, directory), arguments, root,
            process.environment(powershell, (python, SimpleNamespace(path=git))), 'native-preparation', _PreparationPumps)
        result = process._run_owned(command, session, data + b'\n', 30)
    packet.require(result.exit_code == 0 and result.stderr == b'')
    return result


if __name__ == '__main__':
    try:
        if len(sys.argv) == 3 and sys.argv[1] == 'header':
            answer = header(sys.stdin.buffer.read(MAX_HEADER + 1), sys.argv[2])
        else:
            packet.require(len(sys.argv) == 6 and sys.argv[1] == 'close')
            answer = close_frame(sys.stdin.buffer.read(MAX_FRAME + 1),
                dict(nonce=sys.argv[2], controlSha256=sys.argv[3], headerSha256=sys.argv[4]), sys.argv[5])
        print(json.dumps(answer, separators=(',', ':')))
    except Exception:
        print('Native preparation metadata refused.', file=sys.stderr)
        sys.exit(1)
