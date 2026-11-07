"""Owned process image/birth observations before bounded input; fixed refusal probe only."""
from contextlib import ExitStack
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import subprocess
import threading
import time
from types import MappingProxyType

import audit_control_identity as control
import fresh_server_pair as packet
import recovery_files as files

MAX_INPUT, MAX_STDOUT, MAX_STDERR = 131072, 262144, 4096
REFUSAL_INPUT = b'{"schema":"fleetory.generated-admission-refusal.v1"}'


class LaunchError(RuntimeError):
    def __init__(self, category, evidence=None):
        super().__init__('Owned process refused: ' + category)
        self.category = category
        self.evidence = bytes(evidence or b'{}')


class PinnedFile:
    def __init__(self, trusted_path, expected, executable=False):
        packet.hex_value(expected)
        self.path = Path(trusted_path).resolve(strict=True)
        self.parent, self.fd = None, None
        try:
            self.parent = control.DirectoryLease(self.path.parent)
            self.fd = files.relative_open(self.parent.path, self.parent.fd, self.path.name)
            os.set_inheritable(self.fd, False)
            self.state = files.file_state(os.fstat(self.fd))
            packet.require(0 < self.state[2] <= 64 * 1024 * 1024)
            if executable and os.name == 'posix':
                packet.require(os.access(self.path, os.X_OK))
            self.digest = self._hash()
            packet.require(self.digest == expected)
            self.check()
        except BaseException:
            self.close()
            raise

    def _hash(self):
        digest = hashlib.sha256()
        os.lseek(self.fd, 0, os.SEEK_SET)
        count = 0
        while True:
            data = os.read(self.fd, 65536)
            if not data:
                break
            count += len(data)
            packet.require(count <= self.state[2])
            digest.update(data)
        packet.require(count == self.state[2])
        return digest.hexdigest()

    def check(self):
        packet.require(self.fd is not None)
        self.parent.check()
        held, current = os.fstat(self.fd), self.path.lstat()
        packet.require(files.regular_single_file(held) and files.regular_single_file(current))
        packet.require((held.st_dev, held.st_ino) == (current.st_dev, current.st_ino))
        packet.require(files.file_state(held) == self.state and not os.get_inheritable(self.fd))
        packet.require(self._hash() == self.digest and files.file_state(os.fstat(self.fd)) == self.state)

    def close(self):
        with ExitStack() as closing:
            if self.parent is not None:
                closing.callback(self.parent.close)
            if self.fd is not None:
                fd, self.fd = self.fd, None
                closing.callback(os.close, fd)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def environment(executable, additional=()):
    """Fixed trusted-host allowlist; packet input cannot add environment entries."""
    paths = tuple(dict.fromkeys(str(item.path.parent) for item in (executable, *additional)))
    # System paths support the fixed native owner's pre-admission dependencies.
    system_paths = ('/usr/bin', '/bin') if os.name == 'posix' else ()
    value = {'PATH': os.pathsep.join((*paths, *system_paths)), 'LANG': 'C.UTF-8',
        'LC_ALL': 'C.UTF-8', 'DOTNET_CLI_TELEMETRY_OPTOUT': '1', 'DOTNET_NOLOGO': '1'}
    names = ('SystemRoot', 'WINDIR', 'TEMP', 'TMP', 'USERPROFILE', 'APPDATA', 'LOCALAPPDATA',
        'ProgramFiles', 'ProgramFiles(x86)', 'ProgramData', 'HOME')
    for name in names:
        if name in os.environ:
            value[name] = os.environ[name]
    if os.name == 'nt':
        packet.require('SystemRoot' in value)
        value['PATHEXT'] = '.EXE;.COM'
    return MappingProxyType(value)


@dataclass(frozen=True)
class _Command:
    executable: PinnedFile
    sources: tuple
    arguments: tuple
    directory: Path
    env: object
    profile: str

    def check(self):
        packet.require(self.profile in ('generated-worker', 'native-admission-refusal'))
        packet.require(type(self.arguments) is tuple and all(type(x) is str for x in self.arguments))
        self.executable.check()
        for source in self.sources:
            source.check()


class _Pumps:
    def __init__(self, process, data):
        self.process, self.data = process, data
        self.stdout, self.stderr = bytearray(), bytearray()
        self.errors, self.threads = [], []
        self.input_written = 0

    def _read(self, stream, target, bound, category):
        try:
            while True:
                data = stream.read(4096)
                if not data:
                    return
                if len(target) + len(data) > bound:
                    self.errors.append(category)
                    return
                target.extend(data)
        except OSError:
            self.errors.append('output-io')

    def _write(self):
        try:
            view = memoryview(self.data)
            while view:
                chunk = view[:4096]
                count = os.write(self.process.stdin.fileno(), chunk)
                if not 0 < count <= len(chunk):
                    self.errors.append('input-io')
                    return
                self.input_written += count
                view = view[count:]
        except OSError:
            self.errors.append('input-io')
        finally:
            try:
                self.process.stdin.close()
            except OSError:
                self.errors.append('input-io')

    def start(self):
        for target, args in ((self._read, (self.process.stdout, self.stdout, MAX_STDOUT, 'stdout-bound')),
                (self._read, (self.process.stderr, self.stderr, MAX_STDERR, 'stderr-bound')), (self._write, ())):
            thread = threading.Thread(target=target, args=args, daemon=True)
            self.threads.append(thread)
            thread.start()

    def finish(self):
        deadline = time.monotonic_ns() + 3_000_000_000
        for thread in self.threads:
            thread.join(max(0, deadline - time.monotonic_ns()) / 1_000_000_000)
        if any(thread.is_alive() for thread in self.threads):
            raise LaunchError('pipe-closure-unverified')


@dataclass(frozen=True)
class FencedResult:
    exit_code: int
    stdout: bytes
    stderr: bytes
    evidence: bytes


def _spawn(command):
    kwargs = dict(stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0,
        close_fds=True, cwd=command.directory, env=dict(command.env), shell=False)
    args = (str(command.executable.path), *command.arguments)
    if os.name == 'nt':
        kwargs['creationflags'] = subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        kwargs.update(start_new_session=True, executable='/proc/self/fd/' + str(command.executable.fd),
            pass_fds=(command.executable.fd,))
    return subprocess.Popen(args, **kwargs)


def _create_fence(process):
    if os.name == 'nt':
        import audit_process_windows as platform
        fence = platform.JobFence()
        try:
            fence.assign(process)
        except BaseException:
            fence.close()
            raise
        return fence
    import audit_process_posix as platform
    return platform.GroupFence(process)


def _check_deadline(start, seconds):
    if time.monotonic_ns() - start >= seconds * 1_000_000_000:
        raise LaunchError('deadline')


def _wait_for_owner(process, fence, pumps, start, seconds):
    while True:
        if pumps.errors:
            raise LaunchError(pumps.errors[0])
        _check_deadline(start, seconds)
        exited = process.poll() is not None if os.name == 'nt' else fence.exited()
        if exited:
            return
        time.sleep(0.01)


def _close_transport(process, fence):
    failed = False
    for resource in (fence, process.stdin, process.stdout, process.stderr):
        if resource is not None:
            try:
                resource.close()
            except Exception:
                failed = True
    return 'resource-close-unverified' if failed else None


def _finish_owned(process, fence, pumps):
    if process is None:
        return None, None
    ended, failure = None, None
    try:
        if fence is not None:
            ended = fence.terminate()
        else:
            # Trusted entrypoints block on stdin; no descendant work was released.
            process.kill()
        process.wait(timeout=3)
        if pumps is not None:
            pumps.finish()
    except Exception:
        failure = 'fence-unverified'
    return ended, _close_transport(process, fence) or failure


def _process_evidence(command, observed, ended, pumps, pins_rechecked):
    value = dict(schema='fleetory.owned-process-fence.v1', profile=command.profile,
        osIdentity=observed, fence=ended, inputReleased=observed is not None and pumps is not None,
        inputBytesWritten=pumps.input_written if pumps else 0, launchAttemptConsumed=True,
        processIdentityAuthenticated=observed is not None, entrypointPinsMatched=pins_rechecked,
        transitiveCodeContinuityVerified=False, dependenciesAuthenticated=False,
        nativePayloadAccepted=False, nativeResultAuthenticated=False, backendNamespaceBound=False,
        backendCleanupVerified=False, gateOriginAuthenticated=False, dataConsentAuthenticated=False,
        originalInputsRead=False, originalPrivatePkiUsed=False, launchAuthorized=False,
        fullSystemRecoveryVerified=False, phase7Complete=False)
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def _run_owned(command, session, input_bytes, seconds):
    """Private trusted command primitive; it is not a wire command/argument interface."""
    packet.require(type(session) is control.ControlIdentity and type(command) is _Command)
    packet.require(type(input_bytes) in (bytes, bytearray) and 0 < len(input_bytes) <= MAX_INPUT)
    packet.require(type(seconds) is int and 1 <= seconds <= 600)
    data = bytes(input_bytes)
    command.check()
    packet.require(session._plan['runtimes']['powershell'] == command.executable.digest)
    session.consume_launch_attempt()  # Persist consumption before creating any process.
    process, fence, pumps, observed, ended, failure = None, None, None, None, None, None
    pins_rechecked = False
    start_wall, start = time.time_ns(), time.monotonic_ns()
    try:
        process = _spawn(command)
        fence = _create_fence(process)
        observed = fence.identity(process, command.executable)
        command.check()
        pins_rechecked = True
        session.bind_assertion(process.pid, start_wall, command.executable.digest)
        session.check()
        _check_deadline(start, seconds)
        pumps = _Pumps(process, data)
        pumps.start()  # No input was written before OS identity and lifetime fencing.
        _wait_for_owner(process, fence, pumps, start, seconds)
    except Exception as error:
        failure = error.category if isinstance(error, LaunchError) else 'operational'
    finally:
        ended, close_failure = _finish_owned(process, fence, pumps)
        failure = close_failure or failure
    encoded = _process_evidence(command, observed, ended, pumps, pins_rechecked)
    if failure is not None:
        raise LaunchError(failure, encoded)
    if pumps is not None and pumps.errors:
        raise LaunchError(pumps.errors[0], encoded)
    if ended is None or not ended['noRunningMembersVerified'] or pumps is None or pumps.input_written != len(data):
        raise LaunchError('io-or-fence-unverified', encoded)
    session.check()
    return FencedResult(process.returncode, bytes(pumps.stdout), bytes(pumps.stderr), encoded)


def native_refusal_probe(trusted_repository, powershell_path, python_path, owner_sha256, session):
    """Fixed pre-admission refusal only: no caller-selected packet, arguments or command."""
    repo = Path(trusted_repository).resolve(strict=True)
    entry = repo / 'eng/pilot/Invoke-HistoricalAuditObservation.ps1'
    with ExitStack() as held:
        powershell = held.enter_context(PinnedFile(powershell_path, session._plan['runtimes']['powershell'], True))
        python = held.enter_context(PinnedFile(python_path, session._plan['runtimes']['python'], True))
        owner = held.enter_context(PinnedFile(entry, owner_sha256))
        packet.require(owner.path == entry)
        arguments = ('-NoLogo', '-NoProfile', '-NonInteractive', '-File', str(owner.path),
            '-ExpectedPlanSha256', session._plan['nativePlanSha256'], '-Python', str(python.path))
        command = _Command(powershell, (python, owner), arguments, repo, environment(powershell, (python,)),
            'native-admission-refusal')
        result = _run_owned(command, session, REFUSAL_INPUT, 30)
    value = packet.strict_json(result.stdout, MAX_STDOUT)
    packet.require(result.exit_code == 1 and result.stderr.strip() == b'Historical native controller refused; no input contents or credentials logged.')
    packet.require(value['schema'] == 'fleetory.historical-audit-controller-cleanup.v1' and value['stage'] == 'input'
        and value['refusal'] == 'controller-input-admission' and value['cleanupVerified'] is True)
    packet.require(value['resources']['ids'] == [] and value['resources']['payloadClaimed'] is False)
    return result


if __name__ == '__main__':
    raise SystemExit('Owned process fencing is a library; no generic command, data, endpoint or root CLI is provided.')
