"""Generated controller loss; surviving native owner alone retains Docker custody."""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import queue
import re
import select
import shutil
import subprocess
import sys
import tempfile
import threading
import time

from private_runtime_fixture import private_powershell

REPO = Path(__file__).resolve().parents[2]
SOURCES = ('eng/pilot/historical/RetainedControllerPipe.ps1',
           'eng/pilot/historical/RetainedInFlightSql.ps1',
           'eng/pilot/historical/RetainedPostgresTarget.ps1',
           'eng/pilot/historical/RetainedDataStageHost.ps1',
           'eng/pilot/historical/RetainedNativeClient.ps1',
           'tests/Fleetory.Tools.Tests/NativeRetainedServiceUseWorkflow.ps1',
           'tests/Fleetory.Tools.Tests/NativeServerPair.Tests.ps1')


def remaining(deadline, cap):
    seconds=min(cap, deadline-time.monotonic())
    if seconds <= 0:
        raise TimeoutError('Original 660-second worker deadline expired')
    return seconds


def frames(path):
    data = path.read_bytes()
    if len(data) > 8388608:
        raise ValueError('Public fixture output exceeded its bound')
    result = {}
    for line in data.splitlines():
        if not line.startswith(b'{'):
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if type(item) is dict and 'schema' in item:
            if item['schema'] in result:
                raise ValueError('Duplicate owner frame')
            result[item['schema']] = item
    return result


def wait_frame(path, schema, controller, seconds, allow_controller_exit=False):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        found = frames(path).get(schema)
        if found is not None:
            return found
        if not allow_controller_exit and controller.poll() is not None:
            # Read once more after the observed terminal process.
            found = frames(path).get(schema)
            if found is not None:
                return found
            raise RuntimeError('Owner ended without the required frame')
        time.sleep(.1)
    raise TimeoutError('Bounded native owner observation expired')


class ExitObservation:
    """Read-only OS handle, never a signal or cleanup authority."""
    def __init__(self, identifier, expected_birth):
        self.handle = None
        if os.name == 'nt':
            self.api = ctypes.WinDLL('kernel32', use_last_error=True)
            self.api.OpenProcess.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
            self.api.OpenProcess.restype = ctypes.c_void_p
            self.api.CloseHandle.argtypes = [ctypes.c_void_p]
            self.api.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
            self.api.GetProcessTimes.argtypes = [ctypes.c_void_p] + [ctypes.POINTER(ctypes.c_ulonglong)] * 4
            self.handle = self.api.OpenProcess(0x100000 | 0x1000, False, identifier)
            if not self.handle:
                raise OSError('Owner observation handle unavailable')
            times = [ctypes.c_ulonglong() for _ in range(4)]
            if not self.api.GetProcessTimes(self.handle, *(ctypes.byref(t) for t in times)):
                self.close()
                raise OSError('Owner birth observation unavailable')
            birth = dict(kind='windows-filetime', token=str(times[0].value))
        else:
            self.handle = os.pidfd_open(identifier)
            try:
                data = Path(f'/proc/{identifier}/stat').read_bytes()
                if not 0 < len(data) <= 4096:
                    raise ValueError('Owner stat bound')
                fields = data[data.rindex(b')') + 1:].split()
                if fields[0] in (b'Z', b'X'):
                    raise ValueError('Owner already exited at arm')
                birth = dict(kind='linux-proc-start-ticks', token=fields[19].decode('ascii'))
            except BaseException:
                self.close()
                raise
        if birth != expected_birth:
            self.close()
            raise ValueError('Owner birth differs from arm')
        self.require_live()

    def require_live(self):
        if os.name == 'nt':
            exited = self.api.WaitForSingleObject(self.handle, 0) == 0
        else:
            poll = select.poll()
            poll.register(self.handle, select.POLLIN)
            exited = bool(poll.poll(0))
        if exited:
            self.close()
            raise ValueError('Observed process exited before fault injection')

    def wait(self, seconds):
        if os.name == 'nt':
            if self.api.WaitForSingleObject(self.handle, int(seconds*1000)) != 0:
                raise TimeoutError('Owner did not exit')
        else:
            poll = select.poll()
            poll.register(self.handle, select.POLLIN)
            if not poll.poll(int(seconds*1000)):
                raise TimeoutError('Owner did not exit')

    def close(self):
        if self.handle is not None:
            if os.name == 'nt':
                self.api.CloseHandle(self.handle)
            else:
                os.close(self.handle)
            self.handle = None


def controller(runtime, active_sql=False):
    child = subprocess.Popen([runtime, '-NoLogo', '-NoProfile', '-NonInteractive', '-File',
        str(REPO/'tests/Fleetory.Tools.Tests/NativeServerPair.Tests.ps1'), '-Python', sys.executable,
        '-Profile', 'v2-retained-service-use', '-PrivateRuntimeChild', '-OriginalPurpose', '-ControllerLossRehearsal',
        *(['-ControllerFaultPoint','active-sql'] if active_sql else [])],
        stdin=subprocess.PIPE, cwd=REPO)
    try:
        requests = queue.Queue()
        threading.Thread(target=lambda: requests.put(sys.stdin.buffer.read(1)), daemon=True).start()
        while child.poll() is None:
            try:
                request = requests.get(timeout=.1)
                break
            except queue.Empty:
                continue
        else:
            return child.returncode
        if request != b'e':
            raise ValueError('Unexpected fixed fault request')
        child.stdin.close()
        child.stdin = None
        return child.wait(timeout=180)
    finally:
        if child.stdin is not None:
            child.stdin.close()
        # Revocation gives the original owner time to run its own finally.
        # Never turn a harness failure into death of the Docker resource creator.
        if child.poll() is None:
            child.wait(timeout=180)


def absence_checks(cleanup, native, image_id, deadline):
    prefix = ['docker'] + ([] if os.name == 'posix' else ['--context', 'desktop-linux'])
    targets = set(cleanup['ids']) | {native['containerId'], native['auditContainerId'], cleanup['image'], image_id} | set(cleanup['aliases'])
    if len(targets) != 10:
        raise ValueError('Unexpected own-resource observation set')
    for target in targets:
        if not re.fullmatch(r'(?:sha256:)?[a-f0-9]{64}|fleetory-native-(?:pair|audit)-[a-f0-9]{32}:fixture', target):
            raise ValueError('Invalid observation target')
        reply = subprocess.run(prefix + ['inspect', target], capture_output=True, timeout=remaining(deadline,15), check=False)
        if reply.returncode != 1 or not re.search(rb'no such (?:object|image|container)', reply.stderr, re.I):
            raise ValueError('Own-resource absence not independently observed')
    base = subprocess.run(prefix + ['image', 'inspect', '--format', '{{.Id}}', native['baseImageId']],
                          capture_output=True, timeout=remaining(deadline,15), check=False)
    if base.returncode or base.stdout.strip().decode('ascii') != native['baseImageId']:
        raise ValueError('Shared base image was not preserved')
    if (REPO/'artifacts'/('native-pair-' + cleanup['fixture'])).exists():
        raise ValueError('Own fixture payload remains')
    return len(targets)


def rehearse(runtime, case, record, deadline):
    pins = {name: hashlib.sha256((REPO/name).read_bytes()).hexdigest() for name in SOURCES}
    proc = None
    observer = None
    client_observer = None
    control = None
    active_sql = case == 'sql-death'
    output_path = record/'stdout.log'
    try:
        control = subprocess.Popen([sys.executable,'-I','-S','-B','-c','import time;time.sleep(660)'],
            stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        with output_path.open('xb') as output, (record/'stderr.log').open('xb') as errors:
            proc = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), '--controller',
                '--powershell', str(runtime), '--case', case], stdin=subprocess.PIPE,
                stdout=output, stderr=errors, cwd=REPO)
            arm = wait_frame(output_path, 'fleetory.native-owner-controller-arm.v1', proc, remaining(deadline,590))
            if arm['controllerPid'] != proc.pid or arm['ownerPid'] == proc.pid or arm['cleanupAuthorized']:
                raise ValueError('Actual controller/owner arm mismatch')
            if arm['controllerImageSha256'] != hashlib.sha256(Path(sys.executable).resolve().read_bytes()).hexdigest():
                raise ValueError('Actual controller image mismatch')
            expected_point='active-sql' if active_sql else 'after-targets'
            if arm['faultPoint'] != expected_point:
                raise ValueError('Fault point differs from the sealed owner context')
            observer = ExitObservation(arm['ownerPid'], arm['ownerBirth'])
            if active_sql:
                if arm['nativeClientPid'] in (arm['ownerPid'],arm['controllerPid']):
                    raise ValueError('Native client identity aliases an owner/controller')
                client_observer = ExitObservation(arm['nativeClientPid'],arm['nativeClientBirth'])
            elif arm['nativeClientPid'] != 0 or arm['nativeClientBirth'] is not None:
                raise ValueError('Pre-work arm unexpectedly carried a native client')
            observer.require_live()
            if client_observer is not None:
                client_observer.require_live()
            if proc.poll() is not None:
                raise ValueError('Actual controller exited before fault injection')
            if case != 'eof':
                proc.kill()
                if proc.wait(timeout=remaining(deadline,10)) == 0:
                    raise ValueError('Killed controller did not report a failure exit')
            else:
                proc.stdin.write(b'e')
                proc.stdin.flush()
            proof = wait_frame(output_path, 'fleetory.native-original-four-service-use-stage.v1', proc, remaining(deadline,180), case != 'eof')
            if client_observer is not None:
                client_observer.wait(remaining(deadline,10))
            observer.wait(remaining(deadline,10))
            if case == 'eof' and proc.wait(timeout=remaining(deadline,10)) != 0:
                raise ValueError('Native owner returned failure')
        cleanup = frames(output_path)['fleetory.native-pair-cleanup.v1']
        native = proof['case']
        observation = native['externalControllerObservation']
        checks=dict(hostCleanup=proof['cleanupVerified'], externalLoss=proof['externalControllerLossVerified'],
            targetCleanup=native['cleanupVerified'], postgresRemoval=native['ownRemovalCalls']==1,
            auditRemoval=native['ownedAuditRemovalCalls']==1, workScope=(native['nativeWorkDispatches']>0 if active_sql else native['nativeWorkDispatches']==0),
            restores=native['nativePgRestores']==(2 if active_sql else 0), lateRefusal=native['externalControllerLateWorkRefusals']==1,
            lossObserved=observation['lossObserved'], finalParentExit=(case=='eof' or observation['parentExited']))
        failed=[name for name,passed in checks.items() if not passed]
        if failed:
            # Fixed boolean names only; never dump packets, SQL or configuration values.
            raise ValueError('Native fault/cleanup result mismatch: '+','.join(failed))
        if (native['nativeAuditRestored'] != active_sql or native['serverStarted'] or native['independentCreatorDeathCleanupVerified']
                or native['unknownCreateOutcomeRecoveryVerified'] or proof['sourceOriginalFilesRead']
                or proof['fullRuntimeCommandResourceInventoryVerified']):
            raise ValueError('Fault proof exceeded its scope')
        if active_sql:
            flight=native['inFlightSql']
            if not (proof['externalControllerActiveSqlVerified'] and native['externalControllerActiveSqlVerified']
                    and flight['actualQueryActive'] and flight['nativeClientExitVerified'] and native['nativeClientAliveAtExternalLoss']
                    and flight['observationCalls']==flight['lateNativeWorkRefusals']==1
                    and flight['nativeClientPid']==arm['nativeClientPid'] and flight['nativeClientBirth']==arm['nativeClientBirth']
                    and not flight['coordinatorLost'] and not native['postLossDatabaseComparisonVerified']):
                raise ValueError('Actual active SQL/cancelled original client evidence mismatch')
        if control.poll() is not None:
            raise ValueError('Unrelated original control process was not preserved')
        checks = absence_checks(cleanup, native, proof['measuredImageId'], deadline)
        for name, pin in pins.items():
            if hashlib.sha256((REPO/name).read_bytes()).hexdigest() != pin:
                raise ValueError('Measured source changed during fixture')
        result = dict(schema='fleetory.generated-native-controller-rehearsal.v1', case=case, verified=True,
            sourceSha256=pins, arm=arm, ownerProof=proof, cleanup=cleanup, ownerExitObserved=True,
            independentAbsenceChecks=checks, sharedBasePreserved=True, originalInputsOpened=False,
            actualControllerExitCode=proc.returncode, actualControllerExitObserved=(proc.poll() is not None),
            actualActiveSqlObserved=active_sql,originalNativeClientExitObserved=(client_observer is not None),
            unrelatedControlProcessPreserved=True,postLossDatabaseComparisonVerified=False,
            creatorDeathCleanupVerified=False, fullExecutionInventoryVerified=False, phase7Complete=False)

        encoded=json.dumps(result)
        if len(encoded.encode('utf-8'))>32768:
            raise ValueError('Generated controller evidence exceeded its output bound')
        (record/'verified.json').write_text(json.dumps(result, indent=2)+'\n', encoding='utf-8')
        print(encoded)
    finally:
        if client_observer is not None:
            client_observer.close()
        if control is not None and control.poll() is None:
            control.kill();control.wait(timeout=10)
        if observer is not None:
            observer.close()
        if proc is not None:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=10)
            proc.stdin.close()


def main():
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument('--powershell', required=True)
    parser.add_argument('--case', choices=('eof', 'death', 'sql-death'), required=True)
    parser.add_argument('--controller', action='store_true')
    parser.add_argument('--record', type=Path)
    args = parser.parse_args()
    if args.controller:
        return controller(args.powershell,active_sql=args.case=='sql-death')
    deadline=time.monotonic()+660
    root = Path(tempfile.mkdtemp(prefix='fleetory-controller-owner-')).resolve(strict=True)
    parent = Path(tempfile.gettempdir()).resolve(strict=True)
    identity = root.stat()
    try:
        runtime = private_powershell(args.powershell, root)
        record = root
        if args.record is not None:
            args.record.mkdir(exist_ok=False)
            record = args.record
        rehearse(runtime, args.case, record, deadline)
    except BaseException:
        # The owner may still be unwinding. Do not delete its selected runtime.
        print('PUBLIC CONTROLLER FAILURE LEDGER RETAINED: '+str(root), file=sys.stderr)
        raise
    current = root.stat()
    if (root.parent != parent or root.is_symlink() or not root.name.startswith('fleetory-controller-owner-')
            or (current.st_dev, current.st_ino) != (identity.st_dev, identity.st_ino)):
        raise ValueError('Own public runtime cleanup identity changed')
    shutil.rmtree(root)
    return 0


if __name__ == '__main__':
    sys.exit(main())
