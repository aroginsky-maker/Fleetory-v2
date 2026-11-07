"""Actual pinned workers, process images, OS fences and bounded pipes; generated input only."""
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'eng/pilot'))
import audit_control_identity as identity
import audit_process_fence as policy


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class ProcessFenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='fleetory-process-fence-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.control = self.root / 'control'
        self.control.mkdir(mode=0o700)
        self.python = Path(sys.executable).resolve()
        self.worker = Path(__file__).resolve().with_name('audit_process_worker.py')
        self.pwsh = Path(shutil.which('pwsh')).resolve()
        self.plan = dict(schema=identity.SCHEMA, purpose=identity.PURPOSE,
            nonce='12345678-1234-4123-8123-123456789abc', revision='1' * 40, nativePlanSha256='2' * 64,
            codeSha256='3' * 64, probeSha256='4' * 64, runtimes=dict(python=sha(self.python), powershell=sha(self.python)))

    def session(self, plan=None):
        data = json.dumps(plan or self.plan, separators=(',', ':')).encode()
        return identity.claim(self.control, data, hashlib.sha256(data).hexdigest())

    def command(self, held, mode):
        executable = held.enter_context(policy.PinnedFile(self.python, sha(self.python), True))
        source = held.enter_context(policy.PinnedFile(self.worker, sha(self.worker)))
        return policy._Command(executable, (source,), ('-B', str(source.path), mode), self.root,
            policy.environment(executable), 'generated-worker')

    def running(self, pid):
        if os.name == 'nt':
            import audit_process_windows as platform
        else:
            import audit_process_posix as platform
        return platform.pid_is_running(pid)

    def test_real_image_birth_and_fence_authenticated_before_input(self):
        with ExitStack() as held, self.session() as session:
            command = self.command(held, 'echo')
            result = policy._run_owned(command, session, b'generated-private-input', 5)
            self.assertEqual(result.exit_code, 0)
            self.assertEqual(result.stdout, b'generated-private-input')
            self.assertEqual(result.stderr, b'')
            evidence = json.loads(result.evidence)
            self.assertTrue(evidence['processIdentityAuthenticated'])
            self.assertEqual(evidence['osIdentity']['imageSha256'], command.executable.digest)
            self.assertTrue(evidence['osIdentity']['actualImageMatched'])
            self.assertTrue(evidence['osIdentity']['birthToken'])
            self.assertTrue(evidence['fence']['noRunningMembersVerified'])
            self.assertEqual(evidence['inputBytesWritten'], len(result.stdout))
            self.assertTrue(session.report()['launchAttemptConsumed'])
            for name in ('transitiveCodeContinuityVerified', 'dependenciesAuthenticated', 'nativePayloadAccepted',
                'nativeResultAuthenticated', 'backendNamespaceBound', 'backendCleanupVerified', 'gateOriginAuthenticated',
                'dataConsentAuthenticated', 'originalInputsRead', 'originalPrivatePkiUsed', 'launchAuthorized',
                'fullSystemRecoveryVerified', 'phase7Complete'):
                self.assertIs(evidence[name], False)
            self.assertFalse(self.running(evidence['osIdentity']['pid']))

    def test_attempt_is_flushed_before_process_creation_and_cannot_replay(self):
        actual = policy._spawn
        with ExitStack() as held, self.session() as session:
            command = self.command(held, 'echo')
            def observed(spec):
                session.check()
                fd = session._records['launch-attempt.json'][0]
                os.lseek(fd, 0, os.SEEK_SET)
                value = json.loads(os.read(fd, identity.MAX_RECORD))
                self.assertEqual(value['status'], 'ATTEMPT_CONSUMED')
                self.assertFalse(value['launchAuthorized'])
                return actual(spec)
            with patch.object(policy, '_spawn', side_effect=observed) as called:
                policy._run_owned(command, session, b'x', 5)
            self.assertEqual(called.call_count, 1)
            with patch.object(policy, '_spawn', side_effect=AssertionError('Replay spawn forbidden')):
                with self.assertRaises(ValueError):
                    policy._run_owned(command, session, b'x', 5)

    def test_failed_spawn_is_consumed_and_does_not_echo_private_data(self):
        with ExitStack() as held, self.session() as session:
            command = self.command(held, 'echo')
            with patch.object(policy, '_spawn', side_effect=OSError('PRIVATE_INPUT_CANARY')):
                with self.assertRaises(policy.LaunchError) as seen:
                    policy._run_owned(command, session, b'PRIVATE_INPUT_CANARY', 5)
            self.assertNotIn('PRIVATE_INPUT_CANARY', str(seen.exception))
            self.assertFalse(json.loads(seen.exception.evidence)['inputReleased'])
            with self.assertRaises(ValueError):
                policy._run_owned(command, session, b'x', 5)

    def test_launch_claim_flush_failure_prevents_spawn_and_cannot_retry(self):
        with ExitStack() as held, self.session() as session:
            command = self.command(held, 'echo')
            with patch.object(identity.os, 'fsync', side_effect=OSError('Generated flush fault')),\
                    patch.object(policy, '_spawn', side_effect=AssertionError('Unflushed spawn forbidden')):
                with self.assertRaises(OSError):
                    policy._run_owned(command, session, b'x', 5)
            self.assertTrue(session.report()['launchAttemptConsumed'])
            with self.assertRaises(ValueError):
                policy._run_owned(command, session, b'x', 5)

    def test_post_spawn_source_pin_refusal_never_releases_input(self):
        with ExitStack() as held, self.session() as session:
            command = self.command(held, 'echo')
            original = command.check
            checks = []
            def checked():
                checks.append(True)
                if len(checks) > 1:
                    raise ValueError('Generated source pin refusal')
                original()
            with patch.object(policy._Command, 'check', side_effect=checked):
                with self.assertRaises(policy.LaunchError) as seen:
                    policy._run_owned(command, session, b'PRIVATE_INPUT_CANARY', 5)
            value = json.loads(seen.exception.evidence)
            self.assertTrue(value['processIdentityAuthenticated'])
            self.assertFalse(value['entrypointPinsMatched'])
            self.assertFalse(value['inputReleased'])
            self.assertTrue(value['fence']['noRunningMembersVerified'])

    def test_binding_failure_kills_owned_process_without_releasing_input(self):
        with ExitStack() as held, self.session() as session:
            command = self.command(held, 'echo')
            with patch.object(session, 'bind_assertion', side_effect=OSError('PRIVATE_BIND_CANARY')):
                with self.assertRaises(policy.LaunchError) as seen:
                    policy._run_owned(command, session, b'PRIVATE_BIND_CANARY', 5)
            value = json.loads(seen.exception.evidence)
            self.assertTrue(value['processIdentityAuthenticated'])
            self.assertFalse(value['inputReleased'])
            self.assertTrue(value['fence']['noRunningMembersVerified'])
            self.assertNotIn('PRIVATE_BIND_CANARY', str(seen.exception))

    def test_timeout_kills_owned_child_and_preserves_foreign_process(self):
        foreign = subprocess.Popen([str(self.python), '-B', str(self.worker), 'leaf'], stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            **({'start_new_session': True} if os.name == 'posix' else {'creationflags': subprocess.CREATE_NO_WINDOW}))
        try:
            with ExitStack() as held, self.session() as session:
                command = self.command(held, 'sleep')
                with self.assertRaises(policy.LaunchError) as seen:
                    policy._run_owned(command, session, b'x', 1)
                value = json.loads(seen.exception.evidence)
                self.assertEqual(seen.exception.category, 'deadline')
                self.assertTrue(value['fence']['noRunningMembersVerified'])
                self.assertFalse(self.running(value['osIdentity']['pid']))
                self.assertIsNone(foreign.poll())
        finally:
            foreign.kill()
            foreign.wait(timeout=5)

    def test_owner_exit_kills_descendant_holding_pipes(self):
        with ExitStack() as held, self.session() as session:
            result = policy._run_owned(self.command(held, 'owner-dies'), session, b'x', 5)
            self.assertEqual(result.exit_code, 17)
            child = json.loads(result.stdout)['child']
            self.assertFalse(self.running(child))
            self.assertTrue(json.loads(result.evidence)['fence']['noRunningMembersVerified'])

    def test_timeout_kills_descendant_as_well_as_owner(self):
        with ExitStack() as held, self.session() as session:
            with self.assertRaises(policy.LaunchError) as seen:
                policy._run_owned(self.command(held, 'child'), session, b'x', 1)
            value = json.loads(seen.exception.evidence)
            self.assertEqual(seen.exception.category, 'deadline')
            self.assertTrue(value['fence']['noRunningMembersVerified'])
            self.assertEqual(value['fence']['activeMembers'], 0)
            child = int((self.root / 'generated-descendant.pid').read_text(encoding='ascii'))
            self.assertFalse(self.running(child))

    def test_stdout_bound_refuses_without_returning_unbounded_output(self):
        self.bound_case('stdout', 'stdout-bound')

    def test_stderr_bound_refuses_without_returning_unbounded_output(self):
        self.bound_case('stderr', 'stderr-bound')

    def bound_case(self, mode, category):
        with ExitStack() as held, self.session() as session:
            with self.assertRaises(policy.LaunchError) as seen:
                policy._run_owned(self.command(held, mode), session, b'x', 5)
            self.assertEqual(seen.exception.category, category)
            self.assertTrue(json.loads(seen.exception.evidence)['fence']['noRunningMembersVerified'])
            self.assertLess(len(seen.exception.evidence), 4096)

    def test_input_backpressure_obeys_same_deadline(self):
        with ExitStack() as held, self.session() as session:
            with self.assertRaises(policy.LaunchError) as seen:
                policy._run_owned(self.command(held, 'no-read'), session, b'x' * policy.MAX_INPUT, 1)
            self.assertEqual(seen.exception.category, 'deadline')
            self.assertTrue(json.loads(seen.exception.evidence)['fence']['noRunningMembersVerified'])

    def test_unapproved_environment_is_not_inherited(self):
        with patch.dict(os.environ, {'PYTHONPATH': 'PRIVATE_CANARY', 'DOCKER_HOST': 'PRIVATE_CANARY',
                'SONAR_TOKEN': 'PRIVATE_CANARY', 'FLEETORY_PRIVATE_CANARY': 'PRIVATE_CANARY'}):
            with ExitStack() as held, self.session() as session:
                result = policy._run_owned(self.command(held, 'env'), session, b'x', 5)
        self.assertEqual(json.loads(result.stdout), {name: False for name in
            ('PYTHONPATH', 'DOCKER_HOST', 'SONAR_TOKEN', 'FLEETORY_PRIVATE_CANARY')})

    def test_runtime_pin_mismatch_refuses_before_process_creation(self):
        with patch.object(policy, '_spawn', side_effect=AssertionError('Unpinned spawn forbidden')):
            with self.assertRaises(ValueError):
                with policy.PinnedFile(self.python, 'f' * 64, True):
                    self.fail('Wrong runtime pin accepted.')
            runtime = self.root / 'runtime'
            runtime.mkdir(mode=0o700)
            executable = runtime / self.python.name
            shutil.copy2(self.python, executable)
            twin = runtime / ('hardlinked-' + self.python.name)
            os.link(executable, twin)
            with self.assertRaises(policy.files.archive.ArchiveError):
                with policy.PinnedFile(executable, sha(executable), True):
                    self.fail('Hardlinked runtime accepted.')
            twin.unlink()
            if os.name == 'posix':
                runtime.chmod(0o777)
                try:
                    with self.assertRaises(policy.files.archive.ArchiveError):
                        with policy.PinnedFile(executable, sha(executable), True):
                            self.fail('Writable runtime directory accepted.')
                finally:
                    runtime.chmod(0o700)

    def test_source_handle_inheritance_change_invalidates_pin(self):
        source = self.root / 'source.py'
        source.write_bytes(b'generated')
        with policy.PinnedFile(source, sha(source)) as pinned:
            os.set_inheritable(pinned.fd, True)
            try:
                with self.assertRaises(ValueError):
                    pinned.check()
            finally:
                os.set_inheritable(pinned.fd, False)

    def test_actual_impostor_image_is_refused_before_input_and_killed(self):
        impostors = []
        def impostor(command):
            kwargs = dict(stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0,
                cwd=command.directory, close_fds=True, env=dict(command.env))
            if os.name == 'nt':
                kwargs['creationflags'] = subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP
            else:
                kwargs['start_new_session'] = True
            child = subprocess.Popen([str(self.pwsh), '-NoLogo', '-NoProfile', '-NonInteractive', '-Command',
                '[void][Console]::ReadLine(); Start-Sleep -Seconds 20'], **kwargs)
            impostors.append(child.pid)
            return child
        with ExitStack() as held, self.session() as session:
            with patch.object(policy, '_spawn', side_effect=impostor):
                with self.assertRaises(policy.LaunchError) as seen:
                    policy._run_owned(self.command(held, 'echo'), session, b'PRIVATE_CANARY', 5)
            value = json.loads(seen.exception.evidence)
            self.assertFalse(value['processIdentityAuthenticated'])
            self.assertFalse(value['inputReleased'])
            self.assertTrue(value['fence']['noRunningMembersVerified'])
            self.assertEqual(len(impostors), 1)
            self.assertFalse(self.running(impostors[0]))

    def test_invalid_inputs_cannot_consume_a_launch_or_create_process(self):
        with ExitStack() as held, self.session() as session:
            command = self.command(held, 'echo')
            for value, seconds in ((b'', 1), (b'x' * (policy.MAX_INPUT + 1), 1), (b'x', True), (b'x', 601)):
                with self.assertRaises(ValueError):
                    policy._run_owned(command, session, value, seconds)
            self.assertFalse(session.report()['launchAttemptConsumed'])

    def test_real_native_owner_refusal_uses_fixed_arguments_and_actual_runtime_identity(self):
        repo = Path(__file__).resolve().parents[2]
        owner = repo / 'eng/pilot/Invoke-HistoricalAuditObservation.ps1'
        powershell = self.pwsh
        if os.name == 'posix':
            # Hosted installations may have writable ancestors. Do not relax the
            # pin boundary or change shared host modes: use a private fixture copy.
            distribution = self.root / 'powershell'
            shutil.copytree(powershell.parent, distribution, symlinks=True)
            for directory, _, _ in os.walk(distribution, followlinks=False):
                Path(directory).chmod(0o700)
            powershell = distribution / powershell.name
            self.assertEqual(sha(powershell), sha(self.pwsh))
        plan = {**self.plan, 'runtimes': dict(python=sha(self.python), powershell=sha(powershell))}
        with self.session(plan) as session:
            result = policy.native_refusal_probe(repo, powershell, self.python, sha(owner), session)
            self.assertEqual(result.exit_code, 1)
            value = json.loads(result.evidence)
            self.assertEqual(value['profile'], 'native-admission-refusal')
            self.assertEqual(value['osIdentity']['imageSha256'], sha(powershell))
            self.assertTrue(value['processIdentityAuthenticated'])
            self.assertFalse(value['backendNamespaceBound'])
            self.assertFalse(value['backendCleanupVerified'])

    def test_no_generic_operator_command_or_path_cli_is_exposed(self):
        run = subprocess.run([sys.executable, '-B', str(Path(policy.__file__)), '--command', 'PRIVATE_COMMAND_CANARY'],
            capture_output=True, timeout=5)
        self.assertNotEqual(run.returncode, 0)
        self.assertEqual(run.stdout, b'')
        self.assertNotIn(b'PRIVATE_COMMAND_CANARY', run.stderr)


if __name__ == '__main__':
    unittest.main()
