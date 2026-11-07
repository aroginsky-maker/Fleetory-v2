"""Actual disposable directory/handle/death contracts; no source or backend data."""
from concurrent.futures import ThreadPoolExecutor
import copy
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
import uuid
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'eng/pilot'))
import audit_control_identity as policy

REFUSALS = (ValueError, OSError, policy.files.archive.ArchiveError)


def vector():
    return dict(schema=policy.SCHEMA, purpose=policy.PURPOSE, nonce='12345678-1234-4123-8123-123456789abc',
        revision='1' * 40, nativePlanSha256='2' * 64, codeSha256='3' * 64, probeSha256='4' * 64,
        runtimes=dict(python='5' * 64, powershell='6' * 64))


def encoded(value):
    return json.dumps(value, separators=(',', ':')).encode()


class ControlIdentityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='fleetory-control-identity-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.control = self.root / 'control'
        self.control.mkdir(mode=0o700)
        self.plan = vector()
        self.data = encoded(self.plan)
        self.pin = hashlib.sha256(self.data).hexdigest()

    def claim(self, data=None, pin=None):
        return policy.claim(self.control, self.data if data is None else data, self.pin if pin is None else pin)

    def directory(self):
        return self.control / policy.namespace_name(self.plan['nonce'])

    def held(self, session, name):
        fd = session._records[name][0]
        os.lseek(fd, 0, os.SEEK_SET)
        return os.read(fd, policy.MAX_RECORD + 1)

    def junction(self, link, target):
        if os.name == 'nt':
            pwsh = shutil.which('pwsh')
            self.assertIsNotNone(pwsh)
            helper = self.root / 'junction-helper.ps1'
            helper.write_text('param([string]$Link,[string]$Target)\n$ErrorActionPreference="Stop"\n'
                'New-Item -ItemType Junction -Path $Link -Target $Target | Out-Null\n', encoding='utf-8')
            result = subprocess.run([pwsh, '-NoLogo', '-NoProfile', '-File', str(helper), '-Link', str(link), '-Target', str(target)],
                capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, 'Generated junction could not be created.')
            self.addCleanup(lambda: os.rmdir(link) if link.exists() else None)
        else:
            link.symlink_to(target, target_is_directory=True)
            self.addCleanup(lambda: link.unlink() if link.is_symlink() else None)

    def test_frozen_plan_and_records_hold_distinct_directory_and_file_handles(self):
        data = bytearray(self.data)
        with self.claim(data) as session:
            data[:] = b'x' * len(data)
            reservation = json.loads(self.held(session, 'reservation.json'))
            self.assertEqual(reservation['planSha256'], self.pin)
            self.assertEqual(reservation['supervisorPid'], os.getpid())
            self.assertEqual(reservation['runtimes'], self.plan['runtimes'])
            self.assertTrue(session.report()['directoryHandlesHeld'])
            self.assertTrue(session.report()['recordHandlesHeld'])
            self.assertTrue(session.report()['nonceConsumed'])
        self.assertEqual(json.loads((self.directory() / 'reservation.json').read_bytes()), reservation)

    def test_bind_assertion_is_immutable_and_does_not_authenticate_process_or_launch(self):
        with self.claim() as session:
            result = session.bind_assertion(12345, time.time_ns(), self.plan['runtimes']['powershell'])
            record = json.loads(self.held(session, 'binding.json'))
            self.assertEqual(record['assertedChildPid'], 12345)
            self.assertEqual(record['reservationSha256'], result['reservationSha256'])
            self.assertIsNotNone(result['bindingSha256'])
            for name in ('processIdentityAuthenticated', 'runtimeContinuityVerified', 'launchAuthorized',
                'backendNamespaceBound', 'processSupervisionVerified', 'cleanupAuthorized', 'originalInputsRead',
                'originalPrivatePkiUsed', 'fullSystemRecoveryVerified', 'phase7Complete'):
                self.assertIs(result[name], False)
            with self.assertRaises(ValueError):
                session.bind_assertion(12346, time.time_ns(), self.plan['runtimes']['powershell'])
            self.assertEqual(json.loads(self.held(session, 'binding.json')), record)

    def test_same_nonce_and_changed_plan_cannot_reclaim_closed_namespace(self):
        with self.claim():
            pass
        original = (self.directory() / 'reservation.json').read_bytes()
        for data in (self.data, encoded({**self.plan, 'codeSha256': 'f' * 64})):
            with self.assertRaises(OSError):
                with self.claim(data, hashlib.sha256(data).hexdigest()):
                    self.fail('Consumed namespace was adopted.')
        self.assertEqual((self.directory() / 'reservation.json').read_bytes(), original)

    def test_preexisting_unmarked_directory_is_never_adopted_or_deleted(self):
        self.directory().mkdir()
        foreign = self.directory() / 'foreign'
        foreign.write_bytes(b'foreign')
        with self.assertRaises(OSError):
            with self.claim():
                self.fail('Unmarked namespace adopted.')
        self.assertEqual(foreign.read_bytes(), b'foreign')

    def test_preexisting_file_is_not_adopted_or_modified(self):
        self.directory().write_bytes(b'foreign')
        with self.assertRaises(OSError):
            with self.claim():
                self.fail('File namespace adopted.')
        self.assertEqual(self.directory().read_bytes(), b'foreign')

    def test_preexisting_corrupt_marker_is_not_repaired_or_deleted(self):
        self.directory().mkdir()
        path = self.directory() / 'reservation.json'
        path.write_bytes(b'{')
        with self.assertRaises(OSError):
            with self.claim():
                self.fail('Corrupt namespace repaired.')
        self.assertEqual(path.read_bytes(), b'{')

    def test_namespace_link_preserves_foreign_target(self):
        target = self.root / 'foreign'
        target.mkdir()
        self.junction(self.directory(), target)
        with self.assertRaises(REFUSALS):
            with self.claim():
                self.fail('Namespace link adopted.')
        self.assertEqual(list(target.iterdir()), [])

    def test_root_link_is_refused_before_any_namespace_creation(self):
        link = self.root / 'alias'
        self.junction(link, self.control)
        with self.assertRaises(REFUSALS):
            with policy.claim(link, self.data, self.pin):
                self.fail('Root link accepted.')
        self.assertEqual(list(self.control.iterdir()), [])

    def test_held_parent_directory_replacement_is_detected(self):
        lease = policy.DirectoryLease(self.control)
        self.addCleanup(lease.close)
        self.control.rename(self.root / 'held-parent')
        self.control.mkdir(mode=0o700)
        (self.control / 'foreign').write_bytes(b'foreign')
        with self.assertRaises(REFUSALS):
            lease.check()
        self.assertEqual((self.control / 'foreign').read_bytes(), b'foreign')

    def test_held_namespace_directory_replacement_is_detected(self):
        directory = self.control / 'generated'
        directory.mkdir(mode=0o700)
        lease = policy.DirectoryLease(directory)
        self.addCleanup(lease.close)
        directory.rename(self.control / 'held-namespace')
        directory.mkdir(mode=0o700)
        with self.assertRaises(REFUSALS):
            lease.check()

    def test_closed_directory_or_session_cannot_be_used(self):
        lease = policy.DirectoryLease(self.control)
        lease.close()
        with self.assertRaises(REFUSALS):
            lease.check()
        with self.claim() as session:
            pass
        with self.assertRaises(REFUSALS):
            session.report()

    def test_directory_handles_are_not_inherited(self):
        with self.claim() as session:
            for directory in (session._parent, session._directory):
                if os.name == 'nt':
                    self.assertEqual(directory.windows.identity_now(), directory.identity)
                else:
                    self.assertFalse(os.get_inheritable(directory.fd))
            for fd, _ in session._records.values():
                self.assertFalse(os.get_inheritable(fd))

    def test_multiple_threads_have_exactly_one_namespace_winner(self):
        def attempt(_):
            try:
                with self.claim():
                    return True
            except REFUSALS:
                return False
        with ThreadPoolExecutor(max_workers=8) as pool:
            self.assertEqual(sum(pool.map(attempt, range(8))), 1)

    def test_pin_mismatch_refuses_before_creating_any_namespace(self):
        with self.assertRaises(ValueError):
            with self.claim(pin='0' * 64):
                self.fail('Wrong plan pin accepted.')
        self.assertEqual(list(self.control.iterdir()), [])

    def test_plan_shape_types_scope_and_hashes_fail_before_filesystem_use(self):
        mutations = [dict(extra=True), dict(schema='wrong'), dict(purpose='wrong'), dict(nonce='../escape'),
            dict(nonce='00000000-0000-0000-0000-000000000000'), dict(nonce=self.plan['nonce'].upper()),
            dict(revision='f' * 39), dict(codeSha256='A' * 64), dict(nativePlanSha256=False),
            dict(probeSha256='short'), dict(runtimes={'python': '5' * 64}),
            dict(runtimes={'python': '5' * 64, 'powershell': '6' * 64, 'extra': '7' * 64})]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                data = encoded({**self.plan, **mutation})
                with self.assertRaises(ValueError):
                    with self.claim(data, hashlib.sha256(data).hexdigest()):
                        self.fail('Unsafe plan accepted.')
        self.assertEqual(list(self.control.iterdir()), [])

    def test_oversize_duplicate_fields_and_nonfinite_json_refused(self):
        values = [b'x' * (policy.MAX_RECORD + 1), self.data[:-1] + b',"purpose":"duplicate"}',
            self.data.replace(b'"1' + b'1' * 39 + b'"', b'NaN')]
        for data in values:
            with self.assertRaises(ValueError):
                with self.claim(data, hashlib.sha256(data).hexdigest()):
                    self.fail('Malformed plan accepted.')

    def test_invalid_pid_assertion_consumes_binding_attempt(self):
        with self.claim() as session:
            with self.assertRaises(ValueError):
                session.bind_assertion(True, time.time_ns(), self.plan['runtimes']['powershell'])
            with self.assertRaises(ValueError):
                session.bind_assertion(12345, time.time_ns(), self.plan['runtimes']['powershell'])
            self.assertNotIn('binding.json', session._records)

    def test_bad_time_and_runtime_assertions_do_not_publish_binding(self):
        for field in ('past', 'future', 'runtime'):
            plan = copy.deepcopy(self.plan)
            plan['nonce'] = str(uuid.uuid4())
            data = encoded(plan)
            with policy.claim(self.control, data, hashlib.sha256(data).hexdigest()) as session:
                stamp = session._created - 1 if field == 'past' else time.time_ns() + 60_000_000_000 if field == 'future' else time.time_ns()
                runtime = 'f' * 64 if field == 'runtime' else self.plan['runtimes']['powershell']
                with self.assertRaises(ValueError):
                    session.bind_assertion(12345, stamp, runtime)
                self.assertNotIn('binding.json', session._records)

    def test_short_writes_are_completed_before_receipt(self):
        actual = policy.os.write
        with patch.object(policy.os, 'write', side_effect=lambda fd, data: actual(fd, data[:7])):
            with self.claim() as session:
                self.assertTrue(session.report()['nonceConsumed'])

    def test_zero_write_retains_consumed_namespace(self):
        with patch.object(policy.os, 'write', return_value=0):
            with self.assertRaises(ValueError):
                with self.claim():
                    self.fail('Zero write accepted.')
        self.assertTrue(self.directory().exists())
        with self.assertRaises(OSError):
            with self.claim():
                self.fail('Failed write claim reused.')

    def test_flush_failure_keeps_consumed_reservation(self):
        with patch.object(policy.os, 'fsync', side_effect=OSError('Generated flush fault')):
            with self.assertRaises(OSError):
                with self.claim():
                    self.fail('Flush failure accepted.')
        self.assertTrue(self.directory().exists())
        with self.assertRaises(OSError):
            with self.claim():
                self.fail('Flush failure nonce reused.')

    def test_record_corruption_through_held_fd_is_detected(self):
        with self.claim() as session:
            fd = session._records['reservation.json'][0]
            os.lseek(fd, 0, os.SEEK_SET)
            os.write(fd, b'x')
            with self.assertRaises(ValueError):
                session.report()

    def test_record_truncation_through_held_fd_is_detected(self):
        with self.claim() as session:
            os.ftruncate(session._records['reservation.json'][0], 0)
            with self.assertRaises(ValueError):
                session.report()

    def test_replaced_or_locked_record_cannot_be_adopted(self):
        with self.claim() as session:
            name = self.directory() / 'reservation.json'
            original = self.held(session, 'reservation.json')
            try:
                name.rename(self.directory() / 'held-record.json')
            except OSError as error:
                self.assertEqual(os.name, 'nt')
                self.assertIn(error.winerror, (5, 32, 33))
                session.check()
            else:
                name.write_bytes(original)
                with self.assertRaises(ValueError):
                    session.check()

    def test_hardlinked_or_locked_record_is_not_accepted(self):
        with self.claim() as session:
            try:
                os.link(self.directory() / 'reservation.json', self.directory() / 'hardlink.json')
            except OSError as error:
                self.assertEqual(os.name, 'nt')
                self.assertIn(error.winerror, (5, 32, 33))
                session.check()
            else:
                with self.assertRaises(ValueError):
                    session.check()

    def test_record_handle_inheritance_change_is_refused(self):
        with self.claim() as session:
            fd = session._records['reservation.json'][0]
            os.set_inheritable(fd, True)
            try:
                with self.assertRaises(ValueError):
                    session.check()
            finally:
                os.set_inheritable(fd, False)

    def test_directory_handle_inheritance_change_is_refused(self):
        with self.claim() as session:
            directory = session._directory
            if os.name == 'nt':
                from ctypes import wintypes
                setter = directory.windows._kernel.SetHandleInformation
                setter.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD]
                setter.restype = wintypes.BOOL
                def inherited(value):
                    self.assertTrue(setter(directory.windows._handle, 1, int(value)))
            else:
                def inherited(value):
                    os.set_inheritable(directory.fd, value)
            inherited(True)
            try:
                with self.assertRaises(ValueError):
                    session.check()
            finally:
                inherited(False)

    def test_inheritance_setup_failure_closes_newly_allocated_descriptors(self):
        opened = []
        owner, name = (policy.files, 'windows_create_new') if os.name == 'nt' else (policy.os, 'open')
        actual = getattr(owner, name)
        def allocate(*args, **kwargs):
            fd = actual(*args, **kwargs)
            opened.append(fd)
            return fd
        with patch.object(owner, name, side_effect=allocate), patch.object(policy.os, 'set_inheritable', side_effect=OSError('Generated inheritance fault')):
            with self.assertRaises(OSError):
                with self.claim():
                    self.fail('Inheritance failure accepted.')
        self.assertGreater(len(opened), 0)
        for fd in opened:
            with self.assertRaises(OSError):
                os.fstat(fd)

    def test_forced_writer_death_leaves_nonce_consumed_and_reservation_intact(self):
        self.writer_death('reservation', b'RESERVATION_READY')

    def test_forced_bound_writer_death_preserves_unverified_binding_and_consumed_nonce(self):
        self.writer_death('binding', b'BINDING_READY')
        record = json.loads((self.directory() / 'binding.json').read_bytes())
        for name in ('processIdentityAuthenticated', 'launchAuthorized', 'cleanupAuthorized'):
            self.assertIs(record[name], False)

    def writer_death(self, mode, ready):
        worker = Path(__file__).resolve().with_name('audit_control_identity_worker.py')
        process = subprocess.Popen([sys.executable, '-B', str(worker), mode], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=self.control)
        try:
            process.stdin.write(self.data)
            process.stdin.close()
            self.assertEqual(process.stdout.readline().strip(), ready)
            process.kill()
            process.wait(timeout=5)
            self.assertEqual(process.stderr.read(), b'')
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
            process.stdout.close()
            process.stderr.close()
        record = json.loads((self.directory() / 'reservation.json').read_bytes())
        self.assertEqual(record['planSha256'], self.pin)
        with self.assertRaises(OSError):
            with self.claim():
                self.fail('Dead writer reservation was reset.')

    def test_cli_does_not_accept_operator_paths_or_launch_arguments(self):
        result = subprocess.run([sys.executable, '-B', str(Path(policy.__file__)), '--root', str(self.root)],
            capture_output=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b'')
        self.assertNotIn(str(self.root).encode(), result.stderr)


if __name__ == '__main__':
    unittest.main()
