"""Actual fixed owner, pinned source inventory and held payload/control identities. No backend."""
import ast
from contextlib import ExitStack
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / 'eng/pilot'))
import audit_control_identity as control
import audit_launch_bundle as bundle
import audit_payload_binding as binding
import audit_payload_launch as launch
import audit_process_fence as process

NONCE = '12345678-1234-4123-8123-123456789abc'
OTHER = 'abcdefab-1234-4123-8123-123456789abc'
REVISION = '1' * 40


class PayloadLaunchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='fleetory-payload-binding-')
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name).resolve() / 'repo'
        self.repo.mkdir(mode=0o700)
        (self.repo / 'artifacts').mkdir(mode=0o700)
        for name in bundle.SOURCES:
            target = self.repo / name
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            shutil.copyfile(REPO / name, target)
        self.python = Path(sys.executable).resolve()
        self.refresh()

    def refresh(self):
        self.manifest = bundle.measure(self.repo, self.python, NONCE, REVISION)
        self.pin = hashlib.sha256(self.manifest).hexdigest()
        value = json.loads(self.manifest)
        self.plan = dict(schema=control.SCHEMA, purpose=control.PURPOSE, nonce=NONCE, revision=REVISION,
            nativePlanSha256='2' * 64, codeSha256=self.pin, probeSha256='3' * 64,
            runtimes=dict(python=value['pythonSha256'], powershell=value['pythonSha256']))

    def session(self):
        data = bundle.canonical(self.plan)
        return control.claim(self.repo / 'artifacts', data, hashlib.sha256(data).hexdigest())

    def reserve(self, session):
        return launch.reserve_payload(self.repo, self.python, self.manifest, self.pin, session)

    def mutate_owner(self, old, new):
        path = self.repo / 'eng/pilot/audit_payload_owner.py'
        text = path.read_text()
        self.assertIn(old, text)
        path.write_text(text.replace(old, new, 1))
        self.refresh()

    def refused(self, session):
        with self.assertRaises(process.LaunchError) as seen:
            self.reserve(session)
        evidence = json.loads(seen.exception.evidence)
        self.assertTrue(evidence['fence']['noRunningMembersVerified'])
        self.assertTrue(session.report()['launchAttemptConsumed'])
        self.assertFalse(evidence['payload']['payloadRemovedVerified'])
        self.assertFalse(evidence['backendCleanupVerified'])
        self.assertNotIn('PRIVATE_CANARY', str(seen.exception))
        return evidence

    def test_actual_owner_binds_held_payload_and_removes_only_after_flushed_release(self):
        with self.session() as session:
            result = self.reserve(session)
            value = json.loads(result.evidence)
            self.assertEqual((result.exit_code, result.stderr), (0, b''))
            self.assertTrue(value['processIdentityAuthenticated'])
            self.assertTrue(value['entrypointPinsMatched'])
            self.assertTrue(value['payload']['declaredComponentFilesPinned'])
            self.assertTrue(value['payload']['payloadNamespaceBound'])
            self.assertTrue(value['payload']['payloadRemovedVerified'])
            self.assertEqual(value['payload']['bundleSha256'], self.pin)
            for name in ('backendNamespaceBound', 'backendCleanupVerified', 'runtimeDependenciesAuthenticated',
                    'originalInputsRead', 'cleanupAuthorized'):
                self.assertIs(value['payload'][name], False)
            saved = json.loads(session._records['payload-binding.json'][1])
            release = json.loads(session._records['payload-release.json'][1])
            self.assertEqual(saved['actualOwnedProcess'], value['osIdentity'])
            self.assertEqual(saved['controlDirectorySha256'], binding.directory_hash(session._directory))
            self.assertEqual(saved['reservationSha256'], session.report()['reservationSha256'])
            self.assertEqual(release['payloadBindingSha256'], hashlib.sha256(session._records['payload-binding.json'][1]).hexdigest())
            self.assertFalse((self.repo / 'artifacts' / binding.payload_name(NONCE)).exists())
            self.assertTrue((session._directory.path / 'payload-binding.json').is_file())

    def test_replay_cannot_create_a_second_owner(self):
        with self.session() as session:
            self.reserve(session)
            with patch.object(process, '_spawn', side_effect=AssertionError('Replay forbidden')):
                with self.assertRaises(ValueError):
                    self.reserve(session)

    def test_fixed_inventory_matches_all_local_imports_including_platform_branches(self):
        names = {Path(name).stem for name in bundle.SOURCES}
        for relative in bundle.SOURCES:
            tree = ast.parse((REPO / relative).read_text())
            for node in ast.walk(tree):
                imported = [item.name for item in node.names] if isinstance(node, ast.Import) else (
                    [node.module] if isinstance(node, ast.ImportFrom) and node.module else [])
                for name in imported:
                    if (REPO / 'eng/pilot' / (name + '.py')).is_file():
                        self.assertIn(name, names)

    def test_manifest_paths_missing_roles_and_extra_roles_refused_before_spawn(self):
        base = json.loads(self.manifest)
        changes = []
        missing = copy.deepcopy(base); missing['sources'].pop(bundle.SOURCES[0]); changes.append(missing)
        for name in ('../PRIVATE_CANARY', 'eng/pilot/unknown.py', 'eng/pilot/AUDIT_PAYLOAD_OWNER.py'):
            bad = copy.deepcopy(base); bad['sources'][name] = 'a' * 64; changes.append(bad)
        for value in changes:
            data = bundle.canonical(value)
            with self.assertRaises(ValueError):
                bundle.admit(data, hashlib.sha256(data).hexdigest())

    def test_manifest_duplicate_fields_wrong_pin_types_and_bounds_refused(self):
        for data, pin in ((self.manifest, 'f' * 64), (b'', self.pin), (b'x' * 8193, self.pin)):
            with self.assertRaises(ValueError):
                bundle.admit(data, pin)
        for field, value in (('nonce', True), ('revision', 'z' * 40), ('pythonSha256', 42), ('schema', 'other')):
            bad = json.loads(self.manifest); bad[field] = value
            data = bundle.canonical(bad)
            with self.assertRaises((ValueError, TypeError)):
                bundle.admit(data, hashlib.sha256(data).hexdigest())
        data = self.manifest[:-1] + b',"nonce":"' + NONCE.encode() + b'"}'
        with self.assertRaises(ValueError):
            bundle.admit(data, hashlib.sha256(data).hexdigest())

    def test_bundle_must_match_consumed_control_nonce_revision_and_runtime(self):
        for field, value in (('nonce', OTHER), ('revision', '2' * 40), ('pythonSha256', 'f' * 64)):
            bad = json.loads(self.manifest); bad[field] = value
            data = bundle.canonical(bad); pin = hashlib.sha256(data).hexdigest()
            with self.session() as session, patch.object(process, '_spawn', side_effect=AssertionError('Mismatch spawn')):
                with self.assertRaises(ValueError):
                    launch.reserve_payload(self.repo, self.python, data, pin, session)
                self.assertFalse(session.report()['launchAttemptConsumed'])
            target = (self.repo / 'artifacts' / control.namespace_name(NONCE)).resolve(strict=True)
            self.assertTrue(target.is_relative_to(self.repo.resolve(strict=True)))
            shutil.rmtree(target)

    def test_changed_source_bytes_refused_before_owner_creation(self):
        (self.repo / bundle.SOURCES[0]).write_bytes(b'changed')
        with self.session() as session, patch.object(process, '_spawn', side_effect=AssertionError('Changed source spawn')):
            with self.assertRaises(ValueError):
                self.reserve(session)
            self.assertFalse(session.report()['launchAttemptConsumed'])

    def test_hardlinked_source_refused_even_when_content_pin_matches(self):
        source = self.repo / bundle.SOURCES[0]
        os.link(source, self.repo / 'hardlink')
        with self.session() as session, patch.object(process, '_spawn', side_effect=AssertionError('Hardlinked spawn')):
            with self.assertRaises(ValueError):
                self.reserve(session)

    def test_preexisting_directory_and_foreign_marker_are_not_adopted_or_removed(self):
        path = self.repo / 'artifacts' / binding.payload_name(NONCE)
        path.mkdir(mode=0o700)
        sentinel = path / 'foreign'
        sentinel.write_bytes(b'foreign')
        with self.session() as session:
            self.refused(session)
            self.assertEqual(sentinel.read_bytes(), b'foreign')
            self.assertNotIn('payload-binding.json', session._records)

    def test_preexisting_regular_file_is_not_removed(self):
        path = self.repo / 'artifacts' / binding.payload_name(NONCE)
        path.write_bytes(b'foreign')
        with self.session() as session:
            self.refused(session)
            self.assertEqual(path.read_bytes(), b'foreign')

    def test_preexisting_binding_record_cannot_be_adopted_or_overwritten(self):
        with self.session() as session:
            path = session._directory.path / 'payload-binding.json'
            path.write_bytes(b'foreign')
            self.refused(session)
            self.assertEqual(path.read_bytes(), b'foreign')
            self.assertNotIn('payload-binding.json', session._records)
            self.assertNotIn('payload-release.json', session._records)

    def test_held_repository_root_replacement_is_blocked_or_refused(self):
        with self.session() as session:
            with bundle.HeldBundle(self.repo, self.python, self.manifest, self.pin, session) as held:
                moved = self.repo.with_name('moved-repository')
                try:
                    self.repo.rename(moved)
                except PermissionError:
                    held.check()
                    return
                self.repo.mkdir(mode=0o700)
                with self.assertRaises(ValueError):
                    held.check()

    def test_owner_cannot_forge_a_different_process_pid(self):
        self.mutate_owner('with binding.OwnedPayload(repository, value) as owned:',
            "binding.os.getpid = lambda: 42\n    with binding.OwnedPayload(repository, value) as owned:")
        with self.session() as session:
            self.refused(session)
            self.assertNotIn('payload-release.json', session._records)

    def test_ready_nonce_cannot_select_a_foreign_namespace(self):
        self.mutate_owner("nonce=value['nonce'],\n            ownerSha256", "nonce='" + OTHER + "',\n            ownerSha256")
        with self.session() as session:
            self.refused(session)
            self.assertNotIn('payload-binding.json', session._records)

    def test_owner_marker_cannot_replace_the_controller_binding(self):
        self.mutate_owner('with binding.OwnedPayload(repository, value) as owned:',
            "value['controlSha256'] = 'f' * 64\n    with binding.OwnedPayload(repository, value) as owned:")
        with self.session() as session:
            self.refused(session)
            self.assertNotIn('payload-binding.json', session._records)

    def test_namespace_replacement_with_identical_marker_bytes_is_refused(self):
        self.mutate_owner('ready = dict(schema=',
            "import shutil\n        owned.pin.close()\n        moved = owned.path.with_name('moved-original')\n        owned.path.rename(moved)\n        owned.path.mkdir(mode=0o700)\n        shutil.copyfile(moved / binding.MARKER, owned.path / binding.MARKER)\n        ready = dict(schema=")
        with self.session() as session:
            self.refused(session)
            self.assertNotIn('payload-binding.json', session._records)
            self.assertTrue((self.repo / 'artifacts/moved-original' / binding.MARKER).is_file())

    def test_binding_flush_failure_refuses_release_and_preserves_consumption(self):
        actual = control.os.fsync
        with self.session() as session:
            def failing(fd):
                if 'payload-binding.json' in session._records:
                    raise OSError('PRIVATE_CANARY')
                return actual(fd)
            with patch.object(control.os, 'fsync', side_effect=failing):
                self.refused(session)
            self.assertIn('payload-binding.json', session._records)
            self.assertNotIn('payload-release.json', session._records)

    def test_owner_exit_before_ready_is_not_cleanup_evidence(self):
        self.mutate_owner('ready = dict(schema=', 'sys.exit(17)\n        ready = dict(schema=')
        existing_threads = set(threading.enumerate())
        with self.session() as session:
            self.refused(session)
            self.assertTrue((self.repo / 'artifacts' / binding.payload_name(NONCE) / binding.MARKER).is_file())
            self.assertFalse(any(thread not in existing_threads and '(_write)' in thread.name for thread in threading.enumerate()))

    def test_forced_owner_death_after_binding_does_not_authorize_parent_cleanup(self):
        actual = binding.BoundPayload.release
        def killed(owned):
            owned.process.kill()
            if os.name == 'posix':
                while not owned.fence.exited():
                    time.sleep(0.001)
            else:
                owned.process.wait(timeout=3)
            return actual(owned)
        with self.session() as session, patch.object(binding.BoundPayload, 'release', side_effect=killed, autospec=True):
            self.refused(session)
            self.assertIn('payload-binding.json', session._records)
            self.assertNotIn('payload-release.json', session._records)
            self.assertTrue((self.repo / 'artifacts' / binding.payload_name(NONCE)).is_dir())

    def test_extra_file_prevents_recursive_cleanup(self):
        self.mutate_owner('owned.remove()', "(owned.path / 'foreign').write_bytes(b'foreign')\n        owned.remove()")
        with self.session() as session:
            self.refused(session)
            self.assertEqual((self.repo / 'artifacts' / binding.payload_name(NONCE) / 'foreign').read_bytes(), b'foreign')

    def test_forged_closed_frame_without_deletion_is_refused(self):
        self.mutate_owner('owned.remove()', 'owned.check()')
        with self.session() as session:
            self.refused(session)
            self.assertIn('payload-release.json', session._records)
            self.assertTrue((self.repo / 'artifacts' / binding.payload_name(NONCE)).is_dir())

    def test_extra_original_data_or_root_fields_are_not_in_the_protocol(self):
        value = dict(schema='fleetory.audit-payload-reservation.v1', nonce=NONCE,
            controlSha256='a' * 64, controlDirectorySha256='b' * 64, bundleSha256='c' * 64)
        for key in ('archiveBase64', 'root', 'endpoint', 'command'):
            data = bundle.canonical({**value, key: 'PRIVATE_CANARY'})
            with self.assertRaises(ValueError):
                binding.header(data, hashlib.sha256(data).hexdigest())

    def test_oversized_or_unterminated_frames_refused(self):
        import io
        for data in (b'', b'x', b'x' * binding.MAX_FRAME + b'\n'):
            with self.assertRaises(ValueError):
                binding.read_frame(io.BytesIO(data))

    def test_library_has_no_generic_operator_command_cli(self):
        run = subprocess.run([self.python, '-B', str(Path(launch.__file__)), '--root', 'PRIVATE_CANARY'],
            capture_output=True, timeout=5)
        self.assertNotEqual(run.returncode, 0)
        self.assertEqual(run.stdout, b'')
        self.assertNotIn(b'PRIVATE_CANARY', run.stderr)


if __name__ == '__main__':
    unittest.main()
