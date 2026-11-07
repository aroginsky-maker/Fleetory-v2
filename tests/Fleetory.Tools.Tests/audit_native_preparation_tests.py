"""Close-only metadata contracts; no backend, archive capture or private key."""
import ast
import base64
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / 'eng/pilot'))
import audit_native_preparation as prep
import audit_launch_bundle as bundle
from historical_audit_restore_tests import fixture
from audit_backend_binding_tests import control_plan


def vector():
    plan, _ = fixture()
    native = prep.canonical(plan)
    value = dict(schema=prep.SCHEMA, nonce=plan['nonce'], controlSha256='a' * 64,
        planBase64=base64.b64encode(native).decode('ascii'), gitSha256='c' * 64)
    return value, native


class PreparationTests(unittest.TestCase):
    def setUp(self):
        self.value, self.native = vector()
        self.pin = prep.packet.digest(self.native)
        self.data = prep.canonical(self.value)
        self.info = prep.header(self.data, self.pin)

    def closing(self):
        return dict(schema='fleetory.native-preparation-close.v1', nonce=self.info['nonce'],
            controlSha256=self.info['controlSha256'], headerSha256=self.info['headerSha256'],
            readySha256='b' * 64, decision='close-without-input')

    def test_header_pins_plan_and_control_metadata_without_private_body(self):
        self.assertEqual(self.info['nativePlanSha256'], self.pin)
        self.assertEqual(self.info['headerSha256'], prep.packet.digest(self.data))
        self.assertEqual(self.info['nonce'], self.value['nonce'])
        self.assertEqual(self.info['gitSha256'], self.value['gitSha256'])
        self.assertEqual(set(self.value), {'schema', 'nonce', 'controlSha256', 'planBase64', 'gitSha256'})

    def test_old_header_or_missing_git_pin_is_refused(self):
        old = {**self.value, 'schema': 'fleetory.native-preparation-header.v1'}
        missing = {k: v for k, v in self.value.items() if k != 'gitSha256'}
        for value in (old, missing):
            with self.subTest(fields=value.keys()), self.assertRaises(ValueError):
                prep.header(prep.canonical(value), self.pin)

    def test_git_descriptor_is_held_and_changed_bytes_are_refused(self):
        with tempfile.TemporaryDirectory(prefix='fleetory-git-held-') as temp:
            path = Path(temp).resolve() / ('git.exe' if os.name == 'nt' else 'git')
            path.write_bytes(b'generated executable canary')
            path.chmod(0o700)
            expected = prep.packet.digest(path.read_bytes())
            with prep.ExitStack() as held:
                pinned = prep._pin_git(held, path, expected)
                self.assertEqual(pinned.digest, expected)
                self.assertFalse(os.get_inheritable(pinned.fd))
                try:
                    path.write_bytes(b'changed executable canary')
                except OSError:
                    pinned.check()  # Windows must deny the write while held.
                else:
                    with self.assertRaises(ValueError):
                        pinned.check()

    def test_git_wrong_hash_relative_name_and_hardlink_are_refused(self):
        with tempfile.TemporaryDirectory(prefix='fleetory-git-refusals-') as temp:
            root = Path(temp).resolve()
            path = root / ('git.exe' if os.name == 'nt' else 'git')
            path.write_bytes(b'generated executable canary')
            path.chmod(0o700)
            expected = prep.packet.digest(path.read_bytes())
            for selected, pin in ((path, '0' * 64), (Path(path.name), expected), (root / 'other.exe', expected)):
                with self.subTest(selected=selected), prep.ExitStack() as held, self.assertRaises(ValueError):
                    prep._pin_git(held, selected, pin)
            alias = root / 'alias'
            os.link(path, alias)
            with prep.ExitStack() as held, self.assertRaises(ValueError):
                prep._pin_git(held, path, expected)

    def test_archive_key_endpoint_and_root_fields_are_not_admitted(self):
        for name in ('archiveBase64', 'privateKey', 'endpoint', 'root', 'command'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                prep.header(prep.canonical({**self.value, name: 'generated-canary'}), self.pin)

    def test_wrong_control_types_schema_nonce_and_plan_pin_refused(self):
        for field, value in (('schema', 'full-restore'), ('nonce', 'ABCDEFAB-1234-4123-8123-123456789ABC'),
                ('nonce', True), ('controlSha256', 'A' * 64), ('planBase64', True), ('gitSha256', 'C' * 64), ('gitSha256', True)):
            changed = {**self.value, field: value}
            with self.subTest(field=field), self.assertRaises((ValueError, TypeError)):
                prep.header(prep.canonical(changed), self.pin)
        with self.assertRaises(ValueError):
            prep.header(self.data, 'f' * 64)

    def test_nonce_substitution_across_plan_and_header_refused(self):
        changed = {**self.value, 'nonce': 'abcdefab-1234-4123-8123-123456789abc'}
        with self.assertRaises(ValueError):
            prep.header(prep.canonical(changed), self.pin)

    def test_duplicate_fields_noncanonical_base64_and_bound_refused(self):
        cases = [self.data[:-1] + b',"nonce":"duplicate"}', self.data + b' ' * prep.MAX_HEADER,
            prep.canonical({**self.value, 'planBase64': self.value['planBase64'] + '\n'})]
        for raw in cases:
            with self.subTest(size=len(raw)), self.assertRaises(ValueError):
                prep.header(raw, self.pin)

    def test_old_native_plan_and_promoted_scope_refused(self):
        for change in ('schema', 'scope'):
            native = json.loads(self.native)
            if change == 'schema':
                native['schema'] = 'fleetory.historical-audit-restore-plan.v1'
            else:
                native['scope']['executionAuthorized'] = True
            raw = prep.canonical(native)
            value = {**self.value, 'planBase64': base64.b64encode(raw).decode('ascii')}
            with self.subTest(change=change), self.assertRaises(ValueError):
                prep.header(prep.canonical(value), prep.packet.digest(raw))

    def test_only_close_without_input_is_accepted(self):
        self.assertEqual(prep.close_frame(prep.canonical(self.closing()), self.info, 'b' * 64), {'verified': True})
        for decision in ('restore', 'release', 'continue', True):
            with self.subTest(decision=decision), self.assertRaises(ValueError):
                prep.close_frame(prep.canonical({**self.closing(), 'decision': decision}), self.info, 'b' * 64)

    def test_close_replay_under_another_header_ready_or_control_refused(self):
        for field in ('nonce', 'controlSha256', 'headerSha256', 'readySha256'):
            changed = {**self.closing(), field: 'foreign'}
            with self.subTest(field=field), self.assertRaises(ValueError):
                prep.close_frame(prep.canonical(changed), self.info, 'b' * 64)

    def test_close_duplicate_extra_and_private_payload_refused(self):
        raw = prep.canonical(self.closing())
        cases = [raw[:-1] + b',"decision":"close-without-input"}', raw + b' ' * prep.MAX_FRAME,
            prep.canonical({**self.closing(), 'archiveBase64': 'generated-canary'})]
        for data in cases:
            with self.subTest(size=len(data)), self.assertRaises(ValueError):
                prep.close_frame(data, self.info, 'b' * 64)

    def test_fixed_preparation_inventory_covers_local_python_imports(self):
        names = {Path(name).stem for name in prep.SOURCES if name.endswith('.py')}
        self.assertEqual(len(prep.SOURCES), 32)
        self.assertEqual(len(bundle.SOURCES), 11)
        for name in names:
            for node in ast.walk(ast.parse((REPO / 'eng/pilot' / (name + '.py')).read_text())):
                imported = [n.name for n in node.names] if isinstance(node, ast.Import) else (
                    [node.module] if isinstance(node, ast.ImportFrom) and node.module else [])
                for local in imported:
                    if (REPO / 'eng/pilot' / (local + '.py')).is_file():
                        self.assertIn(local, names)

    def pumps(self, session=None):
        if session is None:
            session = SimpleNamespace(_plan={'nativePlanSha256': self.pin})
        child = SimpleNamespace(pid=12345, stdin=io.BytesIO())
        command = SimpleNamespace(check=lambda: None)
        return prep._PreparationPumps(child, self.data + b'\n', command, session,
            SimpleNamespace(identity=lambda *_: {'actualImageMatched': True}), time.monotonic_ns(), 30)

    def ready(self):
        return dict(schema='fleetory.native-preparation-ready.v1', **self.info, pid=12345,
            privateInputsAccepted=False, payloadCreated=False, backendCreated=False)

    def test_forged_child_pid_or_backend_claim_is_refused_before_record(self):
        for field, value in (('pid', 12346), ('pid', True), ('privateInputsAccepted', True),
                ('backendCreated', True), ('payloadCreated', True), ('headerSha256', 'f' * 64), ('gitSha256', 'f' * 64)):
            pump = self.pumps()
            changed = {**self.ready(), field: value}
            with self.subTest(field=field), self.assertRaises(ValueError):
                pump._bind_ready(changed, prep.canonical(changed))
            self.assertFalse(pump.ready.is_set())

    def test_extra_ready_fields_and_partial_frame_do_not_release_close(self):
        pump = self.pumps()
        with self.assertRaises(ValueError):
            pump._on_output('stdout-bound', prep.canonical({**self.ready(), 'root': '/unreviewed'}) + b'\n')
        partial = self.pumps()
        partial._on_output('stdout-bound', prep.canonical(self.ready()))
        self.assertFalse(partial.ready.is_set())
        with self.assertRaises(ValueError):
            partial._on_output('stdout-bound', b'x' * prep.MAX_FRAME)

    def test_post_close_record_flush_deadline_sends_no_close_frame(self):
        with tempfile.TemporaryDirectory(prefix='fleetory-native-close-expiry-') as temp:
            plan = control_plan(self.value['nonce'])
            plan['nativePlanSha256'] = self.pin
            data = prep.canonical(plan)
            with prep.control.claim(Path(temp).resolve(), data, prep.packet.digest(data)) as session:
                pump = self.pumps(session)
                pump.ready_pin = 'b' * 64
                pump.ready.set()
                sent = []
                write = session._write_once

                def expire(name, value):
                    write(name, value)
                    if name == 'native-close.json':
                        pump.start_time -= 60_000_000_000

                with patch.object(pump, '_send', side_effect=lambda value: sent.append(value)), \
                        patch.object(session, '_write_once', side_effect=expire):
                    pump._write()
                self.assertEqual(sent, [self.data + b'\n'])
                self.assertIn('preparation-close-refused', pump.errors)
                self.assertTrue((session._directory.path / 'native-close.json').exists())

    def test_foreign_close_record_is_preserved(self):
        with tempfile.TemporaryDirectory(prefix='fleetory-native-close-foreign-') as temp:
            plan = control_plan(self.value['nonce'])
            plan['nativePlanSha256'] = self.pin
            raw = prep.canonical(plan)
            with prep.control.claim(Path(temp).resolve(), raw, prep.packet.digest(raw)) as session:
                path = session._directory.path / 'native-close.json'
                path.write_bytes(b'foreign')
                pump = self.pumps(session)
                pump.ready_pin = 'b' * 64
                pump.ready.set()
                sent = []
                with patch.object(pump, '_send', side_effect=lambda value: sent.append(value)):
                    pump._write()
                self.assertEqual(sent, [self.data + b'\n'])
                self.assertEqual(path.read_bytes(), b'foreign')
                self.assertIn('preparation-close-refused', pump.errors)

    def test_transport_callback_is_not_accepted_for_old_or_unfixed_profiles(self):
        fake = SimpleNamespace(check=lambda: None)
        for profile, factory in (('generated-worker', prep._PreparationPumps), ('native-preparation', None),
                ('native-preparation', lambda *_: None)):
            command = prep.process._Command(fake, (), (), Path('.'), {}, profile, factory)
            with self.subTest(profile=profile), self.assertRaises(ValueError):
                command.check()

    def test_fixed_editor_input_is_held_without_relaxing_recovery_paths(self):
        with tempfile.TemporaryDirectory(prefix='fleetory-editor-pin-') as temp:
            root = Path(temp).resolve()
            path = root / '.editorconfig'
            path.write_bytes(b'public-build-input')
            pin = prep.packet.digest(path.read_bytes())
            with prep._RootInputPin(path, pin) as held:
                held.check()
                self.assertEqual(held.digest, pin)
            with self.assertRaises(prep.files.archive.ArchiveError):
                prep.files.relative_parts('.editorconfig')

    def test_fixed_editor_input_rejects_hardlink_alias(self):
        import os
        with tempfile.TemporaryDirectory(prefix='fleetory-editor-alias-') as temp:
            root = Path(temp).resolve()
            path = root / '.editorconfig'
            path.write_bytes(b'public-build-input')
            os.link(path, root / 'alias')
            with self.assertRaises(ValueError):
                prep._RootInputPin(path, prep.packet.digest(path.read_bytes()))


if __name__ == '__main__':
    unittest.main()
