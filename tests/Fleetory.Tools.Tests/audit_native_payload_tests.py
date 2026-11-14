"""Empty native namespace contracts and real disposable metadata refusals."""
import ast
import base64
import io
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from audit_native_preparation_tests import vector, REPO
from audit_backend_binding_tests import control_plan
import audit_native_payload as policy


def vector_payload():
    value, native = vector()
    value.update(schema=policy.SCHEMA, controlDirectorySha256='d' * 64, selectedSourcesSha256='e' * 64)
    return value, native


class NativePayloadTests(unittest.TestCase):
    def setUp(self):
        self.value, self.native = vector_payload()
        self.pin = policy.packet.digest(self.native)
        self.raw = policy.prep.canonical(self.value)
        self.info = policy.header(self.raw, self.pin)
        self.declared = policy.reservation(self.raw, self.pin)

    def wrapper(self, mode='reserve', frame=None):
        if frame is None:
            frame = policy.authorize(self.info, 'a' * 64, 'b' * 64) if mode == 'reserve' else policy.closing(
                self.info, 'a' * 64, 'c' * 64, 'b' * 64, 'f' * 64)
        result = dict(schema='fleetory.native-empty-payload-action.v1', headerBase64=base64.b64encode(self.raw).decode('ascii'),
            frameBase64=base64.b64encode(policy.prep.canonical(frame)).decode('ascii'))
        if mode == 'remove':
            result.update(ownerSha256='c' * 64, payloadDirectorySha256='d' * 64, intentSha256='b' * 64)
        return result

    def test_strict_header_binds_control_directory_sources_and_native_scope(self):
        self.assertEqual(self.info['headerSha256'], policy.packet.digest(self.raw))
        self.assertEqual(self.declared['controlDirectorySha256'], self.value['controlDirectorySha256'])
        self.assertEqual(self.declared['bundleSha256'], self.value['selectedSourcesSha256'])
        with self.assertRaises(ValueError):
            policy.prep.header(self.raw, self.pin)

    def test_header_cannot_admit_original_bytes_paths_keys_or_commands(self):
        for key in ('archiveBase64', 'privateKey', 'root', 'endpoint', 'command', 'payload'):
            with self.subTest(key=key), self.assertRaises(ValueError):
                policy.header(policy.prep.canonical({**self.value, key: 'generated-canary'}), self.pin)

    def test_header_pins_types_duplicates_bounds_and_old_schema_are_refused(self):
        for key, value in (('controlDirectorySha256', True), ('selectedSourcesSha256', 'E' * 64), ('schema', policy.prep.SCHEMA)):
            with self.subTest(key=key), self.assertRaises(ValueError):
                policy.header(policy.prep.canonical({**self.value, key: value}), self.pin)
        for data in (self.raw[:-1] + b',"nonce":"duplicate"}', self.raw + b' ' * policy.prep.MAX_HEADER):
            with self.assertRaises(ValueError):
                policy.header(data, self.pin)

    def test_authorization_and_removal_are_distinct_fixed_metadata_decisions(self):
        for mode in ('reserve', 'remove'):
            wrapped = self.wrapper(mode)
            _, info, declared, _ = policy._action(policy.prep.canonical(wrapped), self.pin, 'a' * 64, mode)
            self.assertEqual(info, self.info)
            self.assertEqual(declared, self.declared)
        auth = policy.authorize(self.info, 'a' * 64, 'b' * 64)
        for change in ({'decision': 'restore'}, {'nonce': 'foreign'}, {'archiveBase64': 'generated'}, {'intentSha256': True}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                policy._action(policy.prep.canonical(self.wrapper(frame={**auth, **change})), self.pin, 'a' * 64, 'reserve')

    def test_foreign_header_ready_owner_release_or_intent_cannot_remove(self):
        close = policy.closing(self.info, 'a' * 64, 'c' * 64, 'b' * 64, 'f' * 64)
        for key in ('headerSha256', 'readySha256', 'ownerSha256', 'intentSha256', 'releaseSha256'):
            with self.subTest(key=key), self.assertRaises(ValueError):
                policy._action(policy.prep.canonical(self.wrapper('remove', {**close, key: 'foreign'})), self.pin, 'a' * 64, 'remove')

    def test_removal_cannot_carry_private_fields_or_another_operation(self):
        close = policy.closing(self.info, 'a' * 64, 'c' * 64, 'b' * 64, 'f' * 64)
        for change in ({'archiveBase64': 'generated-private-body'}, {'nonce': 'foreign'}, {'decision': 'reserve-empty-metadata'}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                policy._action(policy.prep.canonical(self.wrapper('remove', {**close, **change})), self.pin, 'a' * 64, 'remove')

    def test_new_profile_cannot_select_old_or_arbitrary_transport(self):
        fake = SimpleNamespace(check=lambda: None)
        for factory in (None, policy.prep._PreparationPumps, lambda *_: None):
            command = policy.process._Command(fake, (), (), Path('.'), {}, 'native-empty-payload', factory)
            with self.assertRaises(ValueError):
                command.check()

    def test_action_duplicates_extra_fields_noncanonical_base64_and_bounds_refused(self):
        wrapped = self.wrapper()
        for data in (policy.prep.canonical({**wrapped, 'root': '/unreviewed'}),
                policy.prep.canonical({**wrapped, 'headerBase64': wrapped['headerBase64'] + '\n'}),
                policy.prep.canonical(wrapped) + b' ' * policy.MAX_ACTION,
                policy.prep.canonical(wrapped)[:-1] + b',"schema":"duplicate"}'):
            with self.assertRaises(ValueError):
                policy._action(data, self.pin, 'a' * 64, 'reserve')

    def test_native_delegation_requires_the_actual_direct_parent_pid(self):
        for pid in (True, 0, os.getpid(), 0x100000000):
            with self.subTest(pid=pid), self.assertRaises(ValueError):
                policy.native_action(b'{}', self.pin, 'a' * 64, pid, 'reserve')

    def owned(self, root):
        return policy.binding.OwnedPayload(root, self.declared, os.getppid())

    def fixture(self, temp):
        root = Path(temp).resolve()
        (root / 'artifacts').mkdir(mode=0o700)
        with self.owned(root) as owned:
            ready = dict(ownerSha256=owned.record_sha, payloadDirectorySha256=owned.directory_sha)
            path = owned.path
        return root, ready, path

    def test_exact_delegated_empty_record_reopens_and_is_removed(self):
        with tempfile.TemporaryDirectory(prefix='fleetory-native-empty-remove-') as temp:
            root, ready, path = self.fixture(temp)
            with policy._RecordedEmpty(root, self.declared, ready, os.getppid()) as recorded:
                self.assertEqual(recorded.pin.digest, ready['ownerSha256'])
                recorded.remove()
            self.assertFalse(path.exists())

    def test_foreign_unmarked_namespace_is_preserved(self):
        with tempfile.TemporaryDirectory(prefix='fleetory-native-empty-foreign-') as temp:
            root = Path(temp).resolve()
            (root / 'artifacts').mkdir()
            path = root / 'artifacts' / policy.binding.payload_name(self.declared['nonce'])
            path.mkdir()
            sentinel = path / 'foreign'
            sentinel.write_bytes(b'generated-foreign-sentinel')
            with self.assertRaises(FileExistsError):
                self.owned(root)
            self.assertEqual(sentinel.read_bytes(), b'generated-foreign-sentinel')

    def test_changed_marker_or_directory_identity_cannot_be_adopted(self):
        with tempfile.TemporaryDirectory(prefix='fleetory-native-empty-mismatch-') as temp:
            root, ready, path = self.fixture(temp)
            original = (path / policy.binding.MARKER).read_bytes()
            for key in ('ownerSha256', 'payloadDirectorySha256'):
                with self.subTest(key=key), self.assertRaises(ValueError):
                    policy._RecordedEmpty(root, self.declared, {**ready, key: '0' * 64}, os.getppid())
            self.assertEqual((path / policy.binding.MARKER).read_bytes(), original)

    def test_nonempty_payload_is_never_deleted_by_empty_reservation_close(self):
        with tempfile.TemporaryDirectory(prefix='fleetory-native-empty-extra-') as temp:
            root, ready, path = self.fixture(temp)
            extra = path / 'extra'
            extra.write_bytes(b'generated-content-must-survive')
            with policy._RecordedEmpty(root, self.declared, ready, os.getppid()) as recorded, self.assertRaises(ValueError):
                recorded.remove()
            self.assertEqual(extra.read_bytes(), b'generated-content-must-survive')
            self.assertTrue((path / policy.binding.MARKER).exists())

    def test_hardlinked_marker_is_rejected_and_both_aliases_preserved(self):
        with tempfile.TemporaryDirectory(prefix='fleetory-native-empty-alias-') as temp:
            root, ready, path = self.fixture(temp)
            marker = path / policy.binding.MARKER
            alias = root / 'alias'
            os.link(marker, alias)
            original = marker.read_bytes()
            with self.assertRaises(policy.prep.files.archive.ArchiveError):
                policy._RecordedEmpty(root, self.declared, ready, os.getppid())
            self.assertEqual(alias.read_bytes(), original)
            self.assertEqual(marker.read_bytes(), original)

    def test_new_inventory_is_closed_and_old_profiles_remain_fixed(self):
        self.assertEqual(len(policy.SOURCES), 34)
        self.assertEqual(len(policy.prep.SOURCES), 32)
        import audit_launch_bundle as bundle
        self.assertEqual(len(bundle.SOURCES), 11)
        names = {Path(p).stem for p in policy.SOURCES if p.endswith('.py')}
        for name in names:
            for node in ast.walk(ast.parse((REPO / 'eng/pilot' / (name + '.py')).read_text())):
                imports = [n.name for n in node.names] if isinstance(node, ast.Import) else (
                    [node.module] if isinstance(node, ast.ImportFrom) and node.module else [])
                for item in imports:
                    if (REPO / 'eng/pilot' / (item + '.py')).is_file():
                        self.assertIn(item, names)

    def pumps(self, session):
        value = policy._NativePayloadPumps.make_header(self.native, session.report(), session,
            {n: 'e' * 64 for n in policy.SOURCES}, 'c' * 64)
        child = SimpleNamespace(pid=12345, stdin=io.BytesIO())
        command = SimpleNamespace(check=lambda: None)
        return policy._NativePayloadPumps(child, policy.prep.canonical(value) + b'\n', command, session,
            SimpleNamespace(identity=lambda *_: {'actualImageMatched': True}), time.monotonic_ns(), 30)

    def session(self, temp):
        value = control_plan(self.value['nonce'])
        value['nativePlanSha256'] = self.pin
        raw = policy.prep.canonical(value)
        return policy.control.claim(Path(temp).resolve(), raw, policy.packet.digest(raw))

    def test_expiry_during_intent_flush_sends_no_reservation_authorization(self):
        with tempfile.TemporaryDirectory(prefix='fleetory-native-intent-expiry-') as temp, self.session(temp) as session:
            pump = self.pumps(session)
            pump.ready_pin = 'a' * 64
            pump.ready.set()
            write = session._write_once
            sent = []

            def expire(name, value):
                write(name, value)
                if name == 'native-payload-intent.json':
                    pump.start_time -= 60_000_000_000

            with patch.object(session, '_write_once', side_effect=expire), patch.object(pump, '_send', side_effect=sent.append):
                pump._write()
            self.assertEqual(sent, [pump.data])
            self.assertIsNone(pump.intent_pin)

    def test_foreign_intent_record_is_preserved_without_authorization(self):
        with tempfile.TemporaryDirectory(prefix='fleetory-native-intent-foreign-') as temp, self.session(temp) as session:
            path = session._directory.path / 'native-payload-intent.json'
            path.write_bytes(b'foreign')
            pump = self.pumps(session)
            pump.ready_pin = 'a' * 64
            pump.ready.set()
            sent = []
            with patch.object(pump, '_send', side_effect=sent.append):
                pump._write()
            self.assertEqual(sent, [pump.data])
            self.assertEqual(path.read_bytes(), b'foreign')

    def test_expiry_during_close_flush_sends_no_removal_frame(self):
        with tempfile.TemporaryDirectory(prefix='fleetory-native-remove-expiry-') as temp, self.session(temp) as session:
            pump = self.pumps(session)
            pump.ready_pin = 'a' * 64
            pump.ready.set()
            pump.payload_ready.set()
            pump.frames = [{}, {'ownerSha256': 'c' * 64}]
            pump.bound = SimpleNamespace(check=lambda: None, release=lambda: 'f' * 64)
            write = session._write_once
            sent = []

            def expire(name, value):
                write(name, value)
                if name == 'native-close.json':
                    pump.start_time -= 60_000_000_000

            with patch.object(session, '_write_once', side_effect=expire), patch.object(pump, '_send', side_effect=sent.append):
                pump._write()
            self.assertEqual(len(sent), 2)
            self.assertEqual(json.loads(sent[1])['decision'], 'reserve-empty-metadata')

    def test_forged_payload_ready_does_not_bind_namespace(self):
        with tempfile.TemporaryDirectory(prefix='fleetory-native-payload-forgery-') as temp, self.session(temp) as session:
            pump = self.pumps(session)
            pump.ready_pin, pump.intent_pin = 'a' * 64, 'b' * 64
            pump.frames = [{}]
            ready = dict(schema='fleetory.native-empty-payload-ready.v1', nonce=pump.info['nonce'],
                headerSha256=pump.info['headerSha256'], readySha256='a' * 64, intentSha256='b' * 64,
                ownerSha256='c' * 64, payloadDirectorySha256='d' * 64, privateInputsAccepted=False, backendCreated=False)
            with patch.object(policy.binding, 'BoundPayload') as bind:
                for key, value in (('backendCreated', True), ('privateInputsAccepted', True), ('intentSha256', 'f' * 64)):
                    with self.subTest(key=key), self.assertRaises(ValueError):
                        pump._accept_frame({**ready, key: value}, b'')
                bind.assert_not_called()
            self.assertFalse(pump.payload_ready.is_set())

    def test_failed_owner_never_reports_cleanup_or_private_release(self):
        with tempfile.TemporaryDirectory(prefix='fleetory-native-payload-failed-') as temp, self.session(temp) as session:
            pump = self.pumps(session)
            with self.assertRaises(ValueError):
                pump.finalize_binding(SimpleNamespace(returncode=1), {'noRunningMembersVerified': True}, True)
            for key in ('emptyPayloadNamespaceBound', 'emptyPayloadRemovedVerified', 'privateInputsAccepted',
                    'backendCreated', 'backendNamespaceBound', 'cleanupAuthorized', 'fullSystemRecoveryVerified'):
                self.assertIs(pump.resource_metadata[key], False)


if __name__ == '__main__':
    unittest.main()
