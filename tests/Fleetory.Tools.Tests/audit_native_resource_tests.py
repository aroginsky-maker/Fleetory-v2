"""Native receipt parsing, same-session admission, one-use publication and deadline refusals."""
import ast
import base64
import io
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
import uuid
from types import SimpleNamespace
from unittest.mock import patch

from audit_native_payload_tests import vector_payload, REPO
from audit_linked_binding_tests import image, linked, image_sample, sample, BASE, BUILT, LAYERS, CONTAINER_ID, control_plan
import audit_native_resources as policy


def generated_pair(session, bound=True):
    raw = image.prepare(session, BASE, LAYERS)
    source = image.ImageBinding(session, raw, image.packet.digest(raw))
    source.bind(image.canonical(image_sample(source.intent)), BUILT)
    raw = linked.prepare(session, source)
    target = linked.LinkedContainerBinding(session, raw, image.packet.digest(raw), source)
    if bound:
        target.bind(image.canonical(sample(target.intent)), CONTAINER_ID)
    return source, target


class NativeResourceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='fleetory-native-receipt-contracts-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.header, self.native = vector_payload()
        self.native_pin = policy.packet.digest(self.native)
        self.raw = policy.prep.canonical(self.header)
        self.info = policy.payload.header(self.raw, self.native_pin)
        self.ready = dict(ownerSha256='a' * 64, payloadDirectorySha256='b' * 64, intentSha256='c' * 64)

    def session(self):
        value = control_plan(self.info['nonce'])
        value['nativePlanSha256'] = self.native_pin
        raw = policy.prep.canonical(value)
        directory = self.root / uuid.uuid4().hex
        directory.mkdir(mode=0o700)
        return policy.payload.control.claim(directory, raw, policy.packet.digest(raw))

    def pump(self, session, pair):
        child = SimpleNamespace(pid=12345, stdin=io.BytesIO())
        command = SimpleNamespace(linked_pair=pair, check=lambda: None, executable=None)
        data = policy._NativeResourcePumps.make_header(self.native, session.report(), session,
            {n: 'e' * 64 for n in policy.SOURCES}, 'c' * 64)
        result = policy._NativeResourcePumps(child, policy.prep.canonical(data) + b'\n', command, session,
            SimpleNamespace(identity=lambda *_: dict(pid=12345, actualImageMatched=True)), time.monotonic_ns(), 30)
        result.bound = SimpleNamespace(check=lambda: None, close=lambda: None)
        result.frames = [{}, self.ready]
        result.ready_pin = 'd' * 64
        return result

    def test_same_session_pair_receipt_pins_both_records_intents_ids_and_expiry(self):
        with self.session() as session:
            pair = generated_pair(session)
            result = policy.pair_receipt(session, pair)
            self.assertEqual(result['imageId'], BUILT)
            self.assertEqual(result['containerId'], CONTAINER_ID)
            self.assertEqual(result['containerBindingSha256'], policy.packet.digest(session._records['backend-binding.json'][1]))
            self.assertEqual(result['imageBindingSha256'], policy.packet.digest(session._records['image-binding.json'][1]))
            self.assertEqual(result['expiresNs'], pair[0].intent['expiresNs'])

    def test_foreign_unbound_reversed_or_fake_pair_is_not_adopted(self):
        with self.session() as session, self.session() as foreign:
            pair = generated_pair(session, False)
            for value in (pair, tuple(reversed(pair)), (object(), object()), list(pair)):
                with self.subTest(value=type(value)), self.assertRaises(ValueError):
                    policy.pair_receipt(session, value)
            pair[1].bind(image.canonical(sample(pair[1].intent)), CONTAINER_ID)
            with self.assertRaises(ValueError):
                policy.pair_receipt(foreign, pair)
            self.assertNotIn('native-resource-intent.json', foreign._records)

    def test_receipt_strict_types_fields_ids_expiry_duplicates_and_boundaries(self):
        with self.session() as session:
            value = policy.pair_receipt(session, generated_pair(session))
            mutations = [('schema', 'old'), ('nonce', 'foreign'), ('controlSha256', 'f' * 64), ('imageId', image.IMAGE),
                ('containerId', True), ('containerId', 'F' * 64), ('imageBindingSha256', True),
                ('imageIntentSha256', 'F' * 64), ('containerBindingSha256', None), ('containerIntentSha256', ''),
                ('expiresNs', True), ('expiresNs', time.time_ns() - 1), ('expiresNs', time.time_ns() + 120_000_000_000)]
            for key, item in mutations:
                with self.subTest(key=key, item=item), self.assertRaises(ValueError):
                    policy.receipt({**value, key: item}, value['nonce'], value['controlSha256'])
            with self.assertRaises(ValueError):
                policy.receipt({**value, 'command': 'restore'}, value['nonce'], value['controlSha256'])

    def test_offer_binds_live_header_ready_namespace_and_resource_intent(self):
        with self.session() as session:
            value = policy.pair_receipt(session, generated_pair(session))
            info = {**self.info, 'controlSha256': value['controlSha256']}
            offered = policy.offer(info, 'd' * 64, self.ready, value, 'e' * 64)
            self.assertEqual(offered['ownerSha256'], self.ready['ownerSha256'])
            self.assertEqual(offered['payloadIntentSha256'], self.ready['intentSha256'])
            self.assertLess(len(policy.prep.canonical(offered)), policy.prep.MAX_FRAME)
            ack = policy.acknowledgement(info, 'd' * 64, self.ready, value, 'e' * 64, 12345)
            self.assertEqual(ack['receiptSha256'], policy.packet.digest(policy.prep.canonical(value)))
            self.assertFalse(ack['privateInputsAccepted'])
            self.assertFalse(ack['backendControlAuthorized'])

    def test_direct_native_parent_required_before_action_or_marker_access(self):
        for pid in (True, 0, os.getpid(), 0x100000000):
            with self.subTest(pid=pid), patch.object(policy.payload, '_RecordedEmpty') as reopen, self.assertRaises(ValueError):
                policy.native_acknowledge(b'{}', self.native_pin, 'd' * 64, pid)
            reopen.assert_not_called()

    def test_wire_extra_duplicate_oversize_or_noncanonical_base64_is_refused(self):
        for raw in (b'{}', b'{"schema":1,"schema":2}', b' ' * (policy.payload.MAX_ACTION + 1)):
            with self.assertRaises(ValueError):
                policy.native_acknowledge(raw, self.native_pin, 'd' * 64, os.getppid())

    def test_offer_wire_binding_and_private_fields_are_refused_before_marker_access(self):
        with self.session() as session:
            value = policy.pair_receipt(session, generated_pair(session))
            header = {**self.header, 'controlSha256': value['controlSha256']}
            raw = policy.prep.canonical(header)
            info = policy.payload.header(raw, self.native_pin)
            frame = policy.offer(info, 'd' * 64, self.ready, value, 'e' * 64)
            wrapped = dict(schema='fleetory.native-linked-resource-action.v1', headerBase64=base64.b64encode(raw).decode('ascii'),
                frameBase64=base64.b64encode(policy.prep.canonical(frame)).decode('ascii'), **self.ready)
            for key, item in (('headerSha256', 'f' * 64), ('readySha256', 'f' * 64), ('ownerSha256', 'f' * 64),
                    ('payloadDirectorySha256', 'f' * 64), ('payloadIntentSha256', 'f' * 64), ('decision', 'restore'),
                    ('archiveBase64', 'generated-secret-refused')):
                changed = {**wrapped, 'frameBase64': base64.b64encode(policy.prep.canonical({**frame, key: item})).decode('ascii')}
                with self.subTest(key=key), patch.object(policy.payload, '_RecordedEmpty') as reopen, self.assertRaises(ValueError):
                    policy.native_acknowledge(policy.prep.canonical(changed), self.native_pin, 'd' * 64, os.getppid())
                reopen.assert_not_called()
            for changed in ({**wrapped, 'headerBase64': wrapped['headerBase64'] + '\n'}, {**wrapped, 'root': '/foreign'}):
                with patch.object(policy.payload, '_RecordedEmpty') as reopen, self.assertRaises(ValueError):
                    policy.native_acknowledge(policy.prep.canonical(changed), self.native_pin, 'd' * 64, os.getppid())
                reopen.assert_not_called()

    def test_new_fixed_transport_rejects_old_factory_and_all_old_profiles_reject_pair(self):
        fake = SimpleNamespace(check=lambda: None)
        for factory in (None, policy.payload._NativePayloadPumps, lambda *_: None):
            command = policy.process._Command(fake, (), (), Path('.'), {}, 'native-resource-ack', factory, (None, None))
            with self.assertRaises(ValueError):
                command.check()
        command = policy.process._Command(fake, (), (), Path('.'), {}, 'generated-worker', None, (None, None))
        with self.assertRaises(ValueError):
            command.check()

    def test_closed_inventory_includes_all_local_imports_and_keeps_older_profiles_fixed(self):
        self.assertEqual(len(policy.SOURCES), 40)
        self.assertEqual(len(policy.payload.SOURCES), 34)
        self.assertEqual(len(policy.prep.SOURCES), 32)
        names = {Path(p).stem for p in policy.SOURCES if p.endswith('.py')}
        for name in names:
            for node in ast.walk(ast.parse((REPO / 'eng/pilot' / (name + '.py')).read_text())):
                imports = [n.name for n in node.names] if isinstance(node, ast.Import) else (
                    [node.module] if isinstance(node, ast.ImportFrom) and node.module else [])
                for item in imports:
                    if (REPO / 'eng/pilot' / (item + '.py')).is_file():
                        self.assertIn(item, names)

    def test_expiry_during_intent_flush_sends_no_resource_offer(self):
        with self.session() as session:
            pump = self.pump(session, generated_pair(session))
            session._write_once('payload-binding.json', {'generated': True})
            original = session._write_once
            sent = []
            def expire(name, value):
                original(name, value)
                if name == 'native-resource-intent.json':
                    pump.start_time -= 60_000_000_000
            with patch.object(session, '_write_once', side_effect=expire), patch.object(pump, '_send', side_effect=sent.append), self.assertRaises(policy.process.LaunchError):
                pump._after_payload_bound()
            self.assertEqual(sent, [])
            self.assertIsNone(pump.resource_intent_pin)

    def test_foreign_resource_intent_is_preserved_without_offer(self):
        with self.session() as session:
            pump = self.pump(session, generated_pair(session))
            session._write_once('payload-binding.json', {'generated': True})
            path = session._directory.path / 'native-resource-intent.json'
            path.write_bytes(b'foreign resource intent')
            with patch.object(pump, '_send') as send, self.assertRaises(OSError):
                pump._after_payload_bound()
            send.assert_not_called()
            self.assertEqual(path.read_bytes(), b'foreign resource intent')

    def test_forged_ack_fields_do_not_publish_binding_or_unblock_writer(self):
        with self.session() as session:
            pump = self.pump(session, generated_pair(session))
            pump.resource_intent_pin = 'e' * 64
            valid = policy.acknowledgement(pump.info, pump.ready_pin, self.ready, pump.receipt, 'e' * 64, pump.process.pid)
            for key, item in [('schema', 'old'), ('nonce', 'foreign'), ('pid', True), ('pid', 12346),
                    ('receiptSha256', 'f' * 64), ('intentSha256', 'f' * 64), ('imageId', image.IMAGE),
                    ('containerId', 'f' * 64), ('privateInputsAccepted', True), ('backendControlAuthorized', True), ('backendControlAuthorized', 0), ('privateInputsAccepted', 0),
                    ('ownerSha256', 'f' * 64), ('payloadDirectorySha256', 'f' * 64), ('readySha256', 'f' * 64),
                    ('headerSha256', 'f' * 64), ('command', 'restore')]:
                with self.subTest(key=key), self.assertRaises(ValueError):
                    pump._accept_frame({**valid, key: item}, b'generated forged ack')
            self.assertNotIn('native-resource-ack.json', session._records)
            self.assertFalse(pump.resource_ack.is_set())

    def test_acceptance_rechecks_actual_peer_and_persists_exclusive_ack_record(self):
        with self.session() as session:
            pump = self.pump(session, generated_pair(session))
            pump.resource_intent_pin = 'e' * 64
            valid = policy.acknowledgement(pump.info, pump.ready_pin, self.ready, pump.receipt, 'e' * 64, pump.process.pid)
            with patch.object(pump.fence, 'identity', wraps=pump.fence.identity) as observed:
                pump._accept_frame(valid, policy.prep.canonical(valid))
            observed.assert_called_once()
            self.assertTrue(pump.resource_ack.is_set())
            self.assertEqual(pump.ack_pin, policy.packet.digest(session._records['native-resource-ack.json'][1]))
            with self.assertRaises(ValueError):
                session._write_once('native-resource-ack.json', valid)

    def test_duplicate_ack_cannot_replace_the_final_close(self):
        with self.session() as session:
            pump = self.pump(session, generated_pair(session))
            pump.resource_intent_pin = 'e' * 64
            valid = policy.acknowledgement(pump.info, pump.ready_pin, self.ready, pump.receipt, 'e' * 64, pump.process.pid)
            pump._accept_frame(valid, policy.prep.canonical(valid))
            pump._accept_frame(valid, policy.prep.canonical(valid))
            with self.assertRaises(ValueError):
                pump.finalize_binding(SimpleNamespace(returncode=0), {'noRunningMembersVerified': True}, False)
            self.assertIs(pump.resource_metadata['nativeOwnerResourceAcknowledged'], False)

    def test_failed_peer_identity_or_ack_flush_expiry_never_unblocks_writer(self):
        for failure in ('identity', 'flush-expiry'):
            with self.subTest(failure=failure), self.session() as session:
                pump = self.pump(session, generated_pair(session))
                pump.resource_intent_pin = 'e' * 64
                valid = policy.acknowledgement(pump.info, pump.ready_pin, self.ready, pump.receipt, 'e' * 64, pump.process.pid)
                original = session._write_once
                def write(name, value):
                    original(name, value)
                    if name == 'native-resource-ack.json':
                        pump.start_time -= 60_000_000_000
                identity = patch.object(pump.fence, 'identity', side_effect=ValueError('Generated peer mismatch'))
                flush = patch.object(session, '_write_once', side_effect=write)
                with (identity if failure == 'identity' else flush), self.assertRaises((ValueError, policy.process.LaunchError)):
                    pump._accept_frame(valid, policy.prep.canonical(valid))
                self.assertFalse(pump.resource_ack.is_set())
                self.assertIsNone(pump.ack_pin)

    def test_unoffered_ack_and_source_expiry_are_refused(self):
        with self.session() as session:
            pair = generated_pair(session)
            pump = self.pump(session, pair)
            valid = policy.acknowledgement(pump.info, pump.ready_pin, self.ready, pump.receipt, 'e' * 64, pump.process.pid)
            with self.assertRaises(ValueError):
                pump._accept_frame(valid, policy.prep.canonical(valid))
            pair[0]._deadline = time.monotonic() - 1
            with self.assertRaises(ValueError):
                policy.pair_receipt(session, pair)

    def test_failed_completion_keeps_resource_and_private_authority_false(self):
        with self.session() as session:
            pump = self.pump(session, generated_pair(session))
            with self.assertRaises(ValueError):
                pump.finalize_binding(SimpleNamespace(returncode=1), {'noRunningMembersVerified': True}, True)
            for field in ('nativeOwnerResourceAcknowledged', 'backendControlAuthorized', 'backendCleanupAuthorized',
                    'originalInputsRead', 'originalPrivatePkiUsed', 'fullSystemRecoveryVerified', 'phase7Complete'):
                self.assertIs(pump.resource_metadata[field], False)


if __name__ == '__main__':
    unittest.main()
