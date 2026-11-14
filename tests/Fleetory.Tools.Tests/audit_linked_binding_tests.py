"""Strict same-session image/container linkage and unchanged runtime refusals."""
import json
import os
from pathlib import Path
import tempfile
import unittest
import uuid
from unittest.mock import patch

from audit_image_binding_tests import image, sample as image_sample, BASE, BUILT, LAYERS, control
from audit_backend_binding_tests import control_plan, sample as container_sample, CONTAINER_ID
import audit_linked_binding as linked


def sample(intent):
    value = container_sample(intent)
    value['configImage'] = intent['imageId']
    return value


class LinkedBindingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='fleetory-linked-binding-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()

    def session(self):
        data = image.canonical(control_plan(str(uuid.uuid4())))
        return control.claim(self.root, data, image.packet.digest(data))

    def source(self, session, bound=True):
        data = image.prepare(session, BASE, LAYERS)
        result = image.ImageBinding(session, data, image.packet.digest(data))
        if bound:
            result.bind(image.canonical(image_sample(result.intent)), BUILT)
        return result

    def target(self, session, source):
        raw = linked.prepare(session, source)
        return linked.LinkedContainerBinding(session, raw, image.packet.digest(raw), source)

    def record(self, session, name):
        fd = session._records[name][0]
        os.lseek(fd, 0, os.SEEK_SET)
        return json.loads(os.read(fd, control.MAX_RECORD + 1))

    def test_intent_requires_an_already_bound_image_from_same_held_session(self):
        with self.session() as session:
            source = self.source(session, False)
            with self.assertRaises(ValueError):
                linked.prepare(session, source)
            self.assertNotIn('backend-attempt.json', session._records)
        with self.session() as first, self.session() as second:
            source = self.source(first)
            with self.assertRaises(ValueError):
                linked.prepare(second, source)
            self.assertNotIn('backend-attempt.json', second._records)

    def test_container_intent_pins_image_id_both_receipt_hashes_and_shared_expiry(self):
        with self.session() as session:
            source = self.source(session)
            target = self.target(session, source)
            self.assertEqual(target.intent['image'], BUILT)
            self.assertEqual(target.intent['imageId'], BUILT)
            self.assertEqual(target.intent['expiresNs'], source.intent['expiresNs'])
            self.assertEqual(target.intent['imageBindingSha256'], image.packet.digest(session._records['image-binding.json'][1]))
            self.assertEqual(target.intent['imageIntentSha256'], source.report()['intentSha256'])
            self.assertEqual(self.record(session, 'backend-intent.json')['intent'], target.intent)
            self.assertFalse(target.report()['generatedImageContainerPairBound'])

    def test_success_binds_immutable_image_reference_and_original_runtime_limits(self):
        with self.session() as session:
            source = self.source(session)
            target = self.target(session, source)
            result = target.bind(image.canonical(sample(target.intent)), CONTAINER_ID)
            self.assertTrue(result['generatedImageContainerPairBound'])
            saved = self.record(session, 'backend-binding.json')
            self.assertEqual(saved['schema'], 'fleetory.audit-linked-container-binding.v1')
            self.assertEqual(saved['imageId'], BUILT)
            self.assertEqual(saved['imageBindingSha256'], target.intent['imageBindingSha256'])
            self.assertEqual(saved['imageIntentSha256'], target.intent['imageIntentSha256'])
            for field in ('dockerObservationAuthenticated', 'runtimeContinuityVerified', 'legacyNativeOwnerIntegrated',
                    'backendNamespaceBound', 'cleanupAuthorized', 'backendCleanupVerified', 'originalInputsRead',
                    'executionAuthorized', 'fullSystemRecoveryVerified', 'phase7Complete',
                    'nativeOwnerResourceAcknowledged', 'legacyApplicationImageVerified'):
                self.assertIs(result[field], False)

    def test_foreign_source_consumes_backend_attempt_without_adopting_any_record(self):
        with self.session() as first, self.session() as second:
            source = self.source(first)
            raw = linked.prepare(first, source)
            before = first._records['image-binding.json'][1]
            with self.assertRaises(ValueError):
                linked.LinkedContainerBinding(second, raw, image.packet.digest(raw), source)
            self.assertIn('backend-attempt.json', second._records)
            self.assertNotIn('backend-intent.json', second._records)
            self.assertEqual(first._records['image-binding.json'][1], before)
            self.assertTrue(source.report()['generatedImageIdBound'])

    def test_bad_intent_pin_consumes_the_backend_slot(self):
        with self.session() as session:
            source = self.source(session)
            raw = linked.prepare(session, source)
            with self.assertRaises(ValueError):
                linked.LinkedContainerBinding(session, raw, '0' * 64, source)
            with self.assertRaises(ValueError):
                self.target(session, source)

    def test_old_and_linked_intent_schemas_cannot_be_substituted(self):
        for old in (True, False):
            with self.session() as session:
                source = self.source(session)
                raw = linked.container.prepare(session, BUILT) if old else linked.prepare(session, source)
                with self.assertRaises(ValueError):
                    if old:
                        linked.LinkedContainerBinding(session, raw, image.packet.digest(raw), source)
                    else:
                        linked.container.ContainerBinding(session, raw, image.packet.digest(raw))

    def test_unknown_duplicate_oversized_and_invalid_image_link_fields_refused(self):
        changes = [('imageBindingSha256', '0' * 64), ('imageIntentSha256', 'f' * 64), ('imageId', BASE),
            ('image', image.IMAGE), ('image', 'mutable:tag'), ('controlSha256', '0' * 64),
            ('purpose', 'other'), ('schema', linked.container.SCHEMA), ('expiresNs', True)]
        for field, value in changes:
            with self.subTest(field=field, value=value), self.session() as session:
                source = self.source(session)
                changed = json.loads(linked.prepare(session, source))
                changed[field] = value
                raw = image.canonical(changed)
                with self.assertRaises(ValueError):
                    linked.LinkedContainerBinding(session, raw, image.packet.digest(raw), source)
        for kind in ('extra', 'duplicate', 'bound'):
            with self.subTest(kind=kind), self.session() as session:
                source = self.source(session)
                raw = linked.prepare(session, source)
                if kind == 'extra':
                    value = json.loads(raw); value['cleanupAuthorized'] = True; raw = image.canonical(value)
                elif kind == 'duplicate':
                    raw = raw[:-1] + b',"imageId":"duplicate"}'
                else:
                    raw += b' ' * linked.container.MAX_INTENT
                with self.assertRaises(ValueError):
                    linked.LinkedContainerBinding(session, raw, image.packet.digest(raw), source)

    def test_expiration_cannot_extend_or_outlive_bound_image(self):
        with self.session() as session:
            source = self.source(session)
            value = json.loads(linked.prepare(session, source))
            value['expiresNs'] += 1
            raw = image.canonical(value)
            with self.assertRaises(ValueError):
                linked.LinkedContainerBinding(session, raw, image.packet.digest(raw), source)
        with self.session() as session:
            source = self.source(session)
            target = self.target(session, source)
            source._deadline = -1
            with self.assertRaises(ValueError):
                target.report()
            with self.assertRaises(ValueError):
                linked.prepare(session, source)

    def rejected_observation(self, key, value):
        with self.session() as session:
            source = self.source(session)
            target = self.target(session, source)
            observed = sample(target.intent)
            observed[key] = value(observed[key]) if callable(value) else value
            with self.assertRaises(ValueError):
                target.bind(image.canonical(observed), CONTAINER_ID)
            self.assertIn('backend-binding-attempt.json', session._records)
            self.assertNotIn('backend-binding.json', session._records)
            with self.assertRaises(ValueError):
                target.bind(image.canonical(sample(target.intent)), CONTAINER_ID)

    def test_base_image_mutable_tag_or_foreign_container_cannot_replace_pair(self):
        for key, value in (('imageId', BASE), ('configImage', image.IMAGE), ('configImage', 'mutable:tag'),
                ('configImage', BASE), ('id', 'f' * 64)):
            with self.subTest(key=key, value=value):
                self.rejected_observation(key, value)

    def test_all_existing_runtime_isolation_limits_stay_strict(self):
        changes = [('networkMode', 'bridge'), ('networks', {'bridge': {}}), ('readonly', False),
            ('privileged', True), ('capAdd', ['SYS_ADMIN']), ('capDrop', []), ('securityOpt', []),
            ('user', '0:0'), ('entrypoint', ['/bin/sh']), ('command', ['sleep', '120']),
            ('memory', 67108865), ('memory', True), ('nanoCpus', 250000001), ('pidsLimit', 33),
            ('mounts', [{'Type': 'bind'}]), ('binds', ['/host:/data']), ('ports', {'80/tcp': []}),
            ('portBindings', {'80/tcp': []}), ('tmpfs', {'/data': ''}), ('volumesFrom', ['foreign']),
            ('devices', [{}]), ('deviceRequests', [{}]), ('pidMode', 'host'), ('ipcMode', 'host'),
            ('utsMode', 'host'), ('usernsMode', 'host'), ('restart', {'Name': 'always', 'MaximumRetryCount': 0}),
            ('autoRemove', False), ('publishAllPorts', True), ('running', False), ('paused', True),
            ('restarting', True), ('dead', True)]
        for key, value in changes:
            with self.subTest(key=key, value=value):
                self.rejected_observation(key, value)

    def test_foreign_labels_and_late_creation_are_refused(self):
        self.rejected_observation('labels', lambda value: {**value, 'fleetory.audit.control.image.binding': '0' * 64})
        self.rejected_observation('created', '2100-01-01T00:00:00Z')

    def test_source_intent_mutation_invalidates_linked_report(self):
        with self.session() as session:
            source = self.source(session)
            target = self.target(session, source)
            source.intent['definitionSha256'] = '0' * 64
            with self.assertRaises(ValueError):
                target.report()

    def test_container_intent_mutation_invalidates_linked_report(self):
        with self.session() as session:
            source = self.source(session)
            target = self.target(session, source)
            target.intent['imageBindingSha256'] = '0' * 64
            with self.assertRaises(ValueError):
                target.report()

    def test_post_binding_flush_deadline_does_not_return_success(self):
        with self.session() as session:
            source = self.source(session)
            target = self.target(session, source)
            write = session._write_once
            def expire(name, value):
                write(name, value)
                if name == 'backend-binding.json':
                    target._deadline = -1
            with patch.object(session, '_write_once', side_effect=expire), self.assertRaises(ValueError):
                target.bind(image.canonical(sample(target.intent)), CONTAINER_ID)
            self.assertIn('backend-binding.json', session._records)
            self.assertIsNone(target._bound)

    def test_foreign_binding_file_is_preserved_and_never_promoted(self):
        with self.session() as session:
            source = self.source(session)
            target = self.target(session, source)
            path = session._directory.path / 'backend-binding.json'
            path.write_bytes(b'foreign')
            with self.assertRaises((ValueError, OSError)):
                target.bind(image.canonical(sample(target.intent)), CONTAINER_ID)
            self.assertEqual(path.read_bytes(), b'foreign')
            self.assertIsNone(target._bound)


if __name__ == '__main__':
    unittest.main()
