"""Generated untagged image contracts, no Docker or original data."""
import copy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
import uuid
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'eng/pilot'))
import audit_image_binding as image
import audit_control_identity as control
from audit_backend_binding_tests import control_plan

BASE = 'sha256:' + 'a' * 64
BUILT = 'sha256:' + 'b' * 64
LAYERS = ['sha256:' + 'c' * 64, 'sha256:' + 'd' * 64]


def sample(intent):
    seconds, fraction = divmod(intent['openedNs'] + 1, 1_000_000_000)
    created = datetime.fromtimestamp(seconds, timezone.utc).strftime('%Y-%m-%dT%H:%M:%S') + f'.{fraction:09d}Z'
    return dict(schema='fleetory.audit-generated-image-observation.v1', id=BUILT, tags=[], digests=[],
        parent=intent['baseId'], created=created, labels=copy.deepcopy(intent['labels']), rootfs='layers',
        layers=list(intent['baseLayers']), os='linux', architecture='amd64')


class ImageBindingTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='fleetory-image-binding-')
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()

    def session(self):
        raw = image.canonical(control_plan(str(uuid.uuid4())))
        return control.claim(self.root, raw, image.packet.digest(raw))

    def resource(self, session):
        data = image.prepare(session, BASE, LAYERS)
        return image.ImageBinding(session, data, image.packet.digest(data))

    def record(self, session, name):
        fd = session._records[name][0]
        os.lseek(fd, 0, os.SEEK_SET)
        return json.loads(os.read(fd, control.MAX_RECORD + 1))

    def rejected_model(self, field, value):
        with self.session() as session:
            resource = self.resource(session)
            observed = sample(resource.intent)
            observed[field] = value
            with self.assertRaises(ValueError):
                resource.bind(image.canonical(observed), BUILT)
            self.assertTrue((session._directory.path / 'image-binding-attempt.json').exists())
            self.assertFalse((session._directory.path / 'image-binding.json').exists())
            with self.assertRaises(ValueError):
                resource.bind(image.canonical(sample(resource.intent)), BUILT)

    def test_frozen_intent_and_recipe_bound_to_actual_held_reservation(self):
        with self.session() as session:
            data = bytearray(image.prepare(session, BASE, LAYERS))
            resource = image.ImageBinding(session, data, image.packet.digest(data))
            data[:] = b'x' * len(data)
            saved = self.record(session, 'image-intent.json')
            self.assertEqual(saved['intent'], resource.intent)
            self.assertEqual(resource.intent['controlSha256'], session.report()['reservationSha256'])
            recipe = image.definition(resource.intent)
            self.assertEqual(resource.intent['definitionSha256'], image.packet.digest(recipe))
            self.assertEqual(recipe.count(b'\n'), 2)
            self.assertTrue(recipe.startswith(('FROM ' + image.IMAGE + '\nLABEL ').encode()))
            self.assertNotIn(b'COPY ', recipe)
            self.assertNotIn(b'RUN ', recipe)
            self.assertFalse(resource.report()['generatedImageIdBound'])

    def test_actual_receipt_metadata_bound_without_build_or_cleanup_authority(self):
        with self.session() as session:
            resource = self.resource(session)
            raw = bytearray(image.canonical(sample(resource.intent)))
            pin = image.packet.digest(raw)
            report = resource.bind(raw, BUILT)
            raw[:] = b'x' * len(raw)
            saved = self.record(session, 'image-binding.json')
            self.assertEqual(saved['imageId'], BUILT)
            self.assertEqual(saved['baseId'], BASE)
            self.assertEqual(saved['observationSha256'], pin)
            self.assertEqual(saved['definitionSha256'], resource.intent['definitionSha256'])
            self.assertTrue(report['generatedImageIdBound'])
            for name in ('mutableTagClaimed', 'buildProvenanceAuthenticated', 'registryAvailabilityVerified',
                    'dockerObservationAuthenticated', 'runtimeContinuityVerified', 'legacyNativeOwnerIntegrated',
                    'backendNamespaceBound', 'cleanupAuthorized', 'backendCleanupVerified', 'originalInputsRead',
                    'executionAuthorized', 'fullSystemRecoveryVerified', 'phase7Complete'):
                self.assertIs(report[name], False)

    def test_image_and_container_slots_are_distinct_and_each_one_use(self):
        with self.session() as session:
            first = self.resource(session)
            data = image.container.prepare(session, BASE)
            container = image.container.ContainerBinding(session, data, image.packet.digest(data))
            self.assertFalse(container.report()['generatedContainerIdBound'])
            self.assertFalse(first.report()['generatedImageIdBound'])
            self.assertTrue((session._directory.path / 'backend-intent.json').exists())
            self.assertTrue((session._directory.path / 'image-intent.json').exists())
            with self.assertRaises(ValueError):
                self.resource(session)

    def test_bad_pin_consumes_image_attempt_before_validation(self):
        with self.session() as session:
            raw = image.prepare(session, BASE, LAYERS)
            with self.assertRaises(ValueError):
                image.ImageBinding(session, raw, '0' * 64)
            self.assertTrue((session._directory.path / 'image-attempt.json').exists())
            self.assertFalse((session._directory.path / 'image-intent.json').exists())
            with self.assertRaises(ValueError):
                self.resource(session)

    def test_strict_intent_shape_duplicates_scope_and_bounds_refused(self):
        for change in ('schema', 'extra', 'duplicate', 'bound'):
            with self.subTest(change=change), self.session() as session:
                value = json.loads(image.prepare(session, BASE, LAYERS))
                if change == 'schema':
                    value['schema'] = 'unreviewed'
                if change == 'extra':
                    value['tag'] = 'production:latest'
                raw = image.canonical(value)
                if change == 'duplicate':
                    raw = raw[:-1] + b',"nonce":"duplicate"}'
                if change == 'bound':
                    raw += b' ' * image.MAX_INTENT
                with self.assertRaises(ValueError):
                    image.ImageBinding(session, raw, image.packet.digest(raw))

    def test_foreign_control_base_recipe_and_label_substitutions_refused(self):
        changes = dict(nonce=str(uuid.uuid4()), revision='f' * 40, controlSha256='f' * 64,
            purpose='original-image', base='python:latest', baseId='a' * 64, definitionSha256='f' * 64,
            labels={'injected': '" RUN anything'}, baseLayers=[])
        for name, value in changes.items():
            with self.subTest(name=name), self.session() as session:
                intent = json.loads(image.prepare(session, BASE, LAYERS))
                intent[name] = value
                raw = image.canonical(intent)
                with self.assertRaises(ValueError):
                    image.ImageBinding(session, raw, image.packet.digest(raw))

    def test_unbounded_bad_or_boolean_base_layer_inputs_refused(self):
        with self.session() as session:
            for value in ([], LAYERS * 9, ['bad'], [True], 'layers'):
                with self.subTest(value=value), self.assertRaises(ValueError):
                    image.prepare(session, BASE, value)

    def test_future_expired_and_boolean_intent_windows_refused(self):
        for kind in ('future', 'expired', 'bool'):
            with self.subTest(kind=kind), self.session() as session:
                value = json.loads(image.prepare(session, BASE, LAYERS))
                shift = image.WINDOW_NS * (2 if kind == 'future' else -2)
                value['openedNs'] += shift
                value['expiresNs'] += shift
                if kind == 'bool':
                    value['openedNs'] = True
                raw = image.canonical(value)
                with self.assertRaises(ValueError):
                    image.ImageBinding(session, raw, image.packet.digest(raw))

    def test_foreign_or_truncated_build_receipts_refused(self):
        for receipt in ('sha256:' + 'e' * 64, 'b' * 64, 'sha256:' + 'B' * 64, True):
            with self.subTest(receipt=receipt), self.session() as session:
                resource = self.resource(session)
                with self.assertRaises(ValueError):
                    resource.bind(image.canonical(sample(resource.intent)), receipt)

    def test_parent_and_built_identifier_cannot_be_transplanted_or_reuse_base(self):
        for name, value in (('id', BASE), ('parent', 'sha256:' + 'e' * 64), ('id', 'sha256:' + 'e' * 64)):
            with self.subTest(name=name, value=value):
                self.rejected_model(name, value)

    def test_tagged_published_or_foreign_labelled_images_refused(self):
        for name, value in (('tags', ['foreign:latest']), ('tags', None), ('digests', ['registry@sha256:' + 'e' * 64]),
                ('labels', {}), ('labels', {'fleetory.audit.control.nonce': str(uuid.uuid4())})):
            with self.subTest(name=name):
                self.rejected_model(name, value)

    def test_filesystem_and_platform_substitutions_refused(self):
        for name, value in (('layers', LAYERS + ['sha256:' + 'f' * 64]), ('layers', list(reversed(LAYERS))),
                ('rootfs', 'unreviewed'), ('os', 'windows'), ('architecture', 'arm64')):
            with self.subTest(name=name):
                self.rejected_model(name, value)

    def test_creation_time_and_observation_shape_refused(self):
        for value in ('1970-01-01T00:00:00Z', '2999-01-01T00:00:00Z', 'invalid', True):
            with self.subTest(value=value):
                self.rejected_model('created', value)
        for change in ('extra', 'duplicate', 'bound'):
            with self.subTest(change=change), self.session() as session:
                resource = self.resource(session)
                value = sample(resource.intent)
                if change == 'extra':
                    value['cleanupAuthorized'] = True
                raw = image.canonical(value)
                if change == 'duplicate':
                    raw = raw[:-1] + b',"id":"duplicate"}'
                if change == 'bound':
                    raw += b' ' * image.container.MAX_OBSERVATION
                with self.assertRaises(ValueError):
                    resource.bind(raw, BUILT)

    def test_binding_replay_cannot_change_the_recorded_image(self):
        with self.session() as session:
            resource = self.resource(session)
            raw = image.canonical(sample(resource.intent))
            resource.bind(raw, BUILT)
            saved = self.record(session, 'image-binding.json')
            with self.assertRaises(ValueError):
                resource.bind(raw, BUILT)
            self.assertEqual(self.record(session, 'image-binding.json'), saved)

    def test_foreign_intent_file_is_not_adopted(self):
        with self.session() as session:
            path = session._directory.path / 'image-intent.json'
            path.write_bytes(b'foreign')
            with self.assertRaises(OSError):
                self.resource(session)
            self.assertEqual(path.read_bytes(), b'foreign')

    def test_changed_held_image_record_fails_closed(self):
        with self.session() as session:
            resource = self.resource(session)
            fd = session._records['image-intent.json'][0]
            os.lseek(fd, 0, os.SEEK_SET)
            os.write(fd, b'x')
            with self.assertRaises(ValueError):
                resource.bind(image.canonical(sample(resource.intent)), BUILT)

    def test_image_attempt_flush_failure_cannot_be_retried(self):
        with self.session() as session:
            with patch.object(control.os, 'fsync', side_effect=OSError('generated flush failure')):
                with self.assertRaises(OSError):
                    self.resource(session)
            with self.assertRaises(ValueError):
                self.resource(session)

    def test_post_image_publication_deadline_failure_is_unknown_not_accepted(self):
        with self.session() as session:
            resource = self.resource(session)
            write = session._write_once

            def expire(name, value):
                write(name, value)
                if name == 'image-binding.json':
                    resource._deadline = time.monotonic() - 1

            with patch.object(session, '_write_once', side_effect=expire):
                with self.assertRaises(ValueError):
                    resource.bind(image.canonical(sample(resource.intent)), BUILT)
            self.assertIsNone(resource._bound)
            self.assertTrue((session._directory.path / 'image-binding.json').exists())

    def test_closed_control_and_backward_clock_refuse_image_binding(self):
        with self.session() as session:
            resource = self.resource(session)
            with patch.object(image.container.time, 'time_ns', return_value=resource.intent['openedNs'] - 1):
                with self.assertRaises(ValueError):
                    resource.report()
        with self.assertRaises(ValueError):
            resource.report()


if __name__ == '__main__':
    unittest.main()
