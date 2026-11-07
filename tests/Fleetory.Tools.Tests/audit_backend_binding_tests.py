"""Held immutable intent/observation contracts. Generated metadata only; no Docker here."""
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
import audit_backend_binding as binding
import audit_control_identity as control

IMAGE_ID = 'sha256:' + 'a' * 64
CONTAINER_ID = 'b' * 64


def control_plan(nonce):
    return dict(schema=control.SCHEMA, purpose=control.PURPOSE, nonce=nonce, revision='1' * 40,
        nativePlanSha256='2' * 64, codeSha256='3' * 64, probeSha256='4' * 64,
        runtimes=dict(python='5' * 64, powershell='6' * 64))


def sample(intent, container_id=CONTAINER_ID):
    seconds, fraction = divmod(intent['openedNs'] + 1, 1_000_000_000)
    created = datetime.fromtimestamp(seconds, timezone.utc).strftime('%Y-%m-%dT%H:%M:%S') + f'.{fraction:09d}Z'
    return dict(schema='fleetory.audit-generated-container-observation.v1', id=container_id,
        name='/' + intent['name'], imageId=intent['imageId'], created=created, labels=copy.deepcopy(intent['labels']),
        configImage=binding.IMAGE, user='65534:65534', entrypoint=['python'], command=list(binding.COMMAND),
        running=True, paused=False, restarting=False, dead=False, networkMode='none', networks={'none': {}},
        readonly=True, privileged=False, capDrop=['ALL'], capAdd=None, securityOpt=['no-new-privileges:true'],
        memory=67108864, nanoCpus=250000000, pidsLimit=32, mounts=[], ports={}, portBindings={}, binds=None,
        tmpfs=None, volumesFrom=None, devices=None, deviceRequests=None, pidMode='', ipcMode='private',
        utsMode='', usernsMode='', restart={'Name': 'no', 'MaximumRetryCount': 0}, autoRemove=True, publishAllPorts=False)


class BackendBindingTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='fleetory-backend-binding-')
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()

    def session(self):
        value = control_plan(str(uuid.uuid4()))
        data = binding.canonical(value)
        return control.claim(self.root, data, binding.packet.digest(data))

    def resource(self, session):
        data = binding.prepare(session, IMAGE_ID)
        return binding.ContainerBinding(session, data, binding.packet.digest(data))

    def encoded(self, value):
        return binding.canonical(value)

    def raw_record(self, session, name):
        fd = session._records[name][0]
        os.lseek(fd, 0, os.SEEK_SET)
        return os.read(fd, control.MAX_RECORD + 1)

    def record(self, session, name):
        return json.loads(self.raw_record(session, name))

    def rejected_model(self, field, value):
        with self.session() as session:
            resource = self.resource(session)
            observed = sample(resource.intent)
            observed[field] = value
            with self.assertRaises((ValueError, OSError)):
                resource.bind(self.encoded(observed), CONTAINER_ID)
            self.assertTrue((session._directory.path / 'backend-binding-attempt.json').is_file())
            self.assertFalse((session._directory.path / 'backend-binding.json').exists())
            with self.assertRaises(ValueError):
                resource.bind(self.encoded(sample(resource.intent)), CONTAINER_ID)

    def test_intent_is_frozen_and_bound_to_held_controller_without_authority(self):
        with self.session() as session:
            raw = bytearray(binding.prepare(session, IMAGE_ID))
            resource = binding.ContainerBinding(session, raw, binding.packet.digest(raw))
            raw[:] = b'x' * len(raw)
            saved = self.record(session, 'backend-intent.json')
            self.assertEqual(saved['intent'], resource.intent)
            self.assertEqual(saved['intent']['controlSha256'], session.report()['reservationSha256'])
            self.assertEqual(saved['intent']['revision'], session._plan['revision'])
            self.assertTrue(resource.report()['intentRecorded'])
            self.assertFalse(resource.report()['generatedContainerIdBound'])
            self.assertFalse(session.report()['backendNamespaceBound'])
            self.assertFalse(session.report()['launchAttemptConsumed'])

    def test_successful_observation_is_immutable_and_matches_create_receipt(self):
        with self.session() as session:
            resource = self.resource(session)
            raw = bytearray(self.encoded(sample(resource.intent)))
            pin = binding.packet.digest(raw)
            report = resource.bind(raw, CONTAINER_ID)
            raw[:] = b'x' * len(raw)
            saved = self.record(session, 'backend-binding.json')
            self.assertEqual(saved['containerId'], CONTAINER_ID)
            self.assertEqual(saved['observationSha256'], pin)
            self.assertEqual(saved['intentSha256'], report['intentSha256'])
            self.assertTrue(report['generatedContainerIdBound'])
            for name in ('dockerObservationAuthenticated', 'runtimeContinuityVerified', 'legacyNativeOwnerIntegrated',
                'backendNamespaceBound', 'cleanupAuthorized', 'backendCleanupVerified', 'originalInputsRead',
                'executionAuthorized', 'fullSystemRecoveryVerified', 'phase7Complete'):
                self.assertIs(report[name], False)

    def test_bad_intent_pin_consumes_attempt_before_admission(self):
        with self.session() as session:
            raw = binding.prepare(session, IMAGE_ID)
            with self.assertRaises(ValueError):
                binding.ContainerBinding(session, raw, '0' * 64)
            self.assertTrue((session._directory.path / 'backend-attempt.json').exists())
            self.assertFalse((session._directory.path / 'backend-intent.json').exists())
            with self.assertRaises(ValueError):
                self.resource(session)

    def test_schema_unknown_duplicate_and_oversized_intent_refused(self):
        for change in ('schema', 'extra', 'duplicate', 'bound'):
            with self.subTest(change=change), self.session() as session:
                value = json.loads(binding.prepare(session, IMAGE_ID))
                if change == 'schema':
                    value['schema'] = 'stale'
                if change == 'extra':
                    value['executionAuthorized'] = True
                raw = self.encoded(value)
                if change == 'duplicate':
                    raw = raw[:-1] + b',"nonce":"duplicate"}'
                if change == 'bound':
                    raw += b' ' * binding.MAX_INTENT
                with self.assertRaises(ValueError):
                    binding.ContainerBinding(session, raw, binding.packet.digest(raw))

    def test_foreign_control_nonce_revision_and_reservation_refused(self):
        for field, value in (('nonce', str(uuid.uuid4())), ('revision', 'f' * 40), ('controlSha256', 'f' * 64),
                ('purpose', 'native-original'), ('name', 'foreign'), ('labels', {}), ('image', 'python:latest'), ('imageId', 'a' * 64)):
            with self.subTest(field=field), self.session() as session:
                intent = json.loads(binding.prepare(session, IMAGE_ID))
                intent[field] = value
                raw = self.encoded(intent)
                with self.assertRaises(ValueError):
                    binding.ContainerBinding(session, raw, binding.packet.digest(raw))

    def test_expired_future_extended_and_boolean_windows_refused(self):
        for kind in ('expired', 'future', 'extended', 'bool'):
            with self.subTest(kind=kind), self.session() as session:
                intent = json.loads(binding.prepare(session, IMAGE_ID))
                if kind == 'expired':
                    intent['openedNs'] -= binding.WINDOW_NS * 2
                    intent['expiresNs'] -= binding.WINDOW_NS * 2
                elif kind == 'future':
                    intent['openedNs'] += binding.WINDOW_NS * 2
                    intent['expiresNs'] += binding.WINDOW_NS * 2
                elif kind == 'extended':
                    intent['expiresNs'] += 1
                else:
                    intent['openedNs'] = True
                raw = self.encoded(intent)
                with self.assertRaises(ValueError):
                    binding.ContainerBinding(session, raw, binding.packet.digest(raw))

    def test_one_resource_intent_per_control_even_through_another_wrapper(self):
        with self.session() as session:
            self.resource(session)
            with self.assertRaises(ValueError):
                self.resource(session)

    def test_preexisting_foreign_intent_is_not_adopted(self):
        with self.session() as session:
            path = session._directory.path / 'backend-intent.json'
            path.write_bytes(b'foreign')
            with self.assertRaises(OSError):
                self.resource(session)
            self.assertEqual(path.read_bytes(), b'foreign')

    def test_one_observation_attempt_even_after_success(self):
        with self.session() as session:
            resource = self.resource(session)
            raw = self.encoded(sample(resource.intent))
            resource.bind(raw, CONTAINER_ID)
            before = self.raw_record(session, 'backend-binding.json')
            with self.assertRaises(ValueError):
                resource.bind(raw, CONTAINER_ID)
            self.assertEqual(self.raw_record(session, 'backend-binding.json'), before)

    def test_wrong_create_receipt_and_identifier_refused(self):
        for receipt in ('c' * 64, 'B' * 64, 'b' * 12, True):
            with self.subTest(receipt=receipt), self.session() as session:
                resource = self.resource(session)
                with self.assertRaises(ValueError):
                    resource.bind(self.encoded(sample(resource.intent)), receipt)

    def test_identity_image_and_label_substitutions_refused(self):
        for field, value in (('id', 'c' * 64), ('name', '/foreign'), ('imageId', 'sha256:' + 'c' * 64),
                ('labels', {}), ('configImage', 'python:latest'), ('schema', 'promoted')):
            with self.subTest(field=field):
                self.rejected_model(field, value)

    def test_privileges_mounts_ports_devices_and_namespace_substitutions_refused(self):
        changes = dict(privileged=True, capAdd=['SYS_ADMIN'], capDrop=[], securityOpt=[], readonly=False,
            mounts=[{'Source': '/'}], binds=['/:/host'], tmpfs={'/tmp': ''}, volumesFrom=['foreign'],
            devices=[{}], deviceRequests=[{}], ports={'1/tcp': []}, portBindings={'1/tcp': []},
            publishAllPorts=True, networkMode='host', networks={'none': {}, 'bridge': {}},
            pidMode='host', ipcMode='host', utsMode='host', usernsMode='host', autoRemove=False)
        for field, value in changes.items():
            with self.subTest(field=field):
                self.rejected_model(field, value)

    def test_runtime_command_user_limits_state_and_restart_substitutions_refused(self):
        changes = dict(user='0:0', entrypoint=['sh'], command=['sleep', '999'], memory=0, nanoCpus=1,
            pidsLimit=True, running=False, paused=True, restarting=True, dead=True,
            restart={'Name': 'always', 'MaximumRetryCount': 0})
        for field, value in changes.items():
            with self.subTest(field=field):
                self.rejected_model(field, value)
        self.rejected_model('restart', {'Name': 'no', 'MaximumRetryCount': False})

    def test_old_future_and_noncanonical_creation_timestamps_refused(self):
        for value in ('1970-01-01T00:00:00Z', '2999-01-01T00:00:00Z', '2026-01-01T00:00:00+00:00',
                '2026-01-01T00:00:00.1234567890Z', '2026-99-99T00:00:00Z', 123):
            with self.subTest(value=value):
                self.rejected_model('created', value)

    def test_duplicate_unknown_oversized_and_mutable_bad_observation_consumes_attempt(self):
        for change in ('duplicate', 'extra', 'bound', 'mutable'):
            with self.subTest(change=change), self.session() as session:
                resource = self.resource(session)
                value = sample(resource.intent)
                if change == 'extra':
                    value['cleanupAuthorized'] = True
                raw = self.encoded(value)
                if change == 'duplicate':
                    raw = raw[:-1] + b',"id":"duplicate"}'
                elif change == 'bound':
                    raw += b' ' * binding.MAX_OBSERVATION
                elif change == 'mutable':
                    raw = bytearray(b'invalid')
                with self.assertRaises(ValueError):
                    resource.bind(raw, CONTAINER_ID)
                self.assertTrue(resource.report()['observationAttemptConsumed'])
                with self.assertRaises(ValueError):
                    resource.bind(self.encoded(sample(resource.intent)), CONTAINER_ID)

    def test_replaced_control_directory_refuses_binding_and_preserves_foreign(self):
        with self.session() as session:
            resource = self.resource(session)
            original = session._directory.path
            moved = original.with_name(original.name + '-old')
            try:
                original.rename(moved)
            except PermissionError:
                self.assertEqual(os.name, 'nt')
                session.check()
                result = resource.bind(self.encoded(sample(resource.intent)), CONTAINER_ID)
                self.assertTrue(result['generatedContainerIdBound'])
                self.assertFalse(moved.exists())
                return
            original.mkdir()
            foreign = original / 'foreign'
            foreign.write_bytes(b'foreign')
            with self.assertRaises((ValueError, OSError)):
                resource.bind(self.encoded(sample(resource.intent)), CONTAINER_ID)
            self.assertEqual(foreign.read_bytes(), b'foreign')

    def test_changed_held_intent_record_refuses_binding(self):
        with self.session() as session:
            resource = self.resource(session)
            fd = session._records['backend-intent.json'][0]
            os.lseek(fd, 0, os.SEEK_SET)
            os.write(fd, b'x')
            with self.assertRaises(ValueError):
                resource.bind(self.encoded(sample(resource.intent)), CONTAINER_ID)

    def test_intent_flush_failure_stays_consumed(self):
        with self.session() as session:
            with patch.object(control.os, 'fsync', side_effect=OSError('fixture flush failure')):
                with self.assertRaises(OSError):
                    self.resource(session)
            self.assertTrue((session._directory.path / 'backend-attempt.json').exists())
            with self.assertRaises(ValueError):
                self.resource(session)

    def test_post_binding_flush_expiry_returns_no_accepted_binding(self):
        with self.session() as session:
            resource = self.resource(session)
            write = session._write_once

            def expire(name, value):
                write(name, value)
                if name == 'backend-binding.json':
                    resource._deadline = time.monotonic() - 1

            with patch.object(session, '_write_once', side_effect=expire):
                with self.assertRaises(ValueError):
                    resource.bind(self.encoded(sample(resource.intent)), CONTAINER_ID)
            self.assertIsNone(resource._bound)
            self.assertTrue((session._directory.path / 'backend-binding.json').exists())

    def test_mutated_intent_and_closed_session_refuse_further_use(self):
        with self.session() as session:
            resource = self.resource(session)
            resource.intent['imageId'] = 'sha256:' + 'f' * 64
            with self.assertRaises(ValueError):
                resource.report()
        with self.assertRaises(ValueError):
            binding.prepare(session, IMAGE_ID)

    def test_utc_nanosecond_timestamp_preserves_precision(self):
        self.assertEqual(binding.timestamp_ns('1970-01-01T00:00:00.000000001Z'), 1)
        self.assertEqual(binding.timestamp_ns('1970-01-01T00:00:00Z'), 0)

    def test_backward_wall_clock_refuses_even_before_monotonic_expiry(self):
        with self.session() as session:
            resource = self.resource(session)
            with patch.object(binding.time, 'time_ns', return_value=resource.intent['openedNs'] - 1):
                with self.assertRaises(ValueError):
                    resource.report()


if __name__ == '__main__':
    unittest.main()
