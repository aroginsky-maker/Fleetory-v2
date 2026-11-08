"""Typed probe source, exact runtime tuple, consumed refusals and lease boundaries."""
import copy
import json
from pathlib import Path
import tempfile
import time
import unittest
import uuid
from unittest.mock import patch

import audit_probe_image_tests as fixtures
from audit_backend_binding_tests import sample as base_sample
import audit_probe_runtime as policy
import audit_native_resources as native

probe, packet, container = policy.probe, policy.packet, policy.container


def observed(intent):
    value = base_sample(intent)
    value.update(schema=policy.OBSERVATION_SCHEMA, configImage=intent['imageId'], user='3322:3322',
        entrypoint=['/bin/sh'], command=['-c', 'exec /bin/sleep 660'], memory=402653184, nanoCpus=1000000000,
        pidsLimit=128, tmpfs=copy.deepcopy(policy.TMPFS), environment=list(policy.ENVIRONMENT),
        ulimits=[dict(Name='core', Soft=0, Hard=0)])
    return value


class ProbeRuntimeTests(unittest.TestCase):
    rejected = 0

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='fleetory-probe-runtime-contracts-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.public = self.root / 'publish';fixtures.public_files(self.public)
        self.manifest = probe.image.canonical(fixtures.measure(self.public))

    def held(self):
        return probe.bundle.HeldProbeBundle(self.public, self.manifest, packet.digest(self.manifest))

    def session(self):
        value = fixtures.control_plan(str(uuid.uuid4()))
        value['probeSha256'] = packet.digest((self.public / 'ServerBackendProbe.dll').read_bytes())
        raw = probe.image.canonical(value)
        return probe.bundle.control.claim(self.root, raw, packet.digest(raw))

    def source(self, session, held, bound=True):
        raw = probe.prepare(session, held, copy.deepcopy(fixtures.BASE_VALUES))
        result = probe.ProbeImageBinding(session, raw, packet.digest(raw), held)
        if bound:result.bind(probe.image.canonical(fixtures.observed(result.intent)), fixtures.BUILT)
        return result

    def resource(self, session, source):
        raw = policy.prepare(session, source)
        return policy.ProbeRuntimeBinding(session, raw, packet.digest(raw), source)

    def test_already_bound_exact_probe_image_and_same_session_required(self):
        with self.held() as held, self.session() as first, self.session() as second:
            source = self.source(first, held, False)
            with self.assertRaises(ValueError):policy.prepare(first, source)
            source.bind(probe.image.canonical(fixtures.observed(source.intent)), fixtures.BUILT)
            with self.assertRaises(ValueError):policy.prepare(second, source)
            with self.assertRaises(ValueError):policy.anchor(first, object())
            self.assertNotIn('backend-attempt.json', first._records)

    def test_source_record_intent_context_and_manifest_are_pinned(self):
        with self.held() as held, self.session() as session:
            source = self.source(session, held);target = self.resource(session, source)
            self.assertEqual(target.intent['image'], fixtures.BUILT)
            self.assertEqual(target.intent['imageBindingSha256'], packet.digest(session._records['image-binding.json'][1]))
            self.assertEqual(target.intent['imageIntentSha256'], source.report()['intentSha256'])
            self.assertEqual(target.intent['bundleManifestSha256'], held.pin)
            self.assertEqual(target.intent['sourceCodeSha256'], session._plan['codeSha256'])
            self.assertEqual(target.intent['expiresNs'], source.intent['expiresNs'])

    def test_success_binds_new_schema_and_keeps_operational_authority_false(self):
        with self.held() as held, self.session() as session:
            source = self.source(session, held);target = self.resource(session, source)
            result = target.bind(container.canonical(observed(target.intent)), 'b' * 64)
            self.assertTrue(result['generatedProbeRuntimeBound'])
            record = json.loads(session._records['backend-binding.json'][1])
            self.assertEqual(record['schema'], 'fleetory.audit-probe-runtime-binding.v1')
            for key in policy.SOURCE_FIELDS:self.assertEqual(record[key], target.intent[key])
            for key in ('operationalLeaseAuthorized', 'runtimeContinuityVerified', 'nativeOwnerResourceAcknowledged',
                    'actualProbeNativeOwnerAcknowledged', 'backendServiceStartedVerified', 'backendCleanupAuthorized',
                    'dockerObservationAuthenticated', 'legacyNativeOwnerIntegrated', 'backendNamespaceBound',
                    'originalInputsRead', 'executionAuthorized', 'cleanupAuthorized', 'fullSystemRecoveryVerified', 'phase7Complete'):
                self.assertIs(result[key], False)

    def test_foreign_source_consumes_backend_attempt_without_intent_or_source_change(self):
        with self.held() as held, self.session() as first, self.session() as second:
            source = self.source(first, held);raw = policy.prepare(first, source);before = first._records['image-binding.json'][1]
            with self.assertRaises(ValueError):policy.ProbeRuntimeBinding(second, raw, packet.digest(raw), source)
            self.assertIn('backend-attempt.json', second._records);self.assertNotIn('backend-intent.json', second._records)
            self.assertEqual(first._records['image-binding.json'][1], before)

    def test_bad_intent_pin_consumes_slot_and_cannot_retry(self):
        with self.held() as held, self.session() as session:
            source = self.source(session, held);raw = policy.prepare(session, source)
            with self.assertRaises(ValueError):policy.ProbeRuntimeBinding(session, raw, 'f' * 64, source)
            with self.assertRaises(ValueError):self.resource(session, source)

    def test_old_base_linked_and_native_modes_do_not_admit_probe_runtime(self):
        for profile in ('base', 'linked', 'native'):
            with self.subTest(profile=profile), self.held() as held, self.session() as session:
                source = self.source(session, held);raw = policy.prepare(session, source)
                if profile == 'base':
                    with self.assertRaises(ValueError):container.ContainerBinding(session, raw, packet.digest(raw))
                elif profile == 'linked':
                    with self.assertRaises(ValueError):policy.linked.LinkedContainerBinding(session, raw, packet.digest(raw), source)
                else:
                    target = policy.ProbeRuntimeBinding(session, raw, packet.digest(raw), source)
                    target.bind(container.canonical(observed(target.intent)), 'b' * 64)
                    with self.assertRaises(ValueError):native.pair_receipt(session, (source, target))

    def test_schema_identity_pins_unknown_fields_and_six_hundred_second_extension_refused(self):
        changes = [('schema', policy.linked.SCHEMA), ('purpose', policy.linked.PURPOSE), ('nonce', str(uuid.uuid4())),
            ('revision', 'f' * 40), ('controlSha256', 'f' * 64), ('image', probe.BASES[2]), ('imageId', 'sha256:' + 'f' * 64),
            ('imageBindingSha256', 'f' * 64), ('imageIntentSha256', 'f' * 64), ('bundleManifestSha256', 'f' * 64),
            ('sourceCodeSha256', 'f' * 64), ('runtimeProfileSha256', 'f' * 64), ('name', 'foreign'), ('labels', {}), ('openedNs', 0), ('expiresNs', True),
            ('command', 'restore'), ('root', '/foreign')]
        for key, value in changes:
            with self.subTest(key=key), self.held() as held, self.session() as session:
                source = self.source(session, held);intent = json.loads(policy.prepare(session, source));intent[key] = value
                raw = container.canonical(intent)
                with self.assertRaises(ValueError):policy.ProbeRuntimeBinding(session, raw, packet.digest(raw), source)
                self.assertNotIn('backend-intent.json', session._records)
        with self.held() as held, self.session() as session:
            source = self.source(session, held);intent = json.loads(policy.prepare(session, source));intent['expiresNs'] += 600_000_000_000
            raw = container.canonical(intent)
            with self.assertRaises(ValueError):policy.ProbeRuntimeBinding(session, raw, packet.digest(raw), source)

    def test_duplicate_unknown_and_oversized_json_refused(self):
        for kind in ('duplicate', 'extra', 'oversized'):
            with self.subTest(kind=kind), self.held() as held, self.session() as session:
                source = self.source(session, held);raw = policy.prepare(session, source)
                if kind == 'duplicate':raw = raw[:-1] + b',"image":"duplicate"}'
                elif kind == 'extra':raw = raw[:-1] + b',"secret":"generated-refused"}'
                else:raw += b' ' * container.MAX_INTENT
                with self.assertRaises(ValueError):policy.ProbeRuntimeBinding(session, raw, packet.digest(raw), source)

    def reject(self, key, value):
        with self.held() as held, self.session() as session:
            source = self.source(session, held);target = self.resource(session, source)
            incoming = observed(target.intent);incoming[key] = value
            with self.assertRaises(ValueError):target.bind(container.canonical(incoming), 'b' * 64)
            self.assertIn('backend-binding-attempt.json', session._records);self.assertNotIn('backend-binding.json', session._records)
            with self.assertRaises(ValueError):target.bind(container.canonical(observed(target.intent)), 'b' * 64)
            self.assertFalse(target.report()['generatedProbeRuntimeBound'])
            ProbeRuntimeTests.rejected += 1

    def test_every_selected_identity_sandbox_and_runtime_mutation_refused(self):
        changes = [('schema', 'old'), ('id', 'f' * 64), ('name', '/foreign'), ('imageId', 'sha256:' + 'f' * 64),
            ('created', '1970-01-01T00:00:00Z'), ('labels', {}), ('configImage', probe.BASES[2]), ('user', '0:0'),
            ('entrypoint', ['python']), ('command', ['-c', 'exec /bin/sleep 3300']), ('running', False), ('running', 1),
            ('paused', True), ('restarting', True), ('dead', True), ('networkMode', 'host'), ('networks', {'bridge': {}}),
            ('readonly', False), ('privileged', True), ('capDrop', []), ('capAdd', ['SYS_ADMIN']), ('securityOpt', []),
            ('memory', 402653185), ('memory', True), ('nanoCpus', 1000000001), ('nanoCpus', 1.0), ('pidsLimit', 0),
            ('mounts', [{'Type': 'bind'}]), ('ports', {'22/tcp': []}), ('portBindings', {'22/tcp': []}),
            ('binds', ['/foreign:/tool']), ('volumesFrom', ['foreign']), ('devices', [{'PathOnHost': '/dev/sda'}]),
            ('deviceRequests', [{'Count': -1}]), ('pidMode', 'host'), ('ipcMode', 'host'), ('utsMode', 'host'),
            ('usernsMode', 'host'), ('restart', {'Name': 'always', 'MaximumRetryCount': 0}),
            ('restart', {'Name': 'no', 'MaximumRetryCount': False}), ('autoRemove', False), ('publishAllPorts', True),
            ('environment', list(policy.ENVIRONMENT) + ['LD_PRELOAD=/tmp/foreign.so']),
            ('environment', list(reversed(policy.ENVIRONMENT))), ('environment', []),
            ('ulimits', []), ('ulimits', [{'Name': 'core', 'Soft': False, 'Hard': 0}]),
            ('ulimits', [{'Name': 'core', 'Soft': 0, 'Hard': 1}]), ('extraField', 'generated-refused')]
        for key, value in changes:
            with self.subTest(key=key):self.reject(key, value)

    def test_tmpfs_path_flags_size_owner_mode_and_extra_mount_refused(self):
        self.reject('tmpfs', None);self.reject('tmpfs', {});self.reject('tmpfs', {**policy.TMPFS, '/extra': 'rw'})
        for path in ('/data', '/tmp'):
            for old, new in (('noexec', 'exec'), ('nosuid', 'suid'), ('nodev', 'dev'), ('uid=3322', 'uid=0'),
                    ('gid=3322', 'gid=0'), ('mode=0700', 'mode=0777'), ('size=256m', 'size=512m') if path == '/data' else
                    ('size=32m', 'size=64m')):
                value = dict(policy.TMPFS);value[path] = value[path].replace(old, new)
                with self.subTest(path=path, old=old):self.reject('tmpfs', value)

    def test_source_expiry_before_create_or_report_invalidates_runtime(self):
        with self.held() as held, self.session() as session:
            source = self.source(session, held);target = self.resource(session, source)
            source._deadline = time.monotonic() - 1
            with self.assertRaises(ValueError):target.report()
            with self.assertRaises(ValueError):target.bind(container.canonical(observed(target.intent)), 'b' * 64)

    def test_intent_publication_crossing_source_expiry_returns_no_runtime(self):
        with self.held() as held, self.session() as session:
            source = self.source(session, held);write = session._write_once
            def expire(name, value):
                write(name, value)
                if name == 'backend-intent.json':source._deadline = time.monotonic() - 1
            with patch.object(session, '_write_once', side_effect=expire), self.assertRaises(ValueError):self.resource(session, source)
            self.assertIn('backend-intent.json', session._records)

    def test_binding_flush_crossing_source_expiry_never_returns_accepted_id(self):
        with self.held() as held, self.session() as session:
            source = self.source(session, held);target = self.resource(session, source);write = session._write_once
            def expire(name, value):
                write(name, value)
                if name == 'backend-binding.json':source._deadline = time.monotonic() - 1
            with patch.object(session, '_write_once', side_effect=expire), self.assertRaises(ValueError):
                target.bind(container.canonical(observed(target.intent)), 'b' * 64)
            self.assertIsNone(target._bound)

    def test_foreign_backend_record_preserved_and_observation_attempt_consumed(self):
        with self.held() as held, self.session() as session:
            source = self.source(session, held);target = self.resource(session, source)
            path = session._directory.path / 'backend-binding.json';path.write_bytes(b'foreign record must survive')
            with self.assertRaises(OSError):target.bind(container.canonical(observed(target.intent)), 'b' * 64)
            self.assertTrue(target._attempted);self.assertEqual(path.read_bytes(), b'foreign record must survive')

    def test_mutated_source_or_runtime_intent_cannot_be_reported(self):
        for which in ('source', 'runtime'):
            with self.subTest(which=which), self.held() as held, self.session() as session:
                source = self.source(session, held);target = self.resource(session, source)
                changed = source if which == 'source' else target
                changed.intent['expiresNs'] += 1
                with self.assertRaises(ValueError):target.report()

    def test_profile_complete_bytes_are_pinned_before_parse_or_runtime_use(self):
        self.assertEqual(policy.runtime_profile(), policy.PROFILE)
        valid = container.canonical(policy.PROFILE)
        with patch.object(policy.probe.bundle.files, 'inspect_file', return_value=('f' * 64, len(valid), valid)), \
                patch.object(packet, 'strict_json', wraps=packet.strict_json) as parsed:
            with self.assertRaises(ValueError):policy.runtime_profile()
            parsed.assert_not_called()
        with self.held() as held, self.session() as session:
            source = self.source(session, held);target = self.resource(session, source)
            self.assertEqual(target.intent['runtimeProfileSha256'], policy.PROFILE_SHA256)
            self.assertEqual(target.intent['labels']['fleetory.audit.control.runtime.profile'], policy.PROFILE_SHA256)
            with patch.object(policy.probe.bundle.files, 'inspect_file', return_value=('f' * 64, len(valid), valid)):
                with self.assertRaises(ValueError):target.report()

    def test_no_new_publication_or_backend_authority_on_unbound_report(self):
        with self.held() as held, self.session() as session:
            target = self.resource(session, self.source(session, held));report = target.report()
            self.assertFalse(report['generatedProbeRuntimeBound']);self.assertFalse(report['operationalLeaseAuthorized'])
            self.assertFalse(report['backendServiceStartedVerified']);self.assertFalse(report['actualProbeNativeOwnerAcknowledged'])


if __name__ == '__main__':
    result = unittest.TextTestRunner().run(unittest.defaultTestLoader.loadTestsFromTestCase(ProbeRuntimeTests))
    if not result.wasSuccessful():raise SystemExit(1)
    print('PROBE RUNTIME CONTRACT PASS: ' + str(ProbeRuntimeTests.rejected) + ' unsafe observation mutations refused.')
