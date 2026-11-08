"""Frozen public build bytes, fixed recipe/schema and consumed image receipt contracts."""
import copy
from datetime import datetime, timezone
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import time
import unittest
import uuid
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'eng/pilot'))
import audit_probe_image as policy
from audit_backend_binding_tests import control_plan
import audit_linked_binding as linked

bundle, image, packet = policy.bundle, policy.image, policy.packet
BASE_VALUES = [dict(reference=ref, id='sha256:' + ch * 64, layers=['sha256:' + ch * 64], labels={})
    for ref, ch in zip(policy.BASES, 'abc')]
BUILT = 'sha256:' + 'd' * 64


def public_files(root):
    root.mkdir()
    for name in bundle.REQUIRED:
        (root / name).write_bytes(('generated public ' + name).encode('ascii'))
    directory = root / 'runtimes/linux/native'
    directory.mkdir(parents=True)
    (directory / 'fixture.dll').write_bytes(b'generated nested public library')


def measure(root):
    entries = []
    for path in sorted(root.rglob('*'), key=lambda p: p.relative_to(root).as_posix()):
        kind = 'd' if path.is_dir() else 'f'
        data = b'' if kind == 'd' else path.read_bytes()
        entries.append(dict(kind=kind, path=path.relative_to(root).as_posix(), bytes=len(data),
            sha256='-' if kind == 'd' else packet.digest(data)))
    lines = b'fleetory.historical.probe-bundle.v1\n' + b''.join(
        (v['kind'] + ':' + v['path'] + '\n' + str(v['bytes']) + '\n' + v['sha256'] + '\n').encode('ascii') for v in entries)
    return dict(schema='fleetory.historical-probe-bundle.v1', sha256=packet.digest(lines), entries=entries,
        files=sum(v['kind'] == 'f' for v in entries), bytes=sum(v['bytes'] for v in entries),
        runtimeDependenciesAuthenticated=False, softwareOriginAuthenticated=False)


def observed(intent):
    seconds, fraction = divmod(intent['openedNs'] + 1, 1_000_000_000)
    created = datetime.fromtimestamp(seconds, timezone.utc).strftime('%Y-%m-%dT%H:%M:%S') + f'.{fraction:09d}Z'
    return dict(schema='fleetory.audit-probe-image-observation.v1', id=BUILT, tags=[], digests=[], created=created,
        labels=copy.deepcopy(intent['labels']), rootfs='layers', layers=intent['bases'][2]['layers'] + ['sha256:' + c * 64 for c in 'def'],
        os='linux', architecture='amd64', user='3322:3322')


def readback(root, change=None):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        item = tarfile.TarInfo('tool');item.type = tarfile.DIRTYPE;item.mode = 0o755;archive.addfile(item)
        for path in sorted(root.rglob('*'), key=lambda p: p.relative_to(root).as_posix()):
            name = path.relative_to(root).as_posix()
            info = tarfile.TarInfo('tool/' + name)
            data = None if path.is_dir() else path.read_bytes()
            info.type, info.mode = (tarfile.DIRTYPE, 0o755) if data is None else (tarfile.REGTYPE, 0o644)
            info.size = 0 if data is None else len(data)
            if change is not None:
                info, data = change(info, data)
                if info is None:
                    continue
            archive.addfile(info, None if data is None else io.BytesIO(data))
    return output.getvalue()


class ProbeImageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='fleetory-public-probe-contracts-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.public = self.root / 'publish';public_files(self.public)
        self.value = measure(self.public)
        self.raw = image.canonical(self.value)
        self.pin = packet.digest(self.raw)

    def held(self):
        return bundle.HeldProbeBundle(self.public, self.raw, self.pin)

    def session(self):
        value = control_plan(str(uuid.uuid4()))
        value['probeSha256'] = packet.digest((self.public / bundle.REQUIRED[0]).read_bytes())
        raw = image.canonical(value)
        return bundle.control.claim(self.root, raw, packet.digest(raw))

    def resource(self, session, held):
        raw = policy.prepare(session, held, copy.deepcopy(BASE_VALUES))
        return policy.ProbeImageBinding(session, raw, packet.digest(raw), held)

    def test_manifest_uses_existing_probe_descriptor_and_holds_all_nested_files(self):
        with self.held() as held:
            self.assertEqual(held.value, self.value)
            self.assertEqual(len(held.pins), 4)
            self.assertEqual(len(held.directories), 3)
            held.check()

    def test_manifest_pin_types_unknown_fields_duplicates_and_bounds_are_strict(self):
        for value in ({**self.value, 'command': 'restore'}, {**self.value, 'files': True}, {**self.value, 'bytes': True},
                {**self.value, 'softwareOriginAuthenticated': 0}, {**self.value, 'schema': 'old'}, {**self.value, 'entries': []}):
            raw = image.canonical(value)
            with self.assertRaises(ValueError):
                bundle.manifest(raw, packet.digest(raw))
        for raw in (self.raw[:-1] + b',"files":4}', self.raw + b' ' * bundle.MAX_MANIFEST):
            with self.assertRaises(ValueError):
                bundle.manifest(raw, packet.digest(raw))
        with self.assertRaises(ValueError):
            bundle.HeldProbeBundle(self.public, self.raw, 'f' * 64)

    def test_relative_paths_refuse_traversal_hidden_aliases_absolute_and_tar_overflow(self):
        for name in ('../x.dll', 'a/../x.dll', '/tmp/x.dll', 'C:/x.dll', 'a\\x.dll', 'a//x.dll', './x.dll', '.hidden.dll',
                'x/' * 8 + 'a.dll', 'a' * 101 + '.dll', 'a/' + 'b' * 156 + '/x.dll', 'a\x00.dll'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                bundle.relative_name(name)

    def test_missing_required_file_wrong_counts_hash_and_case_alias_are_refused(self):
        for change in ('required', 'count', 'hash', 'case-alias', 'file-type', 'parent'):
            value = copy.deepcopy(self.value)
            if change == 'required':value['entries'] = value['entries'][1:]
            elif change == 'count':value['files'] += 1
            elif change == 'hash':value['sha256'] = 'f' * 64
            elif change == 'case-alias':value['entries'].append({**value['entries'][0], 'path': value['entries'][0]['path'].upper()})
            elif change == 'file-type':value['entries'][0]['path'] = 'private.key'
            else:value['entries'][0]['path'] = 'missing/leaf.dll'
            raw = image.canonical(value)
            with self.subTest(change=change), self.assertRaises(ValueError):
                bundle.manifest(raw, packet.digest(raw))

    def test_file_digest_or_size_substitution_and_hardlinks_are_refused(self):
        path = self.public / bundle.REQUIRED[0]
        original = path.read_bytes();path.write_bytes(b'changed')
        with self.assertRaises(ValueError):self.held()
        path.write_bytes(original)
        alias = self.root / 'hardlink-alias';os.link(path, alias)
        with self.assertRaises((ValueError, OSError, bundle.files.archive.ArchiveError)):
            self.held()
        self.assertEqual(alias.read_bytes(), original)

    def test_extra_file_or_directory_is_preserved_and_rejected(self):
        with self.held() as held:
            extra = self.public / 'extra.json';extra.write_bytes(b'preserved public extra')
            with self.assertRaises(ValueError):held.check()
            self.assertEqual(extra.read_bytes(), b'preserved public extra')

    def test_links_and_foreign_paths_are_refused_before_pinned_content_hashing(self):
        path = self.public / bundle.REQUIRED[0]
        alias = self.root / 'foreign-alias';os.link(path, alias)
        with patch.object(bundle.process.PinnedFile, '_hash') as hashing, self.assertRaises((ValueError, bundle.files.archive.ArchiveError)):
            self.held()
        hashing.assert_not_called()
        with bundle.control.DirectoryLease(self.public) as directory, patch.object(bundle.process.PinnedFile, '_hash') as hashing, self.assertRaises(ValueError):
            bundle._PublishedPin(directory, '../foreign-alias', packet.digest(alias.read_bytes()))
        hashing.assert_not_called()

    def test_late_extra_file_prevents_context_return_and_is_preserved(self):
        with self.held() as held, self.session() as session:
            resource = self.resource(session, held)
            original = held._content
            extra = self.public / 'late.json'
            last = list(held.pins)[-1]
            def change(name):
                data = original(name)
                if name == last:extra.write_bytes(b'late public content must survive')
                return data
            with patch.object(held, '_content', side_effect=change), self.assertRaises(ValueError):
                held.context(policy.definition(resource.intent))
            self.assertEqual(extra.read_bytes(), b'late public content must survive')

    def test_resealed_descriptor_cannot_authorize_wrong_extensions_or_missing_parents(self):
        for kind in ('extension', 'parent'):
            value = copy.deepcopy(self.value)
            value['entries'][0]['path'] = 'private.key' if kind == 'extension' else 'absent/leaf.dll'
            value['entries'].sort(key=lambda v: v['path'])
            lines = b'fleetory.historical.probe-bundle.v1\n' + b''.join((v['kind'] + ':' + v['path'] + '\n' +
                str(v['bytes']) + '\n' + v['sha256'] + '\n').encode('ascii') for v in value['entries'])
            value['sha256'] = packet.digest(lines)
            raw = image.canonical(value)
            with self.subTest(kind=kind), self.assertRaises(ValueError):bundle.manifest(raw, packet.digest(raw))

    def test_context_is_deterministic_exact_public_files_with_no_host_paths(self):
        with self.held() as held, self.session() as session:
            resource = self.resource(session, held)
            raw = resource.build_bytes()
            self.assertEqual(raw, held.context(policy.definition(resource.intent)))
            self.assertLessEqual(len(raw), bundle.MAX_CONTEXT)
            with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
                names = archive.getnames()
                self.assertEqual(names, ['Dockerfile'] + ['publish/' + n for n in held.pins])
                for item in archive:
                    self.assertTrue(item.isfile());self.assertEqual(item.uid, 0);self.assertEqual(item.gid, 0)
                    self.assertEqual(item.mode, 0o644);self.assertEqual(item.mtime, 0);self.assertFalse(item.pax_headers)
            self.assertEqual(resource.intent['contextSha256'], packet.digest(raw))

    def test_fixed_definition_has_three_pinned_bases_and_only_expected_copy_label_user(self):
        with self.held() as held, self.session() as session:
            resource = self.resource(session, held)
            recipe = policy.definition(resource.intent).decode('ascii')
            self.assertEqual(recipe.count('FROM '), 3);self.assertEqual(recipe.count('COPY '), 3)
            self.assertNotIn('RUN ', recipe);self.assertNotIn('ADD ', recipe);self.assertNotIn(str(self.root), recipe)
            self.assertTrue(recipe.endswith('USER 3322:3322\n'))
            self.assertEqual(resource.intent['definitionSha256'], packet.digest(recipe.encode()))

    def test_base_reference_ids_layers_labels_and_label_injection_are_strict(self):
        mutations = [('reference', 'mutable:latest'), ('id', 'a' * 64), ('layers', []), ('labels', {'fleetory.audit.control.nonce': 'foreign'}),
            ('labels', {'evil\nRUN': 'injection'}), ('labels', {'public': 'line\nvalue'}), ('labels', {'public': True})]
        for key, value in mutations:
            bases = copy.deepcopy(BASE_VALUES);bases[0][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):policy.bases(bases)
        bases = copy.deepcopy(BASE_VALUES);bases[1]['id'] = bases[0]['id']
        with self.assertRaises(ValueError):policy.bases(bases)

    def test_image_intent_requires_same_control_code_probe_context_and_manifest(self):
        for key, item in [('schema', image.SCHEMA), ('purpose', image.PURPOSE), ('nonce', str(uuid.uuid4())),
                ('revision', 'f' * 40), ('controlSha256', 'f' * 64), ('sourceCodeSha256', 'f' * 64), ('probeSha256', 'f' * 64),
                ('bundleManifestSha256', 'f' * 64), ('bundleSha256', 'f' * 64), ('bundleFiles', True), ('bundleBytes', True),
                ('definitionSha256', 'f' * 64), ('contextSha256', 'f' * 64), ('contextBytes', True), ('expiresNs', True),
                ('openedNs', 0), ('command', 'restore')]:
            with self.subTest(key=key), self.held() as held, self.session() as session:
                value = json.loads(policy.prepare(session, held, copy.deepcopy(BASE_VALUES)));value[key] = item;raw = image.canonical(value)
                with self.assertRaises(ValueError):policy.ProbeImageBinding(session, raw, packet.digest(raw), held)
                self.assertIn('image-attempt.json', session._records);self.assertNotIn('image-intent.json', session._records)

    def test_success_binds_untagged_build_receipt_and_preserves_authority_boundaries(self):
        with self.held() as held, self.session() as session:
            resource = self.resource(session, held)
            report = resource.bind(image.canonical(observed(resource.intent)), BUILT)
            self.assertTrue(report['generatedProbeImageRecipeBound'])
            self.assertEqual(json.loads(session._records['image-binding.json'][1])['contextSha256'], resource.intent['contextSha256'])
            for key in ('buildProvenanceAuthenticated', 'publicationOriginAuthenticated', 'deployedReleaseVerified',
                    'legacyApplicationImageVerified', 'nativeOwnerResourceAcknowledged', 'backendCleanupAuthorized',
                    'dockerObservationAuthenticated', 'originalInputsRead', 'executionAuthorized', 'fullSystemRecoveryVerified', 'phase7Complete'):
                self.assertIs(report[key], False)

    def test_probe_profile_cannot_be_used_as_original_python_or_linked_native_image(self):
        with self.held() as held, self.session() as session:
            resource = self.resource(session, held);resource.bind(image.canonical(observed(resource.intent)), BUILT)
            with self.assertRaises(ValueError):linked.anchor(session, resource)
        with self.held() as held, self.session() as session:
            raw = policy.prepare(session, held, copy.deepcopy(BASE_VALUES))
            with self.assertRaises(ValueError):image.ImageBinding(session, raw, packet.digest(raw))
            self.assertNotIn('image-intent.json', session._records)

    def test_mutable_tag_wrong_id_user_layers_labels_or_time_refused_and_attempt_consumed(self):
        mutations = [('tags', ['mutable:latest']), ('digests', ['registry@sha256:' + 'f' * 64]), ('id', BASE_VALUES[0]['id']),
            ('user', '0:0'), ('os', 'windows'), ('architecture', 'arm64'), ('rootfs', 'unknown'), ('layers', ['sha256:' + 'f' * 64]),
            ('labels', {}), ('created', '1970-01-01T00:00:01Z'), ('schema', 'old'), ('root', '/foreign')]
        for key, item in mutations:
            with self.subTest(key=key), self.held() as held, self.session() as session:
                resource = self.resource(session, held);value = observed(resource.intent);value[key] = item
                with self.assertRaises(ValueError):resource.bind(image.canonical(value), BUILT)
                self.assertIn('image-binding-attempt.json', session._records);self.assertNotIn('image-binding.json', session._records)
                with self.assertRaises(ValueError):resource.bind(image.canonical(observed(resource.intent)), BUILT)

    def test_foreign_observation_preserves_source_receipt_and_consumes_target_attempt(self):
        with self.held() as held, self.session() as source, self.session() as target:
            first = self.resource(source, held);before = first.bind(image.canonical(observed(first.intent)), BUILT)
            saved = source._records['image-binding.json'][1]
            second = self.resource(target, held)
            with self.assertRaises(ValueError):second.bind(image.canonical(observed(first.intent)), BUILT)
            self.assertEqual(source._records['image-binding.json'][1], saved);self.assertTrue(before['generatedProbeImageRecipeBound'])
            self.assertFalse(second.report()['generatedProbeImageRecipeBound'])

    def test_context_or_source_lifetime_mutation_never_returns_build_bytes_or_binding(self):
        with self.held() as held, self.session() as session:
            resource = self.resource(session, held);original = resource._context;resource._context += b'changed'
            with self.assertRaises(ValueError):resource.build_bytes()
            resource._context = original;resource._deadline = time.monotonic() - 1
            with self.assertRaises(ValueError):resource.build_bytes()

    def test_expiry_during_binding_flush_never_returns_accepted_image(self):
        with self.held() as held, self.session() as session:
            resource = self.resource(session, held);original = session._write_once
            def expire(name, value):
                original(name, value)
                if name == 'image-binding.json':resource._deadline = time.monotonic() - 1
            with patch.object(session, '_write_once', side_effect=expire), self.assertRaises(ValueError):
                resource.bind(image.canonical(observed(resource.intent)), BUILT)
            self.assertIsNone(resource._bound)

    def test_readback_verifies_every_published_file_and_exact_tree_without_extracting(self):
        with self.held() as held:
            result = bundle.verify_readback(readback(self.public), held)
            self.assertEqual(result['files'], self.value['files']);self.assertEqual(result['bundleSha256'], self.value['sha256'])

    def test_readback_refuses_changed_omitted_linked_or_traversal_file(self):
        for kind in ('changed', 'omitted', 'symlink', 'hardlink', 'traversal', 'permissions'):
            def mutate(item, body):
                if item.name != 'tool/ServerBackendProbe.dll':return item, body
                if kind == 'changed':return item, b'x' * len(body)
                if kind == 'omitted':return None, None
                if kind in ('symlink', 'hardlink'):
                    item.type = tarfile.SYMTYPE if kind == 'symlink' else tarfile.LNKTYPE;item.size = 0;item.linkname = '../foreign'
                    return item, None
                if kind == 'traversal':item.name = 'tool/../ServerBackendProbe.dll'
                if kind == 'permissions':item.mode = 0o777
                return item, body
            with self.subTest(kind=kind), self.held() as held, self.assertRaises(ValueError):
                bundle.verify_readback(readback(self.public, mutate), held)

    def test_readback_empty_oversized_and_unknown_root_are_refused(self):
        with self.held() as held:
            for raw in (b'', b'x' * (bundle.MAX_CONTEXT + 1), b'\0' * 10240):
                with self.assertRaises(ValueError):bundle.verify_readback(raw, held)


if __name__ == '__main__':
    unittest.main()
