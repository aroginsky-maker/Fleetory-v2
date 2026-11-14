"""Typed publication root, held manifest and one-use handoff contracts; no publisher or secrets."""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import tempfile
import unittest
import uuid
from types import SimpleNamespace

import audit_probe_image_tests as fixtures
import audit_publication_namespace as ns
import audit_archive

packet=ns.packet


class PublicationNamespaceContracts(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='fleetory-public-namespace-contract-');self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve();self.repo=self.root/'repository';self.repo.mkdir();(self.repo/'artifacts').mkdir()
        self.control=self.root/'controls';self.control.mkdir()
        self.source=self.root/'public';fixtures.public_files(self.source)
        self.manifest=ns.bundle.prep.canonical(fixtures.measure(self.source));self.manifest_pin=packet.digest(self.manifest)

    def session(self):
        value=fixtures.control_plan(str(uuid.uuid4()));raw=ns.bundle.prep.canonical(value)
        return ns.control.claim(self.control,raw,packet.digest(raw))

    @contextmanager
    def pair(self):
        with self.session() as session:
            data=ns.prepare(session,self.manifest_pin,'e'*64)
            with ns.OwnedPublication(self.repo,data,packet.digest(data)) as owned:
                command=SimpleNamespace(directory=self.repo,executable=None,check=lambda:None)
                child=SimpleNamespace(pid=os.getpid())
                fence=SimpleNamespace(identity=lambda *_:dict(pid=os.getpid(),actualImageMatched=True))
                with ns.BoundPublication(command,session,child,fence,data,packet.digest(data),owned.ready()) as bound:
                    yield session,owned,bound

    def fill(self,path):
        for source in self.source.rglob('*'):
            target=path/source.relative_to(self.source)
            if source.is_dir():target.mkdir()
            else:target.write_bytes(source.read_bytes())

    def test_separate_namespace_keeps_old_empty_marker_and_inventories_closed(self):
        nonce=str(uuid.uuid4())
        self.assertNotEqual(ns.name(nonce),ns.empty.payload_name(nonce));self.assertNotEqual(ns.MARKER,ns.empty.MARKER)
        self.assertEqual(len(ns.SOURCES),17);self.assertEqual(len(set(ns.SOURCES)),17)
        import audit_native_probe_create as creator
        self.assertEqual((len(creator.SOURCES),len(creator.base.SOURCES),len(creator.payload.SOURCES)),(46,45,34))
        self.assertNotIn('eng/pilot/audit_publication_namespace.py',creator.SOURCES)

    def test_intent_unknown_fields_hash_schema_nonce_and_types_are_closed(self):
        with self.session() as session:
            data=ns.prepare(session,self.manifest_pin,'e'*64);value=json.loads(data)
            for key,item in (('schema',ns.empty.header.__name__),('nonce','../escape'),('controlSha256',True),('manifestSha256','F'*64),('root','/host'),('command',['publish'])):
                altered=ns.bundle.prep.canonical({**value,key:item})
                with self.subTest(key=key),self.assertRaises(ValueError):ns.OwnedPublication(self.repo,altered,packet.digest(altered))
            with self.assertRaises(ValueError):ns.OwnedPublication(self.repo,data,'f'*64)
            self.assertEqual(list((self.repo/'artifacts').iterdir()),[])

    def test_collision_does_not_adopt_or_remove_an_existing_namespace(self):
        with self.session() as session:
            data=ns.prepare(session,self.manifest_pin,'e'*64)
            with ns.OwnedPublication(self.repo,data,packet.digest(data)) as owned:
                marker=(owned.directory.path/ns.MARKER).read_bytes()
                with self.assertRaises(FileExistsError):ns.OwnedPublication(self.repo,data,packet.digest(data))
                self.assertEqual((owned.directory.path/ns.MARKER).read_bytes(),marker)

    def test_independent_binding_holds_every_file_through_matching_owner_ack(self):
        with self.pair() as (session,owned,bound):
            self.fill(owned.output.path);expected=bound.seal(self.manifest);value=owned.seal(self.manifest)
            self.assertEqual(value,expected);self.assertEqual(len(bound.published.pins),4)
            self.assertEqual(set(bound.published.pins),set(owned.published.pins))
            bound.acknowledge(value);pin=bound.release();packet.hex_value(pin)
            self.assertIn('publication-release.json',session._records)
            with self.assertRaises(ValueError):bound.check()
            self.assertTrue(owned.directory.path.is_dir())
            self.assertEqual(ns.bundle.tree(owned.output.path),{n:v['kind'] for n,v in owned.published.entries.items()})

    def test_publication_attempt_is_consumed_even_on_bad_live_owner(self):
        with self.session() as session:
            data=ns.prepare(session,self.manifest_pin,'e'*64)
            with ns.OwnedPublication(self.repo,data,packet.digest(data)) as owned:
                command=SimpleNamespace(directory=self.repo,executable=None,check=lambda:None)
                child=SimpleNamespace(pid=os.getpid());fence=SimpleNamespace(identity=lambda *_:dict(pid=os.getpid()+1))
                with self.assertRaises(ValueError):ns.BoundPublication(command,session,child,fence,data,packet.digest(data),owned.ready())
                self.assertIn('publication-attempt.json',session._records)
                with self.assertRaises(ValueError):ns.BoundPublication(command,session,child,fence,data,packet.digest(data),owned.ready())
                self.assertTrue((owned.directory.path/ns.MARKER).is_file())

    def test_foreign_controller_cannot_bind_namespace(self):
        with self.pair() as (_,owned,bound),self.session() as foreign:
            with self.assertRaises(ValueError):ns.BoundPublication(bound.command,foreign,bound.child,bound.fence,
                ns.bundle.prep.canonical(owned.value),packet.digest(ns.bundle.prep.canonical(owned.value)),owned.ready())
            self.assertIn('publication-attempt.json',foreign._records)

    def test_manifest_tamper_consumes_seal_attempt_and_preserves_unknown_tree(self):
        with self.pair() as (session,owned,bound):
            self.fill(owned.output.path)
            with self.assertRaises(ValueError):bound.seal(self.manifest+b' ')
            with self.assertRaises(ValueError):bound.seal(self.manifest)
            self.assertIn('publication-seal-attempt.json',session._records);self.assertNotIn('publication-binding.json',session._records)
            with self.assertRaises(ValueError):owned.seal(self.manifest+b' ')
            with self.assertRaises(ValueError):owned.seal(self.manifest)
            self.assertTrue((owned.output.path/'ServerBackendProbe.dll').is_file())

    def test_unknown_root_or_output_files_are_preserved_and_rejected(self):
        with self.pair() as (_,owned,bound):
            extra=owned.directory.path/'unknown.json';extra.write_bytes(b'public unknown')
            with self.assertRaises(ValueError):bound.check()
            with self.assertRaises(ValueError):owned.check()
            self.assertEqual(extra.read_bytes(),b'public unknown')
        with self.pair() as (_,owned,bound):
            self.fill(owned.output.path);extra=owned.output.path/'unknown.json';extra.write_bytes(b'public unknown')
            with self.assertRaises(ValueError):bound.seal(self.manifest)
            self.assertTrue(extra.is_file())

    def test_file_mutation_after_seal_refuses_ack_and_release(self):
        with self.pair() as (session,owned,bound):
            self.fill(owned.output.path);value=bound.seal(self.manifest)
            path=owned.output.path/'ServerBackendProbe.dll'
            try:path.write_bytes(b'changed public bytes')
            except PermissionError:return # Windows denies mutation while descriptors are held.
            with self.assertRaises(ValueError):bound.acknowledge(value)
            with self.assertRaises(ValueError):bound.release()
            self.assertNotIn('publication-release.json',session._records)

    def test_root_directory_replacement_is_detected_from_held_identity(self):
        with self.pair() as (_,owned,bound):
            original=owned.directory.path;renamed=original.with_name(original.name+'-moved')
            try:original.rename(renamed)
            except PermissionError:
                self.assertTrue((original/ns.MARKER).is_file());return
            original.mkdir()
            with self.assertRaises(ValueError):bound.check()
            with self.assertRaises(ValueError):owned.check()
            self.assertTrue((renamed/ns.MARKER).is_file())

    def test_marker_replacement_is_detected_and_not_removed(self):
        with self.pair() as (_,owned,bound):
            path=owned.directory.path/ns.MARKER
            try:path.unlink();path.write_bytes(b'public replacement')
            except PermissionError:return
            with self.assertRaises(ValueError):bound.check()
            self.assertTrue(path.is_file())

    def test_symlink_and_hardlink_output_cannot_be_held_as_public_files(self):
        for kind in ('symbolic','hard'):
            with self.subTest(kind=kind),self.pair() as (_,owned,bound):
                self.fill(owned.output.path);path=owned.output.path/'ServerBackendProbe.dll';path.unlink()
                target=self.source/'ServerBackendProbe.dll'
                try:
                    if kind=='symbolic':path.symlink_to(target)
                    else:os.link(target,path)
                except OSError:continue # Platform privilege refusal also prevents creating the unsafe entry.
                with self.assertRaises((ValueError,audit_archive.ArchiveError)):bound.seal(self.manifest)
                self.assertTrue(target.is_file())

    def test_ack_and_release_cannot_be_replayed_or_grant_private_or_publisher_authority(self):
        with self.pair() as (session,owned,bound):
            self.fill(owned.output.path);value=bound.seal(self.manifest)
            with self.assertRaises(ValueError):bound.release()
            for key,item in (('privateInputsAccepted',True),('actualNativePublicationVerified',True),('manifestSha256','f'*64),('files',True),('ownerSha256','f'*64)):
                with self.subTest(key=key),self.assertRaises(ValueError):bound.acknowledge({**value,key:item})
            bound.acknowledge(value)
            with self.assertRaises(ValueError):bound.acknowledge(value)
            bound.release()
            with self.assertRaises(ValueError):bound.release()
            self.assertEqual(json.loads(session._records['publication-release.json'][1])['backendCleanupAuthorized'],False)

    def test_old_empty_namespace_still_rejects_nonempty_removal(self):
        with self.session() as session:
            value=dict(schema='fleetory.audit-payload-reservation.v1',nonce=session._plan['nonce'],controlSha256=session.report()['reservationSha256'],
                controlDirectorySha256=ns.empty.directory_hash(session._directory),bundleSha256='e'*64)
            with ns.empty.OwnedPayload(self.repo,value) as empty:
                (empty.path/'public.json').write_bytes(b'public bytes')
                with self.assertRaises(ValueError):empty.remove()
                self.assertTrue((empty.path/'public.json').is_file())

    def test_shared_writer_refuses_unknown_paths_before_any_file_creation(self):
        with ns.control.DirectoryLease(self.repo/'artifacts') as directory:
            for name in ('../outside.json','.env','unknown.json','C:/private.key',True):
                with self.subTest(name=name),self.assertRaises(ValueError):ns.empty._create_named_record(directory,name,b'public bytes')
            self.assertEqual(list(directory.path.iterdir()),[])

    def test_posix_exit_observation_does_not_reap_before_group_cleanup(self):
        import native_publication_namespace as fixture
        from unittest.mock import Mock,patch
        child=Mock();fence=Mock();fence.exited.return_value=True
        with patch.object(fixture.os,'name','posix'):
            self.assertTrue(fixture.owner_exited(child,fence))
            fixture.wait_owner_exit(child,fence,ns.bundle.prep.process.time.monotonic_ns())
        child.poll.assert_not_called();child.wait.assert_not_called()
        self.assertEqual(fence.exited.call_count,2)


if __name__=='__main__':unittest.main()
