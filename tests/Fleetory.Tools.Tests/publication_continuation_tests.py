"""Generated continuation contracts. Synthetic native evidence here is not an actual native proof."""
from contextlib import ExitStack
import copy
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
import uuid
from unittest.mock import patch

import audit_probe_image_tests as fixtures
import audit_publication_continuation as policy

ns, packet = policy.ns, policy.packet
C, H = policy.prep.canonical, packet.digest


class PublicationContinuationContracts(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='fleetory-public-continuation-contract-')
        self.addCleanup(self.temp.cleanup)
        self.held = ExitStack();self.addCleanup(self.held.close)
        self.root = Path(self.temp.name).resolve();self.repo = self.root/'repository';self.repo.mkdir()
        (self.repo/'artifacts').mkdir();self.controls = self.root/'controls';self.controls.mkdir()
        self.source = self.root/'public';fixtures.public_files(self.source)
        self.manifest = C(fixtures.measure(self.source))

    def capability(self, activate=True):
        plan = fixtures.control_plan(str(uuid.uuid4()))
        plan['probeSha256'] = H((self.source/'ServerBackendProbe.dll').read_bytes())
        raw = C(plan);session = self.held.enter_context(ns.control.claim(self.controls, raw, H(raw)))
        data = ns.prepare(session, H(self.manifest), 'a'*64)
        owned = self.held.enter_context(ns.OwnedPublication(self.repo, data, H(data)))
        for source in self.source.rglob('*'):
            target = owned.output.path/source.relative_to(self.source)
            if source.is_dir():target.mkdir()
            else:target.write_bytes(source.read_bytes())
        command = SimpleNamespace(directory=self.repo, executable=None, check=lambda:None)
        owner = dict(pid=os.getpid(), actualImageMatched=True)
        fence = SimpleNamespace(identity=lambda *_:owner)
        bound = self.held.enter_context(ns.BoundPublication(command, session, SimpleNamespace(pid=os.getpid()), fence,
            data, H(data), owned.ready()))
        receipt = bound.seal(self.manifest);bound.acknowledge(receipt)
        session._write_once('native-publication-receipt.json', dict(actualNativePublicationVerified=True,
            actualOwnedProcess=owner, manifestSha256=H(self.manifest), fileDescriptorsHeld=4))
        root = self.held.enter_context(ns.control.DirectoryLease(self.repo))
        code = self.root/(plan['nonce']+'.py');code.write_bytes(b'generated public controller')
        source_pin = self.held.enter_context(ns.process.PinnedFile(code, H(code.read_bytes())))
        delivery = policy._Delivery(root, (source_pin,))
        item = policy.RetainedPublication(bound, delivery);self.addCleanup(item.close)
        delivery.item = item;item.release_pin = bound.release()
        evidence = dict(profile='native-publication-retain', osIdentity=owner, processIdentityAuthenticated=True,
            launchAttemptConsumed=True, fence=dict(noRunningMembersVerified=True), payload=dict(actualNativePublicationVerified=True,
            publicationDescriptorsRetained=True, selectedSourceFilesPinned=len(policy.SOURCES)))
        result = ns.process.FencedResult(0, b'', b'', C(evidence))
        if activate:item.activate(result)
        return item, bound, result, code

    def resource(self, item):
        resource = item.image(copy.deepcopy(fixtures.BASE_VALUES))
        resource.bind(C(fixtures.observed(resource.intent)), fixtures.BUILT)
        return resource

    def observation(self, item, resource):
        return dict(id='e'*64, name='/fleetory-probe-copy-'+item.session._plan['nonce'].replace('-', ''),
            image=fixtures.BUILT, configImage=fixtures.BUILT,
            labels=dict(resource.intent['labels'], **{'fleetory.audit.control.copy':'public-probe-readback.v1'}),
            running=False, status='created', pid=0, network='none', mounts=[], readonly=True, privileged=False,
            user='3322:3322', entrypoint=['/bin/true'])

    def test_separate_fixed_profile_keeps_old_source_inventories_and_timeouts(self):
        self.assertEqual((len(policy.native.SOURCES), len(policy.SOURCES), len(set(policy.SOURCES))), (36,40,40))
        self.assertEqual(policy.WINDOW_NS, 60_000_000_000)
        self.assertEqual(policy._ContinuationPumps.profile, 'native-publication-retain')
        self.assertEqual(policy._ContinuationPumps.max_frames, 4)
        self.assertEqual(policy._ContinuationPumps.switch, '-PublicProbePublicationOnly')

    def test_same_descriptors_survive_native_release_without_reopening(self):
        item, bound, _, _ = self.capability()
        pins = item._bundle.pins
        descriptors = {n:p.fd for n,p in pins.items()}
        bound.close();item.check()
        self.assertIs(item._bundle, bound.published)
        self.assertEqual(descriptors, {n:p.fd for n,p in item._bundle.pins.items()})
        self.assertTrue(all(os.fstat(fd).st_size>0 for fd in descriptors.values()))
        self.assertTrue(item.report()['samePublicationDescriptorsHeld'])

    def test_replacing_a_pin_with_a_duplicate_fd_does_not_preserve_continuity(self):
        item, _, _, _ = self.capability();pin = item._bundle.pins['ServerBackendProbe.dll'];duplicate = os.dup(pin.fd)
        try:
            with patch.object(pin,'fd',duplicate),self.assertRaises(ValueError):item.check()
        finally:os.close(duplicate)

    def test_provisional_capture_cannot_authorize_an_image(self):
        item, _, result, _ = self.capability(False)
        with self.assertRaises(ValueError):item.check()
        with self.assertRaises(ValueError):item.image(copy.deepcopy(fixtures.BASE_VALUES))
        item.activate(result);item.check()
        with self.assertRaises(ValueError):item.activate(result)

    def test_native_result_must_match_actual_owner_profile_and_complete_fence(self):
        mutations = [('profile','native-publication'), ('osIdentity',dict(pid=1)), ('processIdentityAuthenticated',False),
            ('launchAttemptConsumed',False), ('fence',dict(noRunningMembersVerified=False)),
            ('payload',dict(actualNativePublicationVerified=False, publicationDescriptorsRetained=True, selectedSourceFilesPinned=40)),
            ('payload',dict(actualNativePublicationVerified=True, publicationDescriptorsRetained=False, selectedSourceFilesPinned=40)),
            ('payload',dict(actualNativePublicationVerified=True, publicationDescriptorsRetained=True, selectedSourceFilesPinned=True))]
        for key,value in mutations:
            with self.subTest(key=key):
                item, _, result, _ = self.capability(False)
                altered = json.loads(result.evidence);altered[key] = value
                with self.assertRaises(ValueError):item.activate(ns.process.FencedResult(0,b'',b'',C(altered)))
                self.assertNotIn('publication-continuation-binding.json',item.session._records)

    def test_nonzero_exit_stderr_and_untyped_result_are_not_accepted(self):
        item, _, result, _ = self.capability(False)
        for bad in (ns.process.FencedResult(1,b'',b'',result.evidence), ns.process.FencedResult(0,b'',b'error',result.evidence), object()):
            with self.assertRaises(ValueError):item.activate(bad)

    def test_close_releases_every_held_publication_fd_and_preserves_namespace(self):
        item, bound, _, _ = self.capability();fds = [p.fd for p in item._bundle.pins.values()]
        path = bound.directory.path;item.close();item.close()
        for fd in fds:
            with self.assertRaises(OSError):os.fstat(fd)
        self.assertTrue(path.is_dir())
        with self.assertRaises(ValueError):item.report()

    def test_wall_expiry_boundary_and_clock_rollback_refused(self):
        item, _, _, _ = self.capability()
        for now in (item.opened-1,item.expires,item.expires+1):
            with patch.object(policy.time,'time_ns',return_value=now),self.assertRaises(ValueError):item.check()

    def test_monotonic_expiry_and_clock_rollback_refused(self):
        item, _, _, _ = self.capability()
        for now in (item._monotonic-1,item._monotonic+policy.WINDOW_NS):
            with patch.object(policy.time,'monotonic_ns',return_value=now),self.assertRaises(ValueError):item.check()

    def test_forked_or_foreign_controller_cannot_reuse_capability(self):
        item, _, _, _ = self.capability()
        with patch.object(policy.os,'getpid',return_value=item._controller+1),self.assertRaises(ValueError):item.check()

    def test_publication_mutation_is_denied_or_detected(self):
        item, bound, _, _ = self.capability()
        path = bound.output.path/'ServerBackendProbe.dll'
        try:path.write_bytes(b'changed public bytes')
        except PermissionError:item.check()
        else:
            with self.assertRaises(ValueError):item.check()

    def test_namespace_replacement_is_denied_or_detected(self):
        item, bound, _, _ = self.capability();path = bound.directory.path
        try:path.rename(path.with_name(path.name+'-moved'))
        except PermissionError:item.check()
        else:
            with self.assertRaises((ValueError,FileNotFoundError)):item.check()

    def test_unknown_output_file_is_preserved_and_refused(self):
        item, bound, _, _ = self.capability();path = bound.output.path/'unexpected.json';path.write_bytes(b'public')
        with self.assertRaises(ValueError):item.check()
        self.assertEqual(path.read_bytes(),b'public')

    def test_pinned_controller_source_change_is_denied_or_detected(self):
        item, _, _, path = self.capability()
        try:path.write_bytes(b'changed controller')
        except PermissionError:item.check()
        else:
            with self.assertRaises(ValueError):item.check()

    def test_invalid_bases_consume_image_attempt_without_any_image_intent(self):
        item, _, _, _ = self.capability()
        with self.assertRaises(ValueError):item.image([])
        with self.assertRaises(ValueError):item.image(copy.deepcopy(fixtures.BASE_VALUES))
        self.assertIn('publication-continuation-use.json',item.session._records)
        self.assertNotIn('image-intent.json',item.session._records)

    def test_context_is_built_from_the_still_held_publication(self):
        item, _, _, _ = self.capability();resource = self.resource(item)
        raw = resource.build_bytes();self.assertEqual(raw,resource.build_bytes())
        with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
            self.assertEqual(archive.extractfile('publish/ServerBackendProbe.dll').read(),(self.source/'ServerBackendProbe.dll').read_bytes())
        with self.assertRaises(ValueError):item.image(copy.deepcopy(fixtures.BASE_VALUES))

    def test_resource_cannot_outlive_lease_close(self):
        item, _, _, _ = self.capability();resource = self.resource(item);item.close()
        for operation in (resource.report,resource.build_bytes):
            with self.assertRaises(ValueError):operation()

    def test_resource_cannot_outlive_lease_expiry(self):
        item, _, _, _ = self.capability();resource = self.resource(item)
        with patch.object(policy.time,'monotonic_ns',return_value=item._monotonic+policy.WINDOW_NS):
            with self.assertRaises(ValueError):resource.build_bytes()
            with self.assertRaises(ValueError):resource.report()

    def test_foreign_image_capability_is_refused_before_readback(self):
        item, _, _, _ = self.capability();foreign, _, _, _ = self.capability();resource = self.resource(foreign)
        with self.assertRaises(ValueError):item.complete(resource,'e'*64,C(self.observation(item,resource)),fixtures.readback(self.source))
        self.assertNotIn('publication-continuation-readback.json',item.session._records)

    def test_stopped_copy_image_network_types_and_extra_fields_are_closed(self):
        for key,value in (('image','sha256:'+'f'*64),('network','host'),('running',0),('pid',False),('mounts',[{}]),('extra',True)):
            with self.subTest(key=key):
                item, _, _, _ = self.capability();resource = self.resource(item);observation=self.observation(item,resource)
                observation[key]=value
                with self.assertRaises(ValueError):item.complete(resource,'e'*64,C(observation),fixtures.readback(self.source))
                self.assertNotIn('publication-continuation-readback.json',item.session._records)

    def test_corrupt_readback_consumes_attempt_and_never_writes_ack(self):
        item, _, _, _ = self.capability();resource = self.resource(item);observation=C(self.observation(item,resource))
        with self.assertRaises((ValueError,tarfile.ReadError)):item.complete(resource,'e'*64,observation,b'corrupt')
        with self.assertRaises(ValueError):item.complete(resource,'e'*64,observation,fixtures.readback(self.source))
        self.assertNotIn('publication-continuation-readback.json',item.session._records)

    def test_complete_readback_binds_publication_image_and_stopped_copy_once(self):
        item, _, _, _ = self.capability();resource = self.resource(item);observation=C(self.observation(item,resource));copied=fixtures.readback(self.source)
        result=item.complete(resource,'e'*64,observation,copied)
        record=policy._record(item.session,'publication-continuation-readback.json')
        self.assertEqual((result['files'],record['imageId'],record['containerId']),(4,fixtures.BUILT,'e'*64))
        self.assertEqual(record['readbackSha256'],H(copied));self.assertTrue(item.report()['readbackVerified'])
        self.assertFalse(record['operationalLeaseAuthorized']);self.assertFalse(record['backendCleanupAuthorized'])
        with self.assertRaises(ValueError):item.complete(resource,'e'*64,observation,copied)

    def test_closed_control_session_prevents_later_image_use(self):
        item, _, _, _ = self.capability();item.session.close()
        with self.assertRaises(ValueError):item.check()

    def test_command_profiles_reject_untyped_delivery_and_wrong_factory(self):
        executable=Path(sys.executable);pin=H(executable.read_bytes())
        with ns.process.PinnedFile(executable,pin,True) as runtime:
            for profile,factory,delivery in (('native-publication-retain',policy._ContinuationPumps,object()),
                    ('native-publication-retain',policy.native._NativePublicationPumps,object()),
                    ('native-publication',policy.native._NativePublicationPumps,object())):
                command=ns.process._Command(runtime,(),(),self.repo,{},profile,factory,dotnet=runtime,continuation=delivery)
                with self.assertRaises(ValueError):command.check()


if __name__=='__main__':unittest.main()
