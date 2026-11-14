"""Generated retained sleep contracts; synthetic native/image evidence is not an actual runtime proof."""
import copy
import json
import os
from pathlib import Path
import time
import unittest
from unittest.mock import patch

import publication_continuation_tests as publication_fixture
import audit_probe_image_tests as image_fixture
import audit_probe_runtime_tests as runtime_fixture
import audit_retained_runtime as policy

C, H = policy.container.canonical, policy.packet.digest


class RetainedRuntimeContracts(unittest.TestCase):
    def setUp(self):
        self.fixture=publication_fixture.PublicationContinuationContracts();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        root=self.fixture.repo/'eng/pilot';root.mkdir(parents=True)
        for name in policy.EXTRA_SOURCES:
            (self.fixture.repo/name).write_bytes((Path(policy.__file__).parent/Path(name).name).read_bytes())

    def source(self, complete=True):
        retained, _, _, _=self.fixture.capability();source=self.fixture.resource(retained)
        if complete:
            observation=C(self.fixture.observation(retained,source))
            retained.complete(source,'e'*64,observation,image_fixture.readback(self.fixture.source))
        return retained,source

    def target(self, source, data=None, pin=None, session=None, source_pins=None):
        values=policy.measure_sources(source) if source_pins is None else source_pins
        session=source.session if session is None else session
        raw=policy.prepare(source.session,source,values) if data is None else data
        target=policy.RetainedRuntimeBinding(session,raw,H(raw) if pin is None else pin,source,source_pins=values)
        self.addCleanup(target.close);return target

    @staticmethod
    def observation(target):
        value=runtime_fixture.observed(target.intent);value['schema']=policy.OBSERVATION_SCHEMA
        return value

    def test_old_exact_type_schema_and_profile_guards_are_not_widened(self):
        retained,source=self.source()
        with self.assertRaises(ValueError):policy.runtime.prepare(source.session,source)
        self.assertEqual(len(policy.publication.SOURCES),40);self.assertEqual(len(policy.EXTRA_SOURCES),4)
        self.assertEqual(policy.runtime.PROFILE_SHA256,'5402adcd0d010f4bc2e6b7c78d6f16ddbcbd3f3ad4ebab5f111e8c9fb17e034f')
        raw=policy.prepare(source.session,source,policy.measure_sources(source))
        with self.assertRaises(ValueError):policy.runtime.ProbeRuntimeBinding(source.session,raw,H(raw),source)

    def test_complete_readback_and_exact_retained_source_required(self):
        retained,source=self.source(False)
        with self.assertRaises(ValueError):self.target(source,source_pins={n:'a'*64 for n in policy.EXTRA_SOURCES},data=b'{}')
        self.assertIn('backend-attempt.json',source.session._records)
        self.assertNotIn('backend-intent.json',source.session._records)
        with self.assertRaises(ValueError):policy._source(source.session,object())

    def test_unbound_image_is_rejected_without_runtime_intent(self):
        retained,_,_,_=self.fixture.capability();source=retained.image(copy.deepcopy(image_fixture.BASE_VALUES))
        with self.assertRaises(ValueError):self.target(source,source_pins={n:'a'*64 for n in policy.EXTRA_SOURCES},data=b'{}')
        self.assertNotIn('backend-intent.json',source.session._records)

    def test_subclasses_are_not_a_way_to_enter_the_retained_profile(self):
        retained,source=self.source()
        class Foreign(policy.publication.RetainedProbeImageBinding):pass
        impostor=object.__new__(Foreign)
        with self.assertRaises(ValueError):policy._source(source.session,impostor)

    def test_source_records_descriptor_manifest_and_code_pins_match(self):
        retained,source=self.source();target=self.target(source);intent=target.intent
        report=retained.report()
        self.assertEqual(intent['publicationContinuationSha256'],report['bindingSha256'])
        self.assertEqual(intent['heldDescriptorsSha256'],report['heldDescriptorsSha256'])
        self.assertEqual(intent['imageBindingSha256'],H(source.session._records['image-binding.json'][1]))
        self.assertEqual(intent['publicationReadbackSha256'],H(source.session._records['publication-continuation-readback.json'][1]))
        self.assertEqual(intent['runtimeCodeSha256'],H(C(policy.measure_sources(source))))
        self.assertEqual(intent['expiresNs'],min(source.intent['expiresNs'],retained.expires))
        self.assertLess(intent['expiresNs'],source.intent['expiresNs'])

    def test_success_has_a_distinct_receipt_and_no_service_or_cleanup_lease(self):
        retained,source=self.source();target=self.target(source)
        result=target.bind(C(self.observation(target)),'b'*64)
        self.assertTrue(result['retainedPublicationSleepRuntimeBound']);self.assertEqual(result['additionalRuntimeSourcesHeld'],4)
        record=json.loads(source.session._records['backend-binding.json'][1])
        self.assertEqual(record['schema'],'fleetory.retained-probe-runtime-binding.v1')
        for key in policy.EXTRA_FIELDS:self.assertEqual(record[key],target.intent[key])
        for key in ('executionAuthorized','cleanupAuthorized','operationalLeaseAuthorized','backendCleanupAuthorized',
                'backendServiceStartedVerified','actualProbeNativeOwnerAcknowledged','liveServiceLeaseAuthorized',
                'controllerDeathCleanupVerified','fullSystemRecoveryVerified','phase7Complete'):self.assertIs(result[key],False)

    def test_foreign_controller_consumes_its_attempt_without_adopting_source(self):
        retained,source=self.source();other,_=self.source()
        raw=policy.prepare(source.session,source,policy.measure_sources(source))
        with self.assertRaises(ValueError):self.target(source,data=raw,session=other.session)
        self.assertIn('backend-attempt.json',other.session._records);self.assertNotIn('backend-intent.json',other.session._records)

    def test_bad_source_inventory_or_hash_consumes_attempt_and_cannot_retry(self):
        for kind in ('missing','hash','alias'):
            retained,source=self.source();pins=policy.measure_sources(source);raw=policy.prepare(source.session,source,pins)
            if kind=='missing':pins.pop(next(iter(pins)))
            elif kind=='hash':pins[next(iter(pins))]='f'*64
            else:pins[next(iter(pins))]=True
            with self.subTest(kind=kind),self.assertRaises(ValueError):self.target(source,data=raw,source_pins=pins)
            with self.assertRaises(ValueError):self.target(source)
            self.assertNotIn('backend-intent.json',source.session._records)

    def test_bad_wire_pin_consumes_backend_attempt(self):
        retained,source=self.source()
        with self.assertRaises(ValueError):self.target(source,pin='f'*64)
        with self.assertRaises(ValueError):self.target(source)
        self.assertNotIn('backend-intent.json',source.session._records)

    def test_pins_schema_deadline_extensions_and_unknown_fields_are_refused(self):
        changes=[('schema',policy.runtime.SCHEMA),('purpose',policy.runtime.PURPOSE),('publicationContinuationSha256','f'*64),
            ('publicationReadbackSha256','f'*64),('heldDescriptorsSha256','f'*64),('runtimeCodeSha256','f'*64),
            ('imageId','sha256:'+'f'*64),('runtimeProfileSha256','f'*64),('expiresNs',True),('root','/foreign')]
        for key,value in changes:
            retained,source=self.source();raw=policy.prepare(source.session,source,policy.measure_sources(source));intent=json.loads(raw);intent[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):self.target(source,data=C(intent))
            self.assertNotIn('backend-intent.json',source.session._records)
        retained,source=self.source();raw=policy.prepare(source.session,source,policy.measure_sources(source));intent=json.loads(raw);intent['expiresNs']+=60_000_000_000
        with self.assertRaises(ValueError):self.target(source,data=C(intent))

    def test_duplicate_oversize_and_old_observation_schema_refused(self):
        for suffix in (b',"image":"duplicate"}', b' ' * policy.container.MAX_INTENT):
            retained,source=self.source();raw=policy.prepare(source.session,source,policy.measure_sources(source))
            altered=raw[:-1]+suffix if suffix.startswith(b',') else raw+suffix
            with self.assertRaises(ValueError):self.target(source,data=altered)
        retained,source=self.source();target=self.target(source);value=self.observation(target);value['schema']=policy.runtime.OBSERVATION_SCHEMA
        with self.assertRaises(ValueError):target.bind(C(value),'b'*64)
        self.assertNotIn('backend-binding.json',source.session._records)

    def test_identity_sandbox_command_environment_and_limits_are_still_exact(self):
        changes=[('imageId','sha256:'+'f'*64),('configImage','mutable:tag'),('command',['-c','exec /bin/sleep 3300']),
            ('networkMode','host'),('readonly',False),('privileged',True),('capDrop',[]),('securityOpt',[]),
            ('memory',True),('nanoCpus',1.0),('pidsLimit',0),('mounts',[{}]),('portBindings',{'22/tcp':[]}),
            ('tmpfs',{}),('environment',[]),('ulimits',[dict(Name='core',Soft=False,Hard=0)]),('running',1),('unknown',True)]
        for key,value in changes:
            retained,source=self.source();target=self.target(source);incoming=self.observation(target);incoming[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):target.bind(C(incoming),'b'*64)
            with self.assertRaises(ValueError):target.bind(C(self.observation(target)),'b'*64)
            self.assertNotIn('backend-binding.json',source.session._records)

    def test_retained_close_invalidates_runtime_even_with_unexpired_image(self):
        retained,source=self.source();target=self.target(source);retained.close()
        with self.assertRaises(ValueError):target.report()

    def test_either_image_or_retained_deadline_invalidates_runtime(self):
        retained,source=self.source();target=self.target(source)
        source._deadline=time.monotonic()-1
        with self.assertRaises(ValueError):target.report()
        retained,source=self.source();target=self.target(source)
        with patch.object(policy.publication.time,'monotonic_ns',return_value=retained._monotonic+policy.publication.WINDOW_NS):
            with self.assertRaises(ValueError):target.report()

    def test_runtime_source_mutation_is_denied_or_detected(self):
        retained,source=self.source();target=self.target(source);path=self.fixture.repo/policy.EXTRA_SOURCES[0]
        try:path.write_bytes(b'changed public runtime code')
        except PermissionError:target.report()
        else:
            with self.assertRaises(ValueError):target.report()

    def test_source_pins_close_without_closing_publication(self):
        retained,source=self.source();target=self.target(source);fds=[pin.fd for pin in target._pins];target.close();target.close()
        for fd in fds:
            with self.assertRaises(OSError):os.fstat(fd)
        retained.check()
        with self.assertRaises(ValueError):target.report()

    def test_binding_flush_crossing_retained_expiry_returns_no_accepted_runtime(self):
        retained,source=self.source();target=self.target(source);write=source.session._write_once
        def expire(name,value):
            write(name,value)
            if name=='backend-binding.json':source._deadline=time.monotonic()-1
        with patch.object(source.session,'_write_once',side_effect=expire),self.assertRaises(ValueError):target.bind(C(self.observation(target)),'b'*64)
        self.assertIsNone(target._bound)


if __name__=='__main__':unittest.main()
