"""Probe-specific native receipt pins, old-mode refusal and consumed owner protocol contracts."""
import ast
import base64
from contextlib import contextmanager
import io
import json
from pathlib import Path
import tempfile
import time
import unittest
import uuid
from types import SimpleNamespace
from unittest.mock import patch

import audit_probe_runtime_tests as model
import audit_native_resource_tests as old
import audit_native_probe_runtime as policy

packet, runtime = policy.packet, policy.runtime
REPO = Path(__file__).resolve().parents[2]
PROBE_BYTES = b'generated public ServerBackendProbe.dll'


@contextmanager
def generated_pair(session, root):
    public = root / ('public-' + uuid.uuid4().hex)
    model.fixtures.public_files(public)
    manifest = runtime.container.canonical(model.fixtures.measure(public))
    with runtime.probe.bundle.HeldProbeBundle(public, manifest, packet.digest(manifest)) as held:
        source = model.ProbeRuntimeTests.source(None, session, held)
        raw = runtime.prepare(session, source)
        target = runtime.ProbeRuntimeBinding(session, raw, packet.digest(raw), source)
        target.bind(runtime.container.canonical(model.observed(target.intent)), 'b' * 64)
        yield source, target


class ProbeNativeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='fleetory-probe-native-contract-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.header, original = old.vector_payload()
        self.plan = json.loads(original)
        self.plan['probeSha256'] = packet.digest(PROBE_BYTES)
        self.native = policy.prep.canonical(self.plan)
        self.native_pin = packet.digest(self.native)
        self.header['planBase64'] = base64.b64encode(self.native).decode('ascii')
        self.raw = policy.prep.canonical(self.header)
        self.info = policy.payload.header(self.raw, self.native_pin)
        self.ready = dict(ownerSha256='a' * 64, payloadDirectorySha256='b' * 64, intentSha256='c' * 64)

    def session(self):
        value = model.fixtures.control_plan(self.info['nonce'])
        value.update(nativePlanSha256=self.native_pin, probeSha256=self.plan['probeSha256'],
            revision=self.plan['revision'], codeSha256=self.plan['codeSha256'])
        directory = self.root / uuid.uuid4().hex;directory.mkdir(mode=0o700)
        raw = policy.prep.canonical(value)
        return policy.payload.control.claim(directory, raw, packet.digest(raw))

    def pump(self, session, pair):
        child = SimpleNamespace(pid=12345, stdin=io.BytesIO())
        command = SimpleNamespace(linked_pair=pair, check=lambda: None, executable=None)
        data = policy._NativeProbePumps.make_header(self.native, session.report(), session,
            {n:'e' * 64 for n in policy.SOURCES}, 'c' * 64)
        result = policy._NativeProbePumps(child, policy.prep.canonical(data) + b'\n', command, session,
            SimpleNamespace(identity=lambda *_:dict(pid=12345, actualImageMatched=True)), time.monotonic_ns(), 30)
        result.bound = SimpleNamespace(check=lambda:None, close=lambda:None)
        result.frames = [{},self.ready];result.ready_pin = 'd' * 64
        return result

    def test_complete_probe_bundle_source_profile_and_both_receipts_are_pinned(self):
        with self.session() as session, generated_pair(session,self.root) as pair:
            value = policy.pair_receipt(session,pair)
            self.assertEqual(value['schema'],policy.RECEIPT_SCHEMA)
            for key in ('bundleManifestSha256','sourceCodeSha256','runtimeProfileSha256'):
                self.assertEqual(value[key],pair[1].intent[key])
            for key,name in (('imageBindingSha256','image-binding.json'),('containerBindingSha256','backend-binding.json')):
                self.assertEqual(value[key],packet.digest(session._records[name][1]))
            self.assertEqual(value['expiresNs'],pair[0].intent['expiresNs'])

    def test_foreign_control_reversal_fake_and_old_python_pairs_are_refused(self):
        with self.session() as session, self.session() as foreign, generated_pair(session,self.root) as pair:
            for candidate in (list(pair),tuple(reversed(pair)),(object(),object()),old.generated_pair(foreign)):
                with self.subTest(kind=type(candidate)),self.assertRaises(ValueError):policy.pair_receipt(session,candidate)
            with self.assertRaises(ValueError):policy.pair_receipt(foreign,pair)
            with self.assertRaises(ValueError):policy.base.pair_receipt(session,pair)
            value = policy.pair_receipt(session,pair)
            with self.assertRaises(ValueError):policy.base.receipt(value,value['nonce'],value['controlSha256'])

    def test_wire_fields_hash_types_profile_expiry_and_unknown_fields_are_closed(self):
        with self.session() as session, generated_pair(session,self.root) as pair:
            value = policy.pair_receipt(session,pair)
            changes = [('schema',policy.base.RECEIPT_SCHEMA),('nonce',str(uuid.uuid4())),('controlSha256','f'*64),
                ('imageId',True),('containerId','F'*64),('runtimeProfileSha256','f'*64),
                ('bundleManifestSha256',False),('sourceCodeSha256','F'*64),('expiresNs',True),
                ('expiresNs',time.time_ns()-1),('expiresNs',time.time_ns()+120_000_000_000),('archiveBase64','refused')]
            for key,item in changes:
                with self.subTest(key=key),self.assertRaises(ValueError):policy.receipt({**value,key:item},value['nonce'],value['controlSha256'])

    def test_offer_matches_header_code_and_stays_under_fixed_frame_limit(self):
        with self.session() as session, generated_pair(session,self.root) as pair:
            value = policy.pair_receipt(session,pair)
            info = self.pump(session,pair).info
            offered = policy.offer(info,'a'*64,self.ready,value,'b'*64)
            self.assertEqual(offered['schema'],policy.OFFER_SCHEMA)
            self.assertLessEqual(len(policy.prep.canonical(offered)),policy.prep.MAX_FRAME)
            with self.assertRaises(ValueError):policy.offer({**info,'codeSha256':'f'*64},'a'*64,self.ready,value,'b'*64)
            with self.assertRaises(ValueError):policy.base.offer(info,'a'*64,self.ready,value,'b'*64)

    def test_runtime_source_intent_and_profile_drift_cannot_be_projected(self):
        with self.session() as session, generated_pair(session,self.root) as pair:
            pair[1].intent['runtimeProfileSha256'] = 'f'*64
            with self.assertRaises(ValueError):policy.pair_receipt(session,pair)
        with self.session() as session, generated_pair(session,self.root) as pair:
            pair[0]._deadline = time.monotonic()-1
            with self.assertRaises(ValueError):policy.pair_receipt(session,pair)

    def test_native_helper_rejects_wrong_parent_oversize_duplicate_and_old_schema(self):
        with patch.object(packet,'strict_json',wraps=packet.strict_json) as parsed:
            with self.assertRaises(ValueError):policy.native_acknowledge(b'{}',self.native_pin,'a'*64,0)
            parsed.assert_not_called()
        with patch.object(policy.payload.os,'getppid',return_value=123):
            for data in (b'{}',b'{'*(policy.payload.MAX_ACTION+1),b'{"schema":1,"schema":2}'):
                with self.subTest(size=len(data)),self.assertRaises(ValueError):policy.native_acknowledge(data,self.native_pin,'a'*64,123)
            action = policy.prep.canonical(dict(schema=policy.base.ACTION_SCHEMA,headerBase64='',frameBase64='',
                ownerSha256='a'*64,payloadDirectorySha256='b'*64,intentSha256='c'*64))
            with self.assertRaises(ValueError):policy.native_acknowledge(action,self.native_pin,'a'*64,123)

    def test_static_factory_profile_and_pair_slot_reject_other_transports(self):
        fake = SimpleNamespace(check=lambda:None)
        for profile,factory,pair in (('native-probe-runtime-ack',policy.base._NativeResourcePumps,(None,None)),
                ('native-resource-ack',policy._NativeProbePumps,(None,None)),('generated-worker',None,(None,None)),
                ('native-probe-runtime-ack',policy._NativeProbePumps,None)):
            value = policy.process._Command(fake,(),(),Path('.'),{},profile,factory,pair)
            with self.subTest(profile=profile),self.assertRaises(ValueError):value.check()

    def test_closed_inventory_covers_imports_and_json_without_expanding_old_profiles(self):
        self.assertEqual((len(policy.SOURCES),len(policy.base.SOURCES),len(policy.payload.SOURCES),len(policy.prep.SOURCES)),(45,40,34,32))
        self.assertIn('eng/pilot/probe-runtime-profile.json',policy.SOURCES)
        names = {Path(p).stem for p in policy.SOURCES if p.endswith('.py')}
        for name in names:
            for node in ast.walk(ast.parse((REPO/'eng/pilot'/(name+'.py')).read_text())):
                imports = [n.name for n in node.names] if isinstance(node,ast.Import) else ([node.module] if isinstance(node,ast.ImportFrom) and node.module else [])
                for item in imports:
                    if (REPO/'eng/pilot'/(item+'.py')).is_file():self.assertIn(item,names)

    def test_valid_ack_pins_live_owner_and_shared_intent_without_operational_authority(self):
        with self.session() as session, generated_pair(session,self.root) as pair:
            pump = self.pump(session,pair);session._write_once('payload-binding.json',{'generated':True})
            sent=[]
            with patch.object(pump,'_send_frame',side_effect=sent.append),patch.object(pump,'_wait'):
                pump._after_payload_bound()
            value=policy.acknowledgement(pump.info,pump.ready_pin,self.ready,pump.receipt,pump.resource_intent_pin,12345)
            pump._accept_frame(value,policy.prep.canonical(value))
            self.assertTrue(pump.resource_ack.is_set())
            self.assertEqual(sent[0]['schema'],policy.OFFER_SCHEMA)
            bound=json.loads(session._records['native-resource-ack.json'][1])
            self.assertEqual(bound['schema'],policy._NativeProbePumps._bound_schema)
            self.assertEqual(bound['actualOwnedProcess']['pid'],12345)
            self.assertFalse(bound['backendControlAuthorized']);self.assertFalse(bound['privateInputReleaseAuthorized'])
            with self.assertRaises(ValueError):pump._accept_frame(value,policy.prep.canonical(value))

    def test_bad_ack_fields_never_publish_acceptance(self):
        for key,item in (('schema',policy.base.ACK_SCHEMA),('pid',True),('pid',54321),('containerId','f'*64),
                ('receiptSha256','f'*64),('privateInputsAccepted',True),('backendControlAuthorized',True),('archiveBase64','refused')):
            with self.subTest(key=key),self.session() as session,generated_pair(session,self.root) as pair:
                pump=self.pump(session,pair);pump.resource_intent_pin='e'*64
                value=policy.acknowledgement(pump.info,pump.ready_pin,self.ready,pump.receipt,pump.resource_intent_pin,12345)
                value[key]=item
                with self.assertRaises(ValueError):pump._accept_frame(value,policy.prep.canonical(value))
                self.assertNotIn('native-resource-ack.json',session._records)

    def test_expiry_during_intent_flush_sends_no_offer(self):
        with self.session() as session,generated_pair(session,self.root) as pair:
            pump=self.pump(session,pair);session._write_once('payload-binding.json',{'generated':True})
            original=session._write_once
            def expire(name,value):
                original(name,value)
                if name=='native-resource-intent.json':pair[0]._deadline=time.monotonic()-1
            with patch.object(session,'_write_once',side_effect=expire),patch.object(pump,'_send_frame') as send:
                with self.assertRaises(ValueError):pump._after_payload_bound()
                send.assert_not_called()

    def test_expiry_during_ack_flush_preserves_record_without_acceptance(self):
        with self.session() as session,generated_pair(session,self.root) as pair:
            pump=self.pump(session,pair);pump.resource_intent_pin='e'*64
            value=policy.acknowledgement(pump.info,pump.ready_pin,self.ready,pump.receipt,pump.resource_intent_pin,12345)
            original=session._write_once
            def expire(name,item):
                original(name,item)
                if name=='native-resource-ack.json':pair[0]._deadline=time.monotonic()-1
            with patch.object(session,'_write_once',side_effect=expire):
                with self.assertRaises(ValueError):pump._accept_frame(value,policy.prep.canonical(value))
            self.assertIn('native-resource-ack.json',session._records)
            self.assertFalse(pump.resource_ack.is_set());self.assertIsNone(pump.ack_pin)

    def test_existing_foreign_ack_record_is_preserved(self):
        with self.session() as session,generated_pair(session,self.root) as pair:
            pump=self.pump(session,pair);pump.resource_intent_pin='e'*64
            session._write_once('native-resource-ack.json',{'foreign':True});before=session._records['native-resource-ack.json'][1]
            value=policy.acknowledgement(pump.info,pump.ready_pin,self.ready,pump.receipt,pump.resource_intent_pin,12345)
            with self.assertRaises(ValueError):pump._accept_frame(value,policy.prep.canonical(value))
            self.assertEqual(session._records['native-resource-ack.json'][1],before)


if __name__=='__main__':unittest.main()
