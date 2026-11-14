"""Native create admission, immutable offers, old-mode separation and one-use receipt contracts."""
import base64
from contextlib import contextmanager
import io
import json
from pathlib import Path
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import audit_native_probe_tests as fixture
import audit_native_probe_create as policy

packet, runtime = policy.packet, policy.runtime


@contextmanager
def unbound_pair(session, root):
    public = root/'public';fixture.model.fixtures.public_files(public)
    manifest = runtime.container.canonical(fixture.model.fixtures.measure(public))
    with runtime.probe.bundle.HeldProbeBundle(public, manifest, packet.digest(manifest)) as held:
        source = fixture.model.ProbeRuntimeTests.source(None, session, held)
        raw = runtime.prepare(session, source)
        yield source, runtime.ProbeRuntimeBinding(session, raw, packet.digest(raw), source)


class NativeCreateTests(unittest.TestCase):
    setUp = fixture.ProbeNativeTests.setUp
    session = fixture.ProbeNativeTests.session

    def vector(self, session, pair):
        value = policy._NativeCreatePumps.make_header(self.native, session.report(), session,
            {n:'e'*64 for n in policy.SOURCES}, 'c'*64, docker_sha256='d'*64,
            runtime_intent_sha256=packet.digest(pair[1]._intent_bytes))
        raw = policy.prep.canonical(value)
        return raw, policy.header(raw, self.native_pin)

    def test_source_profile46_and_old_profiles_stay_closed(self):
        self.assertEqual((len(policy.SOURCES),len(policy.base.SOURCES),len(policy.base.base.SOURCES),len(policy.payload.SOURCES),len(policy.prep.SOURCES)),(46,45,40,34,32))
        self.assertEqual(len(set(policy.SOURCES)),46)
        self.assertEqual(policy._NativeCreatePumps.max_frames,5)
        self.assertEqual(policy.base._NativeProbePumps.max_frames,4)
        self.assertEqual(policy.prep.MAX_FRAME,2048)

    def test_header_pins_docker_and_frozen_intent_without_changing_ready_fields(self):
        with self.session() as session, unbound_pair(session,self.root) as pair:
            raw,info=self.vector(session,pair)
            self.assertEqual(set(info),set(self.info))
            self.assertEqual(info['headerSha256'],packet.digest(raw))
            self.assertEqual(policy.reservation(raw,self.native_pin)['nonce'],session._plan['nonce'])
            for decode in (policy.payload.header,policy.prep.header):
                with self.assertRaises(ValueError):decode(raw,self.native_pin)
            for key,item in (('dockerSha256',True),('runtimeIntentSha256','F'*64),('schema',policy.payload.SCHEMA),('endpoint','tcp://host')):
                value=json.loads(raw);value[key]=item
                with self.subTest(key=key),self.assertRaises(ValueError):policy.header(policy.prep.canonical(value),self.native_pin)

    def test_runtime_offer_exact_bytes_pin_and_all_authority_fields_closed(self):
        with self.session() as session, unbound_pair(session,self.root) as pair:
            _,info=self.vector(session,pair);raw=pair[1]._intent_bytes
            self.assertEqual(policy.runtime_intent(raw,packet.digest(raw),info),pair[1].intent)
            for key,item in (('schema',policy.base.base.RECEIPT_SCHEMA),('nonce','00000000-0000-0000-0000-000000000000'),
                    ('image','latest'),('name','foreign'),('runtimeProfileSha256','f'*64),('sourceCodeSha256','f'*64),
                    ('expiresNs',True),('expiresNs',time.time_ns()-1),('openedNs',True),('command',['/bin/sh']),('root','/host')):
                value=json.loads(raw);value[key]=item;changed=policy.prep.canonical(value)
                with self.subTest(key=key),self.assertRaises(ValueError):policy.runtime_intent(changed,packet.digest(changed),info)
            value=json.loads(raw);value['labels']['fleetory.audit.control.reservation']='f'*64;changed=policy.prep.canonical(value)
            with self.assertRaises(ValueError):policy.runtime_intent(changed,packet.digest(changed),info)
            with self.assertRaises(ValueError):policy.runtime_intent(raw+b' ',packet.digest(raw),info)

    def action(self, raw, info, intent):
        frame=policy.create_offer(info,'a'*64,self.ready,intent)
        return dict(schema='fleetory.native-empty-payload-action.v1',headerBase64=base64.b64encode(raw).decode(),
            frameBase64=base64.b64encode(policy.prep.canonical(frame)).decode(),**self.ready)

    def test_tampered_create_offer_refused_before_namespace_or_docker(self):
        with self.session() as session, unbound_pair(session,self.root) as pair:
            raw,info=self.vector(session,pair);value=self.action(raw,info,pair[1]._intent_bytes)
            frame=json.loads(base64.b64decode(value['frameBase64']))
            for key,item in (('decision','build'),('readySha256','f'*64),('ownerSha256','f'*64),('schema',policy.base.OFFER_SCHEMA),
                    ('runtimeIntentBase64',base64.b64encode(pair[1]._intent_bytes+b' ').decode()),('arguments',['rm','-f','foreign'])):
                changed={**frame,key:item};wrapped={**value,'frameBase64':base64.b64encode(policy.prep.canonical(changed)).decode()}
                with self.subTest(key=key),patch.object(policy.os,'getppid',return_value=123),patch.object(policy.payload,'_RecordedEmpty') as opened,patch.object(policy,'_Docker') as docker:
                    with self.assertRaises(ValueError):policy.native_create(policy.prep.canonical(wrapped),self.native_pin,'a'*64,123)
                    opened.assert_not_called();docker.assert_not_called()

    def test_wrong_native_parent_refused_before_docker(self):
        with patch.object(policy.os,'getppid',return_value=999),patch.object(policy,'_Docker') as docker:
            with self.assertRaises(ValueError):policy.native_create(b'{}',self.native_pin,'a'*64,123)
            docker.assert_not_called()

    def test_precreated_foreign_reversed_and_fake_pairs_refused(self):
        with self.session() as session, unbound_pair(session,self.root) as pair:
            self.assertEqual(policy._unbound_pair(session,pair),pair[1]._intent_bytes)
            for other in (list(pair),tuple(reversed(pair)),(object(),object())):
                with self.assertRaises(ValueError):policy._unbound_pair(session,other)
            pair[1].bind(runtime.container.canonical(fixture.model.observed(pair[1].intent)),'b'*64)
            with self.assertRaises(ValueError):policy._unbound_pair(session,pair)

    def test_fixed_docker_args_use_no_wire_command_mount_endpoint_or_port(self):
        with self.session() as session, unbound_pair(session,self.root) as pair:
            args=policy._arguments(pair[1].intent)
            for flag in ('--pull=never','--network=none','--read-only','--user=3322:3322','--cap-drop=ALL','--security-opt=no-new-privileges:true','--ulimit=core=0:0'):
                self.assertIn(flag,args)
            self.assertEqual(args[-3:],[pair[1].intent['imageId'],*runtime.COMMAND])
            self.assertEqual(args.count('--tmpfs'),2)
            self.assertFalse(any(v in args for v in ('--mount','-v','-p','--privileged','--env-file','build','login','pull')))

    def pump(self,session,pair):
        raw,_=self.vector(session,pair)
        child=SimpleNamespace(pid=12345,stdin=io.BytesIO())
        command=SimpleNamespace(linked_pair=pair,docker=SimpleNamespace(digest='d'*64),check=lambda:None,executable=None)
        result=policy._NativeCreatePumps(child,raw+b'\n',command,session,SimpleNamespace(identity=lambda *_:dict(pid=12345,actualImageMatched=True)),time.monotonic_ns(),30)
        result.bound=SimpleNamespace(check=lambda:None,close=lambda:None)
        result.frames=[{},self.ready];result.ready_pin='a'*64;result.create_pin='b'*64
        return result

    def test_creation_reply_is_observed_and_bound_before_ack_and_cannot_repeat(self):
        with self.session() as session, unbound_pair(session,self.root) as pair:
            pumps=self.pump(session,pair);identifier='b'*64
            value=policy.created(pumps.info,pumps.ready_pin,self.ready,packet.digest(pair[1]._intent_bytes),identifier,12345)
            observed=runtime.container.canonical(fixture.model.observed(pair[1].intent))
            with patch.object(policy,'_Docker') as client:
                client.return_value.observe.return_value=observed
                pumps._accept_frame(value,policy.prep.canonical(value))
                self.assertTrue(pumps.created_event.is_set())
                self.assertEqual(pumps.receipt['containerId'],identifier)
                client.return_value.observe.assert_called_once_with(identifier)
                self.assertIn('native-probe-create-binding.json',session._records)
                with self.assertRaises(ValueError):pumps._accept_frame(value,policy.prep.canonical(value))
                self.assertEqual(client.return_value.observe.call_count,1)

    def test_forged_or_premature_creation_reply_never_observed(self):
        with self.session() as session, unbound_pair(session,self.root) as pair:
            pumps=self.pump(session,pair)
            value=policy.created(pumps.info,pumps.ready_pin,self.ready,packet.digest(pair[1]._intent_bytes),'b'*64,12345)
            for key,item in (('pid',True),('pid',12346),('containerId','B'*64),('runtimeIntentSha256','f'*64),('backendServiceStarted',True)):
                with self.subTest(key=key),patch.object(policy,'_Docker') as client:
                    changed={**value,key:item}
                    with self.assertRaises(ValueError):pumps._accept_frame(changed,policy.prep.canonical(changed))
                    client.assert_not_called()
            pumps.create_pin=None
            with self.assertRaises(ValueError):pumps._accept_frame(value,policy.prep.canonical(value))

    def test_failed_creation_observation_consumes_binding_and_cannot_be_adopted(self):
        with self.session() as session, unbound_pair(session,self.root) as pair:
            pumps=self.pump(session,pair)
            value=policy.created(pumps.info,pumps.ready_pin,self.ready,packet.digest(pair[1]._intent_bytes),'b'*64,12345)
            observed=fixture.model.observed(pair[1].intent);observed['privileged']=True
            with patch.object(policy,'_Docker') as client:
                client.return_value.observe.return_value=runtime.container.canonical(observed)
                with self.assertRaises(ValueError):pumps._accept_frame(value,policy.prep.canonical(value))
            self.assertTrue(pair[1]._attempted)
            self.assertNotIn('native-probe-create-binding.json',session._records)
            with self.assertRaises(ValueError):policy._unbound_pair(session,pair)

    def test_local_cli_context_and_engine_are_closed_before_create(self):
        path=self.root/('docker.exe' if policy.os.name=='nt' else 'docker')
        path.write_bytes(b'public CLI pin fixture');path.chmod(0o700)
        good='npipe:////./pipe/dockerDesktopLinuxEngine' if policy.os.name=='nt' else 'unix:///var/run/docker.sock'
        with policy.process.PinnedFile(path,packet.digest(path.read_bytes()),True) as pinned:
            with patch.object(policy._Docker,'_call',side_effect=[good.encode(),b'linux:29.8.0']) as calls:
                policy._Docker(pinned);self.assertEqual(calls.call_count,2)
            for endpoint in ('tcp://127.0.0.1:2375','ssh://host','unix:///other.sock','npipe:////remote/pipe/docker'):
                with self.subTest(endpoint=endpoint),patch.object(policy._Docker,'_call',return_value=endpoint.encode()) as calls:
                    with self.assertRaises(ValueError):policy._Docker(pinned)
                    self.assertEqual(calls.call_count,1)
            for version in ('linux:27.0.0','windows:29.8.0','linux:next'):
                with self.subTest(version=version),patch.object(policy._Docker,'_call',side_effect=[good.encode(),version.encode()]):
                    with self.assertRaises(ValueError):policy._Docker(pinned)

    def test_docker_create_requires_absent_exact_name_and_full_id(self):
        with self.session() as session,unbound_pair(session,self.root) as pair:
            client=object.__new__(policy._Docker)
            with patch.object(client,'_call',return_value=b'foreign\n') as calls:
                with self.assertRaises(ValueError):client.create(pair[1].intent)
                self.assertEqual(calls.call_count,1)
            for reply in (b'abcd',b'B'*64,b'b'*64+b'\nextra'):
                with self.subTest(reply=reply),patch.object(client,'_call',side_effect=[b'',reply]) as calls:
                    with self.assertRaises(ValueError):client.create(pair[1].intent)
                    self.assertEqual(calls.call_count,2)
            with patch.object(client,'_call',side_effect=[b'',b'b'*64+b'\n']) as calls:
                self.assertEqual(client.create(pair[1].intent),'b'*64)
                self.assertEqual(calls.call_args.args[0],policy._arguments(pair[1].intent))

    def test_name_lookup_expiring_admission_never_dispatches_create(self):
        with self.session() as session,unbound_pair(session,self.root) as pair:
            client=object.__new__(policy._Docker)
            for now in (pair[1].intent['expiresNs'],pair[1].intent['expiresNs']+1,
                    pair[1].intent['expiresNs']-runtime.container.WINDOW_NS-1):
                with self.subTest(now=now),patch.object(client,'_call',return_value=b'') as calls,patch.object(policy.time,'time_ns',return_value=now):
                    with self.assertRaises(ValueError):client.create(pair[1].intent)
                    self.assertEqual(calls.call_count,1)
                    self.assertEqual(calls.call_args.args[0][0:2],['container','ls'])


if __name__=='__main__':unittest.main()
