"""Actual private-pipe peers with generated SDK bytes; no live PublicSdkOutputLease/SDK/native grant."""
from pathlib import Path
import concurrent.futures
import hashlib
import json
import os
import struct
import subprocess
import sys
import tempfile
import unittest
import uuid

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'eng/pilot'))
import audit_publication_namespace as ns
import public_build_output_tests as fixture
import audit_probe_image_tests as legacy

BOOTSTRAP='import pathlib,runpy,sys; p=sys.argv[1];sys.path.insert(0,str(pathlib.Path(p).parent.parent));sys.argv=sys.argv[1:];runpy.run_path(p,run_name="__main__")'


class PeerTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory(prefix='fleetory-sdk-peer-test-')
        self.addCleanup(self.temporary.cleanup)
        self.nonce=uuid.uuid4().hex
        self.root=Path(self.temporary.name).resolve()/('fleetory-sdk-publication-'+self.nonce)
        self.root.mkdir();(self.root/'controls').mkdir();(self.root/'repository').mkdir();(self.root/'repository/artifacts').mkdir()
        self.raw=fixture.make();self.digest=hashlib.sha256(self.raw).digest()
        self.plan=ns.bundle.prep.canonical(legacy.control_plan(str(uuid.UUID(hex=self.nonce))))
        self.process=None
        self.executor=concurrent.futures.ThreadPoolExecutor(max_workers=1)
        self.addCleanup(self.executor.shutdown)
        self.addCleanup(self.stop)

    def start(self,short=False):
        peer=ROOT/'eng/pilot/public_build/publication_peer.py'
        code=BOOTSTRAP
        if short:
            code='import pathlib,runpy,sys; p=sys.argv[1];sys.path.insert(0,str(pathlib.Path(p).parent.parent));v=runpy.run_path(p,run_name="generated_short_fixture");f=v["serve"];f.__globals__["LIFETIME"]=0.3;f(sys.argv[2],sys.argv[3])'
        self.process=subprocess.Popen([sys.executable,'-I','-S','-B','-c',code,str(peer),str(self.root),self.nonce],
            stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0)
        self.assertEqual(b'FLTSRD01'+self.nonce.encode(),self.read(40))

    def stop(self):
        if self.process is None:return
        if self.process.poll() is None:self.process.kill()
        self.process.wait(timeout=5)
        for stream in (self.process.stdin,self.process.stdout,self.process.stderr):
            if stream is not None:stream.close()

    def read(self,length):
        def exact():
            data=bytearray()
            while len(data)<length:
                part=self.process.stdout.read(length-len(data))
                if not part:raise EOFError('Generated SDK peer EOF')
                data.extend(part)
            return bytes(data)
        return self.executor.submit(exact).result(timeout=5)

    def send(self,data):
        self.process.stdin.write(data);self.process.stdin.flush()

    def input(self,raw=None):
        header=b'FLTSIN01'+self.nonce.encode()+struct.pack('!II',len(self.raw),len(self.plan))+self.digest+hashlib.sha256(self.plan).digest()
        self.send(header+(self.raw if raw is None else raw)+self.plan)

    def frame(self,magic,maximum):
        header=self.read(108)
        self.assertEqual(magic,header[:8]);self.assertEqual(self.nonce.encode(),header[8:40]);self.assertEqual(self.digest,header[40:72])
        length=struct.unpack('!I',header[72:76])[0];self.assertLessEqual(length,maximum)
        data=self.read(length) if length else b''
        self.assertEqual(hashlib.sha256(data).digest(),header[76:108])
        return data

    def published(self):
        self.start();self.input()
        manifest=self.frame(b'FLTSOUT1',98304)
        self.assertEqual(ns.bundle.manifest_from_files(fixture.policy.inspect(self.raw,self.digest.hex())),manifest)
        return manifest

    def context(self):
        recipe=b'FROM separately-approved-generated-fixture\n'
        request=hashlib.sha256(recipe).digest()
        self.send(b'C'+struct.pack('!I',len(recipe))+request+recipe)
        return self.frame(b'FLTSCTX1',16*1024*1024+64),request

    def refused(self):
        self.assertEqual(37,self.process.wait(timeout=5))
        error=self.process.stderr.read()
        self.assertNotIn(b'generated probe',error)
        self.assertNotIn(b'generated server',error)

    def test_one_actual_peer_context_then_closed_release(self):
        manifest=self.published();data,request=self.context()
        self.assertEqual(request,data[:32]);self.assertEqual(hashlib.sha256(manifest).digest(),data[32:64])
        self.assertTrue(data[64:])
        self.send(b'R');self.process.stdin.close()
        self.assertEqual(b'',self.frame(b'FLTSEND1',0))
        self.assertEqual(0,self.process.wait(timeout=5))
        self.assertEqual(b'',self.process.stdout.read());self.assertEqual(b'',self.process.stderr.read())

    def test_corruption_refuses_before_namespace_creation(self):
        self.start();changed=self.raw[:600]+b'X'+self.raw[601:];self.input(changed);self.refused()
        self.assertEqual([],list((self.root/'controls').iterdir()))
        self.assertEqual([],list((self.root/'repository/artifacts').iterdir()))

    def test_truncated_input_eof_refuses_before_namespace_creation(self):
        self.start()
        header=b'FLTSIN01'+self.nonce.encode()+struct.pack('!II',len(self.raw),len(self.plan))+self.digest+hashlib.sha256(self.plan).digest()
        self.send(header+self.raw[:100]);self.process.stdin.close();self.refused()
        self.assertEqual([],list((self.root/'repository/artifacts').iterdir()))

    def test_context_replay_is_not_a_second_context(self):
        self.published();self.context();self.send(b'C');self.refused()
        self.assertEqual(4,len(list((self.root/'repository/artifacts'/ns.name(str(uuid.UUID(hex=self.nonce)))/'publish').iterdir())))

    def test_eof_after_publication_does_not_return_close_ack(self):
        self.published();self.process.stdin.close();self.refused()
        self.assertEqual(b'',self.process.stdout.read())

    def test_wrong_recipe_digest_refuses_context(self):
        self.published();recipe=b'FROM generated-fixture\n'
        self.send(b'C'+struct.pack('!I',len(recipe))+b'\0'*32+recipe);self.refused()

    def test_release_rejects_trailing_commands(self):
        self.published();self.send(b'RC');self.process.stdin.close();self.refused()
        self.assertEqual(b'',self.process.stdout.read())

    def test_deadline_does_not_wait_for_parent(self):
        self.start(short=True)
        self.assertNotEqual(0,self.process.wait(timeout=5))
        self.assertEqual([],list((self.root/'repository/artifacts').iterdir()))


if __name__=='__main__':unittest.main()
