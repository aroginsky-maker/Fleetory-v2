from pathlib import Path
import copy
import hashlib
import json
import os
import queue
import subprocess
import sys
import threading
import unittest

repo=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(repo/'eng/pilot'))
sys.path.insert(0,str(Path(__file__).parent))
from public_build import intake
import public_build_intake_tests as input_models
from public_build import peer


class PeerTests(unittest.TestCase):
    def setUp(self):
        self.fixture=input_models.IntakeTests();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.root=Path(self.fixture.temp.name)
        body={'sources':self.fixture.sp,'packages':self.fixture.pp,'crls':copy.deepcopy(self.fixture.cp)}
        for pin in body['crls'].values():
            for key in ('thisUpdate','nextUpdate'):pin[key]=pin[key].isoformat()
        (self.root/'peer-fixture.json').write_text(json.dumps(body),encoding='utf-8')
        self.expected=self.fixture.capture().take()

    def start(self,mode='normal'):
        process=subprocess.Popen([sys.executable,'-I','-S','-B',str(Path(__file__).with_name('PublicBuildSourceFixture.py')),str(self.root),mode],
            stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        self.addCleanup(self.close,process)
        return process

    @staticmethod
    def close(process):
        if process.poll() is None:process.kill()
        process.communicate(timeout=5)

    def check(self,raw):
        self.assertGreaterEqual(len(raw),peer.HEADER.size)
        magic,length,digest,nonce=peer.HEADER.unpack(raw[:peer.HEADER.size])
        self.assertEqual(peer.MAGIC,magic);self.assertEqual(len(self.expected),length)
        self.assertEqual(hashlib.sha256(self.expected).digest(),digest);self.assertNotEqual(b'\0'*16,nonce)
        end=peer.HEADER.size+length
        self.assertEqual(self.expected,raw[peer.HEADER.size:end])
        return raw[end:]

    def test_actual_child_transfers_exact_frame_and_closes_without_sdk_permit(self):
        p=self.start();raw,error=p.communicate(input=b'',timeout=10)
        self.assertEqual(0,p.returncode);self.assertEqual(b'',error);self.assertEqual(b'',self.check(raw))

    def test_one_request_emits_one_permit_from_live_capsule(self):
        p=self.start();raw,error=p.communicate(input=peer.REQUEST,timeout=10)
        self.assertEqual(0,p.returncode);self.assertEqual(b'',error);self.assertEqual(peer.PERMIT,self.check(raw))

    def test_unknown_or_replayed_control_is_refused(self):
        for message in (b'X',b'SS',b'SX'):
            with self.subTest(message=repr(message)):
                p=self.start();raw,error=p.communicate(input=message,timeout=10)
                self.assertEqual(37,p.returncode)
                self.assertIn(self.check(raw),(b'',peer.PERMIT))
                self.assertEqual(b'Public input fixture refused; no contents logged.\n',error)

    def test_shortened_fixture_original_expiry_exits_with_parent_pipe_still_open(self):
        p=self.start('expiry')
        received=queue.Queue(maxsize=1)
        def drain():
            try:
                header=p.stdout.read(peer.HEADER.size)
                if len(header)!=peer.HEADER.size:raise ValueError('Short test header')
                length=peer.HEADER.unpack(header)[1]
                if not 0<length<131072:raise ValueError('Test body bound')
                body=p.stdout.read(length)
                if len(body)!=length:raise ValueError('Short test body')
                received.put((header,body))
            except Exception as error:received.put(error)
        reader=threading.Thread(target=drain,daemon=True);reader.start()
        try:result=received.get(timeout=5)
        except queue.Empty:
            p.kill();p.wait(timeout=5);reader.join(2)
            self.fail('Bounded fixture frame read timed out')
        reader.join(2);self.assertFalse(reader.is_alive())
        if isinstance(result,Exception):raise result
        header,body=result
        self.assertEqual(b'',self.check(header+body))
        self.assertEqual(37,p.wait(timeout=5));self.assertFalse(p.stdin.closed)
        self.assertEqual(b'',p.stdout.read())

    def test_broken_output_consumes_capture_before_any_control_read(self):
        value=self.fixture.capture();read,write=os.pipe();commands,command_write=os.pipe()
        os.close(read)
        try:
            with self.assertRaises(OSError):peer.serve_capture(value,commands,write)
            self.assertTrue(value.report()['taken'])
            with self.assertRaises(ValueError):value.take()
        finally:
            for descriptor in (write,commands,command_write):os.close(descriptor)


if __name__=='__main__':unittest.main()
