"""Actual original publication peer verifies one copy against its original held descriptors."""
import hashlib
import io
import json
import struct
import tarfile
import unittest

import sdk_publication_peer_tests as source


def copied_tar(change=None):
    files = source.fixture.policy.inspect(source.fixture.make(), hashlib.sha256(source.fixture.make()).hexdigest())
    result = io.BytesIO()
    with tarfile.open(fileobj=result, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for name, raw in files.items():
            if change == 'missing' and name == 'ServerBackendProbe.dll':continue
            if change == 'bytes' and name == 'ServerBackendProbe.dll':raw = b'X' * len(raw)
            entry = tarfile.TarInfo('tool/' + name);entry.size = len(raw);entry.mode = 0o644
            if change == 'mode':entry.mode = 0o777
            if change == 'symlink':entry.type = tarfile.SYMTYPE;entry.linkname = '/etc/passwd'
            archive.addfile(entry, io.BytesIO(raw))
    return result.getvalue()


class ReadbackTests(unittest.TestCase):
    setUp = source.PeerTests.setUp
    start = source.PeerTests.start
    stop = source.PeerTests.stop
    read = source.PeerTests.read
    send = source.PeerTests.send
    input = source.PeerTests.input
    frame = source.PeerTests.frame
    published = source.PeerTests.published
    context = source.PeerTests.context
    refused = source.PeerTests.refused

    def request(self, raw=None, digest=None):
        raw = copied_tar() if raw is None else raw
        self.send(b'B' + struct.pack('!I', len(raw)) + (hashlib.sha256(raw).digest() if digest is None else digest) + raw)
        return raw

    def test_original_descriptors_verify_copy_once_before_closed_release(self):
        manifest = self.published();self.context();raw = self.request()
        reply = self.frame(b'FLTSCHK1',4096)
        self.assertEqual(hashlib.sha256(raw).digest(),reply[:32]);self.assertEqual(hashlib.sha256(manifest).digest(),reply[32:64])
        value = json.loads(reply[64:]);self.assertTrue(value['verified']);self.assertEqual(4,value['files'])
        self.send(b'R');self.process.stdin.close();self.assertEqual(b'',self.frame(b'FLTSEND1',0))
        self.assertEqual(0,self.process.wait(timeout=5))

    def test_readback_before_context_is_refused(self):
        self.published();self.request();self.refused()

    def test_second_readback_is_refused(self):
        self.published();self.context();self.request();self.frame(b'FLTSCHK1',4096)
        self.send(b'B');self.refused()

    def test_copy_digest_mismatch_is_refused(self):
        self.published();self.context();self.request(digest=b'\0'*32);self.refused()

    def mutation_refused(self, mutation):
        self.published();self.context();self.request(copied_tar(mutation));self.refused()

    def test_changed_bytes_refused(self):self.mutation_refused('bytes')
    def test_missing_file_refused(self):self.mutation_refused('missing')
    def test_changed_mode_refused(self):self.mutation_refused('mode')
    def test_symlink_refused(self):self.mutation_refused('symlink')


if __name__=='__main__':unittest.main()
