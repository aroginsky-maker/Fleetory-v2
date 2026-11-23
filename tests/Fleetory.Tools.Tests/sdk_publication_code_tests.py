"""Real isolated publication children executing frozen public-source bytes only."""
import base64
import hashlib
import importlib.util
import json
import os
import re
from pathlib import Path
import subprocess
import sys
import unittest

import sdk_publication_peer_tests as peer

ROOT = Path(__file__).resolve().parents[2]
PILOT = ROOT / 'eng/pilot'
path = PILOT / 'public_build/publication_bootstrap.py'
spec = importlib.util.spec_from_file_location('publication_frame_policy', path)
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)


def code_frame():
    modules = {}
    for path in sorted(PILOT.rglob('*.py')):
        if '__pycache__' in path.parts or path.name in ('__init__.py', 'publication_bootstrap.py'):
            continue
        raw = path.read_bytes()
        name = '.'.join(path.relative_to(PILOT).with_suffix('').parts)
        if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*', name):
            continue
        modules[name] = dict(source=base64.b64encode(raw).decode(), sha256=hashlib.sha256(raw).hexdigest())
    raw = json.dumps(dict(schema='fleetory.publication-code-frame.v1', modules=modules), separators=(',', ':')).encode()
    return raw, hashlib.sha256(raw).hexdigest()


class FrozenCodePeerTests(peer.PeerTests):
    def start(self, short=False):
        self.assertFalse(short)
        raw, digest = code_frame()
        self.process = subprocess.Popen([sys.executable, '-I', '-S', '-B', '-c', path.read_text(), digest, str(self.root), self.nonce],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0,
            cwd=self.temporary.name, env=dict(os.environ, PYTHONPATH=self.temporary.name))
        self.send(len(raw).to_bytes(4, 'big') + raw)
        self.assertEqual(b'FLTSRD01' + self.nonce.encode(), self.read(40))

    def test_deadline_does_not_wait_for_parent(self):
        # Hold stdin open without even sending the code-frame header.
        _, digest = code_frame()
        self.process = subprocess.Popen([sys.executable, '-I', '-S', '-B', '-c', path.read_text(), digest, str(self.root), self.nonce],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
        self.assertEqual(37, self.process.wait(timeout=65))
        self.assertEqual([], list((self.root/'repository/artifacts').iterdir()))
        self.assertEqual(b'', self.process.stdout.read())

    def test_corrupt_code_frame_refuses_before_ready_or_sdk_input(self):
        raw, digest = code_frame()
        self.process = subprocess.Popen([sys.executable, '-I', '-S', '-B', '-c', path.read_text(), digest, str(self.root), self.nonce],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
        self.send(len(raw).to_bytes(4, 'big') + raw[:-1] + b'X')
        self.assertEqual(37, self.process.wait(timeout=5))
        self.assertEqual(b'', self.process.stdout.read())
        self.assertEqual([], list((self.root/'repository/artifacts').iterdir()))

    def test_filesystem_project_module_shadow_is_not_executed(self):
        # Keep the closed publication root clean; put the shadow in cwd/PYTHONPATH.
        (Path(self.temporary.name)/'audit_publication_namespace.py').write_text('raise SystemExit(99)')
        self.test_one_actual_peer_context_then_closed_release()


class CodeFramePolicyTests(unittest.TestCase):
    def test_frozen_sources_require_trusted_frame_pin_and_per_module_pin(self):
        raw, digest = code_frame()
        admitted = policy.admitted_modules(raw, digest)
        self.assertIn('public_build.publication_peer', admitted)
        with self.assertRaises(TypeError):admitted['replacement'] = b'x'
        with self.assertRaises(ValueError):policy.admitted_modules(raw, '0' * 64)
        changed = json.loads(raw)
        changed['modules']['public_build.publication_peer']['source'] = base64.b64encode(b'raise SystemExit(99)').decode()
        modified = json.dumps(changed).encode()
        with self.assertRaises(ValueError):policy.admitted_modules(modified, hashlib.sha256(modified).hexdigest())

    def test_duplicate_or_unknown_shape_refused(self):
        for raw in (b'{"schema":0,"schema":1,"modules":{}}', b'{"schema":"fleetory.publication-code-frame.v1","modules":{},"entry":"os"}'):
            with self.assertRaises(ValueError):policy.admitted_modules(raw, hashlib.sha256(raw).hexdigest())

    def test_runtime_namespace_shadow_refused(self):
        for name in ('os', 'sys', 'json'):
            with self.subTest(name=name), self.assertRaises(ValueError):policy.MemorySource({name:b'pass'})


if __name__ == '__main__':
    unittest.main()
