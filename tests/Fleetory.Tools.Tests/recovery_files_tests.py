"""Synthetic file/CLI contracts; no credentials, remote services or restore operations."""
import copy
import ctypes
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import tracemalloc
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'eng' / 'pilot'))
import recovery_files as files


def sha(data):
    return hashlib.sha256(data).hexdigest()


class RecoveryFilesTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='fleetory-recovery-files-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.record = {'schema': files.SCHEMA, 'artifacts': {}}
        for index, kind in enumerate(sorted(files.KINDS)):
            relative = f'component-{index}/backup.bin'
            packet = ('private.synthetic.' + kind).encode()
            path = self.root / relative
            path.parent.mkdir()
            path.write_bytes(packet)
            self.record['artifacts'][kind] = {'path': relative, 'bytes': len(packet), 'sha256': sha(packet)}
        self.pin()

    def pin(self, packet=None):
        packet = packet if packet is not None else json.dumps(self.record).encode()
        (self.root / 'set.json').write_bytes(packet)
        self.expected = sha(packet)

    def verify(self):
        return files.verify(self.root, 'set.json', self.expected)

    def cli(self, expected=None):
        return subprocess.run([sys.executable, '-B', str(Path(files.__file__)), '--root', str(self.root),
                               '--manifest', 'set.json', '--expected-sha256', expected or self.expected],
                              capture_output=True, timeout=5)

    def entry(self, kind='application-postgres'):
        return self.record['artifacts'][kind]

    def artifact(self, kind='application-postgres'):
        return self.root / self.entry(kind)['path']

    def refused(self):
        with self.assertRaises(Exception):
            self.verify()

    def junction(self, link, target):
        if os.name == 'nt':
            result = subprocess.run(['cmd.exe', '/d', '/c', 'mklink', '/J', str(link), str(target)],
                                    capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 0, 'Synthetic junction creation failed.')
        else:
            link.symlink_to(target, target_is_directory=True)

    def test_complete_cli_is_read_only_and_never_claims_full_restore(self):
        before = {str(p): p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        result = self.cli()
        self.assertEqual(result.returncode, 0, result.stderr)
        parsed = json.loads(result.stdout)
        self.assertEqual(parsed['verifiedArtifacts'], 6)
        self.assertEqual(parsed['manifestSha256'], self.expected)
        for name in ('fullSystemRecoveryVerified', 'independentCustodyVerified', 'globalAtomicSnapshotClaimed', 'phase7Complete'):
            self.assertIs(parsed[name], False)
        self.assertEqual(before, {str(p): p.read_bytes() for p in self.root.rglob('*') if p.is_file()})
        self.assertNotIn(b'private.synthetic.', result.stdout + result.stderr)

    def test_changed_artifact_same_size_is_rejected_without_contents(self):
        path = self.artifact()
        data = path.read_bytes()
        path.write_bytes(b'X' + data[1:])
        result = self.cli()
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, b'')
        self.assertNotIn(data[1:], result.stderr)

    def test_stale_bytes_at_current_name_are_rejected(self):
        self.artifact().write_bytes(b'older.three.event.backup')
        self.refused()

    def test_rewritten_manifest_does_not_rebaseline_trusted_pin(self):
        self.artifact().write_bytes(b'replacement')
        self.entry()['bytes'] = 11
        self.entry()['sha256'] = sha(b'replacement')
        (self.root / 'set.json').write_text(json.dumps(self.record))
        self.refused()

    def test_missing_artifact(self):
        self.artifact().unlink()
        self.refused()

    def test_empty_artifact(self):
        self.artifact().write_bytes(b'')
        self.refused()

    def test_actual_size_exceeds_bound_before_read(self):
        with self.artifact().open('wb') as stream:
            stream.truncate(files.MAX_ARTIFACT + 1)
        self.refused()

    def test_missing_extra_or_duplicate_component(self):
        original = copy.deepcopy(self.record)
        self.record['artifacts'].pop('provider-raft')
        self.pin(); self.refused()
        self.record = copy.deepcopy(original)
        self.record['artifacts']['unapproved-pki'] = self.entry().copy()
        self.pin(); self.refused()
        packet = json.dumps(original).replace('"artifacts": {', '"artifacts": {"application-postgres":{},', 1).encode()
        self.pin(packet); self.refused()

    def test_unique_exact_json_fields(self):
        for transform in (lambda text: text.replace('"schema":', '"schema":"duplicate", "schema":', 1),
                          lambda text: text.replace('"bytes":', '"bytes":1, "bytes":', 1),
                          lambda text: '[' + text + ']',
                          lambda text: text.replace('"path":', '"Path":', 1)):
            with self.subTest(transform=transform):
                self.pin(transform(json.dumps(self.record)).encode()); self.refused()

    def test_typed_size_hash_and_schema_fields(self):
        original = copy.deepcopy(self.record)
        for value in (True, 0, -1, 1.0, '23', files.MAX_ARTIFACT + 1):
            self.record = copy.deepcopy(original)
            self.entry()['bytes'] = value
            self.pin(); self.refused()
        for value in (None, 'a' * 63, 'g' * 64, 'A' * 64):
            self.record = copy.deepcopy(original)
            self.entry()['sha256'] = value
            self.pin(); self.refused()
        self.record = copy.deepcopy(original)
        self.record['schema'] = 'fleetory.recovery-files.v2'
        self.pin(); self.refused()

    def test_no_readiness_claim_fields_are_accepted(self):
        self.record['fullSystemRecoveryVerified'] = True
        self.pin(); self.refused()

    def test_all_paths_checked_before_artifact_reads(self):
        for path in ('../outside', '/absolute', 'C:/secret', r'folder\file', 'a//b', './file',
                     'a/../file', 'a:b', 'file.', 'CON', 'nul.dump', 'LPT1.txt', 'a/b/c/d/e', ''):
            with self.subTest(path=path):
                self.entry()['path'] = path
                self.pin()
                with patch.object(files, 'inspect_file', wraps=files.inspect_file) as observed:
                    self.refused()
                    self.assertEqual(observed.call_count, 1, 'Artifact read before complete path validation.')

    def test_duplicate_paths_case_insensitive_and_manifest_self_reference(self):
        self.entry('signer-postgres')['path'] = self.entry()['path'].upper()
        self.pin(); self.refused()
        self.entry('signer-postgres')['path'] = 'set.json'
        self.pin(); self.refused()

    def test_hardlink_to_external_data_is_rejected(self):
        outside = self.root.parent / (self.root.name + '-outside')
        outside.write_bytes(self.artifact().read_bytes())
        self.addCleanup(outside.unlink)
        self.artifact().unlink()
        os.link(outside, self.artifact())
        self.refused()

    def test_directory_link_escape_is_rejected(self):
        source = self.artifact().parent
        moved = self.root / 'outside-data'
        source.rename(moved)
        self.junction(source, moved)
        self.refused()

    def test_root_and_ancestor_link_rejected(self):
        link = self.root / 'root-link'
        target = self.root / 'target'
        target.mkdir()
        self.junction(link, target)
        for root in (link, link / 'child'):
            with self.assertRaises(Exception):
                files.verify(root, 'set.json', self.expected)

    def test_nonregular_input_does_not_block_cli(self):
        path = self.artifact()
        path.unlink()
        if os.name == 'posix':
            os.mkfifo(path)
        else:
            path.mkdir()
        self.assertEqual(self.cli().returncode, 1)

    def test_leaf_link_is_rejected(self):
        path = self.artifact()
        destination = self.root / 'leaf-target'
        path.rename(destination)
        if os.name == 'posix':
            path.symlink_to(destination)
        else:
            # Windows reparse directories also exercise the leaf handle's refusal.
            destination.unlink(); destination.mkdir()
            self.junction(path, destination)
        self.refused()

    def test_bounded_streaming_hash(self):
        path = self.artifact()
        with path.open('wb') as stream:
            for _ in range(128):
                stream.write(b'x' * 65536)
        self.entry()['bytes'] = path.stat().st_size
        with path.open('rb') as stream:
            self.entry()['sha256'] = hashlib.file_digest(stream, 'sha256').hexdigest()
        self.pin()
        tracemalloc.start()
        try:
            self.verify()
            self.assertLess(tracemalloc.get_traced_memory()[1], 1024 * 1024)
        finally:
            tracemalloc.stop()

    def test_live_growth_is_denied_or_detected(self):
        target = self.artifact()
        inode = target.stat().st_ino
        original = os.fdopen
        changed = []
        test = self

        class Reader:
            def __init__(self, stream):
                self.stream = stream

            def __enter__(self):
                return self

            def __exit__(self, *args):
                self.stream.close()

            def fileno(self):
                return self.stream.fileno()

            def read(self, size):
                packet = self.stream.read(size)
                if not changed and os.fstat(self.fileno()).st_ino == inode:
                    changed.append(True)
                    if os.name == 'nt':
                        with test.assertRaises(PermissionError):
                            with target.open('ab') as writer:
                                writer.write(b'x')
                    else:
                        with target.open('ab') as writer:
                            writer.write(b'x')
                return packet

        with patch.object(files.os, 'fdopen', side_effect=lambda *a, **kw: Reader(original(*a, **kw))):
            if os.name == 'nt':
                self.assertEqual(self.verify()['verifiedArtifacts'], 6)
            else:
                self.refused()
        self.assertEqual(changed, [True])

    def test_manifest_limit_and_invalid_json(self):
        for data in (b'', b' ' * (files.MAX_MANIFEST + 1), b'{', b'\xff', b'{"schema":NaN}'):
            self.pin(data); self.refused()

    def test_invalid_pin_and_manifest_path(self):
        for value in ('', 'a' * 63, 'g' * 64):
            with self.assertRaises(Exception):
                files.verify(self.root, 'set.json', value)
        with self.assertRaises(Exception):
            files.verify(self.root, '../set.json', self.expected)
        self.assertEqual(files.verify(self.root, 'set.json', self.expected.upper())['verifiedArtifacts'], 6)

    def test_short_directory_alias_resolves_to_the_same_protected_root(self):
        root = str(self.root)
        if os.name == 'nt':
            kernel = ctypes.WinDLL('kernel32', use_last_error=True)
            short = kernel.GetShortPathNameW
            short.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32]
            short.restype = ctypes.c_uint32
            buffer = ctypes.create_unicode_buffer(32768)
            length = short(root, buffer, len(buffer))
            self.assertTrue(0 < length < len(buffer))
            root = buffer.value
        self.assertEqual(files.verify(root, 'set.json', self.expected)['verifiedArtifacts'], 6)


if __name__ == '__main__':
    unittest.main()
