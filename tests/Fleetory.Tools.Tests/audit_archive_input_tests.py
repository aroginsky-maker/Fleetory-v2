"""Synthetic audit-only file capture. No original inputs, services or credentials."""
import copy
import ctypes
import dataclasses
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'eng' / 'pilot'))
import audit_archive_input as policy

H = policy.packet.digest


class AuditArchiveInputTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='fleetory-audit-input-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.relative = 'immudb-restore-' + '2' * 32 + '/backup.bin'
        self.path = self.root / self.relative
        self.path.parent.mkdir()
        self.data = b'IMMUBACKUP' + b'PRIVATE_SYNTHETIC_AUDIT_VALUE' * 4
        self.path.write_bytes(self.data)
        refs = [policy.selection.ArtifactReference('application-postgres', 'coherent-postgres-' + '1' * 32 + '/fleetory.dump', 100, 'a' * 64),
                policy.selection.ArtifactReference('signer-postgres', 'coherent-postgres-' + '1' * 32 + '/fleetory_signer.dump', 100, 'b' * 64),
                policy.selection.ArtifactReference('audit-immudb', self.relative, len(self.data), H(self.data))]
        self.record = policy.selection.Selection(tuple(refs), tuple((name, value * 64) for name, value in
            (('audit', 'c'), ('database', 'd'), ('manifest', 'e')))).report()
        self.pin()

    def pin(self):
        self.selection = bytearray(json.dumps(self.record).encode())
        self.expected = H(self.selection)

    def capture(self):
        return policy.capture(self.root, self.selection, self.expected)

    def refused(self):
        with self.assertRaises((ValueError, TypeError, KeyError, OSError, policy.files.archive.ArchiveError)):
            self.capture()

    def cli(self, extra=()):
        return subprocess.run([sys.executable, '-B', str(Path(policy.__file__)), '--expected-selection-sha256', self.expected, *extra],
            input=self.selection, cwd=self.root, capture_output=True, timeout=10)

    def junction(self, link, target):
        if os.name == 'nt':
            r = subprocess.run(['cmd.exe', '/d', '/c', 'mklink', '/J', str(link), str(target)], capture_output=True, timeout=5)
            self.assertEqual(r.returncode, 0, 'Synthetic junction creation failed.')
        else:
            link.symlink_to(target, target_is_directory=True)

    def test_exactly_one_artifact_opened_and_no_broad_verifier(self):
        original = policy.files.inspect_file
        with patch.object(policy.files, 'inspect_file', wraps=original) as observed, \
             patch.object(policy.files, 'verify', side_effect=AssertionError('Broad verifier forbidden')), \
             patch('subprocess.Popen', side_effect=AssertionError('Process forbidden')), \
             patch('socket.socket', side_effect=AssertionError('Socket forbidden')):
            result = self.capture()
        self.assertEqual(observed.call_count, 1)
        self.assertEqual(observed.call_args.args[2:], (self.relative, len(self.data)))
        self.assertIs(observed.call_args.kwargs['retain'], True)
        self.assertEqual(result.data, self.data)
        self.assertEqual(result.report()['verifiedArtifacts'], 1)
        self.assertFalse(result.report()['otherSelectedArtifactsOpened'])

    def test_immutable_capture_does_not_reopen_changed_file(self):
        result = self.capture()
        self.selection[:] = b'changed'
        self.path.write_bytes(b'changed')
        self.assertEqual(result.data, self.data)
        self.assertEqual(result.artifact_sha256, H(self.data))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            result.data = b'changed'

    def test_pin_and_entire_metadata_buffer_frozen_before_parsing(self):
        original = policy.packet.strict_json
        def interleaved(data, bound):
            self.selection[:] = b'changed'
            self.expected = '0' * 64
            return original(data, bound)
        with patch.object(policy.packet, 'strict_json', side_effect=interleaved):
            self.assertEqual(self.capture().data, self.data)

    def test_malformed_or_changed_metadata_refused_before_filesystem(self):
        original = bytes(self.selection)
        for value in (b'', b'{' , b'{"x":NaN}', b'{"x":1,"x":2}', b'\xff', b'x' * (policy.MAX_SELECTION + 1), original[:-1] + b'x'):
            self.selection = value
            self.expected = H(value)
            with patch.object(policy.files, 'rooted', side_effect=AssertionError('Filesystem reached')):
                self.refused()
        self.selection, self.expected = original, '0' * 64
        with patch.object(policy.files, 'rooted', side_effect=AssertionError('Filesystem reached')):
            self.refused()

    def test_wrong_purpose_scope_flags_and_type_confusion(self):
        original = copy.deepcopy(self.record)
        for name in ('executionAuthorized', 'existingConsentExpanded', 'sourceSigningMaterialReuseAuthorized',
                     'providerRootOrTokenUseAuthorized', 'identityIssuerStartAuthorized', 'artifactBytesVerified',
                     'filesystemContainmentVerified', 'metadataOnly', 'metadataPinsMatched'):
            for value in (False, True, 0, 1):
                self.record = copy.deepcopy(original)
                self.record[name] = value
                if type(value) is bool and original[name] is value:
                    continue
                self.pin()
                with self.subTest(name=name, value=value), patch.object(policy.files, 'rooted', side_effect=AssertionError('Filesystem reached')):
                    self.refused()
        self.record = copy.deepcopy(original)
        self.record['purpose'] = 'approved-full-recovery'
        self.pin(); self.refused()

    def test_selected_kinds_missing_extra_reordered_and_excluded(self):
        original = copy.deepcopy(self.record)
        for change in ('missing', 'extra', 'reorder', 'identity', 'provider', 'export'):
            self.record = copy.deepcopy(original)
            rows = self.record['selected']
            if change == 'missing':
                rows.pop()
            elif change == 'extra':
                rows.append(copy.deepcopy(rows[-1]))
            elif change == 'reorder':
                rows.reverse()
            else:
                rows[-1]['kind'] = {'identity': 'identity-postgres', 'provider': 'provider-raft', 'export': 'audit-export'}[change]
            self.pin()
            with patch.object(policy.files, 'inspect_file', side_effect=AssertionError('File reached')):
                self.refused()

    def test_invalid_paths_relabelled_native_paths_and_duplicate_references(self):
        original = copy.deepcopy(self.record)
        for value in ('../outside', '/absolute', 'C:/private', r'folder\file', 'a//b', './file', 'a/../file',
                      'CON', 'NUL.dump', 'file.', 'a:b', 'keycloak/database.dump',
                      'coherent-postgres-' + '1' * 32 + '/fleetory.dump'):
            self.record = copy.deepcopy(original)
            self.record['selected'][-1]['path'] = value
            self.pin()
            with self.subTest(value=value), patch.object(policy.files, 'inspect_file', side_effect=AssertionError('File reached')):
                self.refused()
        self.record = copy.deepcopy(original)
        self.record['selected'][-1]['sha256'] = self.record['selected'][0]['sha256']
        self.pin(); self.refused()

    def test_metadata_size_bounds_counts_digests_and_extra_fields(self):
        original = copy.deepcopy(self.record)
        for name, value in (('bytes', True), ('bytes', 0), ('bytes', 63), ('bytes', policy.MAX_CAPTURE + 1),
                            ('bytes', 100.0), ('sha256', 'A' * 64), ('sha256', 'z' * 64), ('path', None), ('secretPath', 'forbidden')):
            self.record = copy.deepcopy(original)
            self.record['selected'][-1][name] = value
            self.record['selectedBytes'] = sum(row['bytes'] for row in self.record['selected'])
            self.pin(); self.refused()
        for name, value in (('selectedBytes', 0), ('metadataPins', {}), ('excludedKinds', []), ('root', '/forbidden')):
            self.record = copy.deepcopy(original)
            self.record[name] = value
            self.pin(); self.refused()

    def test_changed_stale_empty_oversize_and_wrong_magic_files(self):
        for data in (b'X' + self.data[1:], b'old-three-event-backup', b'', self.data + b'x'):
            self.path.write_bytes(data)
            self.refused()
        self.path.write_bytes(b'NOTBACKUP!' + self.data[10:])
        self.record['selected'][-1]['sha256'] = H(self.path.read_bytes())
        self.pin(); self.refused()

    def test_leaf_hardlink_or_nonregular_input_refused(self):
        outside = self.root / 'unrelated'
        self.path.rename(outside)
        os.link(outside, self.path)
        self.refused()
        self.path.unlink()
        if os.name == 'posix':
            self.path.symlink_to(outside)
        else:
            outside.unlink(); outside.mkdir()
            self.junction(self.path, outside)
        original = Path.resolve
        def no_leaf_resolution(path, *args, **kwargs):
            self.assertNotEqual(path, self.path, 'Leaf reparse target followed')
            return original(path, *args, **kwargs)
        with patch.object(Path, 'resolve', no_leaf_resolution):
            self.refused()

    def test_parent_root_and_ancestor_link_refused(self):
        moved = self.root / 'moved'
        self.path.parent.rename(moved)
        self.junction(self.path.parent, moved)
        self.refused()
        root_link = self.root / 'root-link'
        target = self.root / 'root-target'
        target.mkdir()
        self.junction(root_link, target)
        with self.assertRaises((OSError, policy.files.archive.ArchiveError)):
            policy.capture(root_link, self.selection, self.expected)

    def test_actual_open_rechecks_leaf_swap(self):
        original = policy.files.relative_open
        def swapped(root, descriptor, name):
            self.path.unlink()
            self.path.mkdir()
            return original(root, descriptor, name)
        with patch.object(policy.files, 'relative_open', side_effect=swapped):
            self.refused()

    def test_wrong_root_descriptor_is_not_borrowed(self):
        with tempfile.TemporaryDirectory(prefix='fleetory-other-audit-root-') as other, policy.files.rooted(other) as (_, descriptor):
            original = policy.files.rooted
            from contextlib import contextmanager
            @contextmanager
            def borrowed(root):
                with original(root) as (directory, _):
                    yield directory, 0 if os.name == 'nt' else descriptor
            with patch.object(policy.files, 'rooted', borrowed):
                self.refused()

    def test_growth_during_capture_is_denied_or_detected(self):
        original = os.fdopen
        changed, test = [], self
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
                data = self.stream.read(size)
                if not changed:
                    changed.append(True)
                    if os.name == 'nt':
                        with test.assertRaises(PermissionError):
                            with test.path.open('ab') as writer:
                                writer.write(b'x')
                    else:
                        with test.path.open('ab') as writer:
                            writer.write(b'x')
                return data
        with patch.object(policy.files.os, 'fdopen', side_effect=lambda *args, **kwargs: Reader(original(*args, **kwargs))):
            if os.name == 'nt':
                self.assertEqual(self.capture().data, self.data)
            else:
                self.refused()
        self.assertEqual(changed, [True])

    def test_cli_sanitized_receipt_has_no_raw_bytes_paths_or_authority(self):
        before = self.path.read_bytes()
        result = self.cli()
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual((report['verifiedArtifacts'], report['verifiedBytes']), (1, len(self.data)))
        for name in ('otherSelectedArtifactsOpened', 'nativeChecksumVerified', 'nativeObservationPerformed',
                     'independentEventExpectationsVerified', 'originalKeyContinuityVerified', 'signaturesVerified',
                     'executionAuthorized', 'fullSystemRecoveryVerified', 'phase7Complete'):
            self.assertIs(report[name], False)
        for value in (self.data, str(self.root).encode(), self.relative.encode()):
            self.assertNotIn(value, result.stdout + result.stderr)
        self.assertEqual(self.path.read_bytes(), before)
        failed = self.cli(('--root', 'PRIVATE_PATH_CANARY'))
        self.assertEqual(failed.returncode, 1)
        self.assertEqual(failed.stdout, b'')
        self.assertNotIn(b'PRIVATE_PATH_CANARY', failed.stderr)

    def test_cli_cannot_use_ambient_other_root(self):
        self.path.unlink()
        failed = self.cli()
        self.assertEqual(failed.returncode, 1)
        self.assertEqual(failed.stdout, b'')
        self.assertNotIn(self.relative.encode(), failed.stderr)

    def test_windows_short_root_alias_or_posix_ordinary_root(self):
        root = str(self.root)
        if os.name == 'nt':
            convert = ctypes.WinDLL('kernel32', use_last_error=True).GetShortPathNameW
            convert.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32]
            convert.restype = ctypes.c_uint32
            buffer = ctypes.create_unicode_buffer(32768)
            length = convert(root, buffer, len(buffer))
            self.assertTrue(0 < length < len(buffer))
            root = buffer.value
        self.assertEqual(policy.capture(root, self.selection, self.expected).data, self.data)


if __name__ == '__main__':
    unittest.main()
