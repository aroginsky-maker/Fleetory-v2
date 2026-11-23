"""Portable synthetic release contracts; no remote services, real archives or credentials."""
import copy
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'eng' / 'pilot'))
import release_inputs as release


class ReleaseInputsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='fleetory-release-inputs-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.name = 'release-abcdef0.tar.gz'
        self.members = [(name, b'private.synthetic.' + name.encode(), tarfile.REGTYPE)
                        for name in sorted(release.REQUIRED)]
        self.pin()

    def tar(self, members=None, fmt=tarfile.USTAR_FORMAT):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode='w', format=fmt) as writer:
            for name, packet, kind in self.members if members is None else members:
                info = tarfile.TarInfo(name)
                info.type = kind
                if kind == tarfile.REGTYPE:
                    info.size = len(packet)
                elif kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
                    info.linkname = '/outside/private.key'
                writer.addfile(info, io.BytesIO(packet))
        return output.getvalue()

    def pin(self, packet=None):
        packet = gzip.compress(self.tar()) if packet is None else packet
        self.path = self.root / self.name
        self.path.write_bytes(packet)
        self.digest = hashlib.sha256(packet).hexdigest()

    def inspect(self):
        return release.inspect(self.root, self.name, self.digest)

    def refused(self):
        with self.assertRaises(Exception):
            self.inspect()

    def observed(self, inventory):
        return {role: {'imageId': 'sha256:' + 'a' * 64, 'readOnlyImageCodePathVerified': True,
                       'files': copy.deepcopy(payload)}
                for role, payload in release.payloads(inventory).items()}

    def cli(self, extra=()):
        return subprocess.run([sys.executable, '-B', str(Path(release.__file__)),
                               '--archive', self.name, '--expected-sha256', self.digest, *extra],
                              capture_output=True, cwd=self.root, timeout=10)

    def test_inventory_cli_is_read_only_and_contains_only_names_sizes_hashes(self):
        before = self.path.read_bytes()
        result = self.cli()
        self.assertEqual(result.returncode, 0, result.stderr)
        record = json.loads(result.stdout)
        self.assertEqual(set(record['files']), release.REQUIRED)
        self.assertNotIn(b'private.synthetic.', result.stdout + result.stderr)
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(list(self.root.iterdir()), [self.path])
        for field in ('sourceRevisionAuthenticated', 'releaseSignatureVerified', 'fullSystemRecoveryVerified', 'phase7Complete'):
            self.assertIs(record[field], False)

    def test_full_payload_comparison_requires_every_file_and_keeps_scope(self):
        inventory = self.inspect()
        result = release.compare_runtime(inventory, self.observed(inventory))
        self.assertEqual(result['matchedFiles'], len(release.REQUIRED) - 3)
        self.assertIs(result['codePayloadContinuityVerified'], True)
        for field in ('imageConfigurationVerified', 'sourceRevisionAuthenticated', 'releaseSignatureVerified',
                      'fullSystemRecoveryVerified', 'phase7Complete'):
            self.assertIs(result[field], False)

    def test_stale_payload_size_digest_missing_extra_are_rejected(self):
        inventory = self.inspect()
        for role in ('server', 'signer'):
            name = next(iter(release.payloads(inventory)[role]))
            for mutation in ('digest', 'size', 'missing', 'extra', 'boolean-size', 'fields'):
                with self.subTest(role=role, mutation=mutation):
                    observed = self.observed(inventory)
                    values = observed[role]['files']
                    if mutation == 'digest':
                        values[name]['sha256'] = '0' * 64
                    elif mutation == 'size':
                        values[name]['bytes'] += 1
                    elif mutation == 'missing':
                        del values[name]
                    elif mutation == 'extra':
                        values['unexpected.dll'] = values[name]
                    elif mutation == 'boolean-size':
                        values[name]['bytes'] = True
                    else:
                        values[name]['unreviewed'] = True
                    with self.assertRaises(Exception):
                        release.compare_runtime(inventory, observed)

    def test_runtime_image_and_boundary_are_required(self):
        inventory = self.inspect()
        for field, value in (('imageId', 'mutable:tag'), ('readOnlyImageCodePathVerified', False),
                             ('readOnlyImageCodePathVerified', 1), ('unreviewed', True)):
            observed = self.observed(inventory)
            observed['server'][field] = value
            with self.assertRaises(Exception):
                release.compare_runtime(inventory, observed)

    def test_wrong_archive_pin_is_rejected_without_contents(self):
        self.digest = '0' * 64
        result = self.cli()
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, b'')
        self.assertNotIn(b'private.synthetic.', result.stderr)

    def test_compressed_limit_is_enforced(self):
        with patch.object(release, 'MAX_COMPRESSED', self.path.stat().st_size - 1):
            self.refused()

    def test_gzip_expansion_is_bounded(self):
        self.pin(gzip.compress(bytes(65536)))
        with patch.object(release, 'MAX_EXPANDED', 4096):
            self.refused()

    def test_gzip_corruption_truncation_and_garbage_are_rejected(self):
        packet = self.path.read_bytes()
        for invalid in (packet[:-1], packet[:-8], packet + b'garbage', b'not-gzip'):
            self.pin(invalid)
            self.refused()

    def test_archive_path_is_basename_only(self):
        for name in ('../release-abcdef0.tar.gz', '/release-abcdef0.tar.gz',
                     'C:/release-abcdef0.tar.gz', 'sub/release-abcdef0.tar.gz',
                     'release-abcdef0.tar.gz:stream', 'backup.tar.gz'):
            with self.subTest(name=name):
                self.name = name
                self.refused()

    def test_root_cannot_be_replaced_from_cli(self):
        self.assertEqual(self.cli(('--root', str(self.root))).returncode, 2)

    def test_archive_hardlink_is_rejected(self):
        alias = self.root / 'alias'
        os.link(self.path, alias)
        self.refused()

    def test_changed_descriptor_state_is_rejected(self):
        actual = release.files.file_state
        calls = []
        def changed(info):
            calls.append(None)
            return (*actual(info), len(calls))
        with patch.object(release.files, 'file_state', side_effect=changed):
            self.refused()

    def test_member_paths_are_not_extraction_destinations(self):
        for name in ('../escape.dll', '/etc/private.key', 'server/publish/../Fleetory.Server.dll',
                     'server\\publish\\Fleetory.Server.dll', 'server/publish/Fleetory.Server.dll:stream',
                     'server/publish/identity.pem', 'signer/publish/provider-token', 'other/publish/test.dll'):
            with self.subTest(name=name):
                self.pin(gzip.compress(self.tar(self.members + [(name, b'private', tarfile.REGTYPE)])))
                self.refused()

    def test_symlinks_hardlinks_devices_and_fifo_are_rejected(self):
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.CHRTYPE, tarfile.BLKTYPE, tarfile.FIFOTYPE):
            with self.subTest(kind=kind):
                self.pin(gzip.compress(self.tar(self.members + [('server/publish/Fleetory.Core.dll', b'', kind)])))
                self.refused()

    def test_pax_and_gnu_extensions_are_rejected_before_interpretation(self):
        for kind in (tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.GNUTYPE_LONGNAME,
                     tarfile.GNUTYPE_LONGLINK, tarfile.GNUTYPE_SPARSE):
            header = tarfile.TarInfo('extension')
            header.type = kind
            self.pin(gzip.compress(header.tobuf(format=tarfile.USTAR_FORMAT) + bytes(1024)))
            self.refused()

    def test_duplicate_and_case_colliding_members_are_rejected(self):
        for name in (self.members[0][0], self.members[0][0].upper()):
            self.pin(gzip.compress(self.tar(self.members + [(name, b'duplicate', tarfile.REGTYPE)])))
            self.refused()

    def test_directory_records_have_only_reviewed_paths_and_zero_size(self):
        valid = self.members + [('server', b'', tarfile.DIRTYPE)]
        self.pin(gzip.compress(self.tar(valid)))
        self.inspect()
        self.pin(gzip.compress(self.tar(self.members + [('server/private', b'', tarfile.DIRTYPE)])))
        self.refused()
        header = tarfile.TarInfo('server')
        header.type, header.size = tarfile.DIRTYPE, 1
        self.pin(gzip.compress(header.tobuf() + bytes(2048)))
        self.refused()

    def test_missing_runtime_and_recipe_inputs_are_rejected(self):
        for removed in sorted(release.REQUIRED):
            with self.subTest(removed=removed):
                self.pin(gzip.compress(self.tar([m for m in self.members if m[0] != removed])))
                self.refused()

    def test_member_size_and_count_limits_are_enforced(self):
        with patch.object(release, 'MAX_MEMBER', 1):
            self.refused()
        with patch.object(release, 'MAX_ENTRIES', 1):
            self.refused()

    def test_tar_checksum_and_complete_terminator_are_required(self):
        packet = self.tar()
        for invalid in (b'X' + packet[1:], packet[:512], packet[:-1],
                        packet + bytes(512) + b'X' + bytes(511)):
            self.pin(gzip.compress(invalid))
            self.refused()


if __name__ == '__main__':
    unittest.main(verbosity=2)
