"""Real private-filesystem/CLI contracts; fixture data only, no production access."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'eng' / 'pilot'))
import audit_archive as archive


def snapshot(count=1):
    events = []
    for number in range(1, count + 1):
        events.append({'event_id': f'00000000-0000-4000-8000-{number:012d}',
                       'actor_subject_id': 'fixture-owner', 'actor_kind': 1,
                       'action': 'fixture.audit', 'target_type': None, 'target_id': None,
                       'correlation_id': f'fixture-{number}',
                       'occurred_at': '2026-11-01T00:00:00.000000Z',
                       'recorded_at': '2026-11-01T00:00:01.000000Z',
                       'context_json': json.dumps({'message': 'Проверка 审计', 'value': number}, ensure_ascii=False)})
    return {'schema': 'fleetory.audit-snapshot.v1', 'events': events, 'pendingExportCount': 0}


def bundle(count=1):
    value = snapshot(count)
    receipt = {'schema': 'fleetory.audit-archive-receipt.v1', 'sequence': 1,
               'capturedAt': '2026-11-01T01:00:00.000000Z',
               'snapshotSha256': archive.digest(value), 'previousReceiptSha256': archive.ZERO}
    return {'schema': 'fleetory.audit-archive-export.v1', 'receipts': [receipt], 'snapshot': value}


def checksum(data):
    return hashlib.sha256(data).hexdigest()


class PortableExportTests(unittest.TestCase):
    def test_exact_hash_and_preserved_unicode(self):
        data = archive.canonical(bundle())
        result = archive.verify_export(data, checksum(data))
        self.assertEqual(1, result['eventCount'])
        self.assertFalse(result['checkpointVerified'])
        self.assertFalse(result['independentCustodyVerified'])
        self.assertFalse(result['administratorTamperProof'])
        self.assertFalse(result['sourceSignedStateVerified'])
        with self.assertRaises(archive.ArchiveError):
            archive.verify_export(data, 'a' * 64)

    def test_checkpoint_extension_and_rollback_rejection(self):
        old = bundle()
        new = bundle(2)
        latest = new['receipts'][0]
        latest['sequence'] = 2
        latest['previousReceiptSha256'] = archive.digest(old['receipts'][0])
        new['receipts'].insert(0, old['receipts'][0])
        before, after = archive.canonical(old), archive.canonical(new)
        self.assertTrue(archive.verify_export(after, checksum(after), before, checksum(before))['checkpointVerified'])
        with self.assertRaises(archive.ArchiveError):
            archive.verify_export(before, checksum(before), after, checksum(after))

    def test_rehashed_history_rewrite_rejected_by_checkpoint(self):
        before = archive.canonical(bundle())
        changed = bundle()
        changed['snapshot']['events'][0]['action'] = 'rewritten'
        changed['receipts'][0]['snapshotSha256'] = archive.digest(changed['snapshot'])
        after = archive.canonical(changed)
        archive.verify_export(after, checksum(after))
        with self.assertRaises(archive.ArchiveError):
            archive.verify_export(after, checksum(after), before, checksum(before))

    def test_checkpoint_requires_both_input_and_trusted_digest(self):
        data = archive.canonical(bundle())
        for prior, expected in ((data, None), (None, checksum(data)), (data, 'f' * 64)):
            with self.subTest(prior=prior is not None), self.assertRaises(archive.ArchiveError):
                archive.verify_export(data, checksum(data), prior, expected)

    def test_duplicate_json_invalid_utf8_oversize_and_nonfinite(self):
        for data in (b'{"schema":1,"schema":2}', b'\xff', b'{}' * (archive.MAX_EXPORT // 2 + 1),
                     b'{"x":NaN}', b'{"x":1e999}', b'[]'):
            with self.subTest(size=len(data)), self.assertRaises((archive.ArchiveError, ValueError)):
                archive.validate_export(data)

    def test_typed_schema_receipt_and_event_rejections(self):
        changes = [lambda v: v.update(extra=True),
                   lambda v: v['receipts'][0].update(sequence=True),
                   lambda v: v['receipts'][0].update(previousReceiptSha256='f' * 64),
                   lambda v: v['receipts'][0].update(capturedAt='2026-11-01'),
                   lambda v: v['snapshot'].update(pendingExportCount=True),
                   lambda v: v['snapshot']['events'][0].update(actor_kind=True),
                   lambda v: v['snapshot']['events'][0].update(event_id='../escape'),
                   lambda v: v['snapshot']['events'].append(v['snapshot']['events'][0])]
        for change in changes:
            value = bundle()
            change(value)
            data = archive.canonical(value)
            with self.subTest(change=changes.index(change)), self.assertRaises((archive.ArchiveError, ValueError)):
                archive.verify_export(data, checksum(data))

    def test_cli_rejects_without_disclosing_event_content(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'export.json'
            value = bundle()
            value['snapshot']['events'][0]['action'] = 'fixture-secret-must-not-be-printed'
            path.write_bytes(archive.canonical(value))
            result = subprocess.run([sys.executable, archive.__file__, 'verify-export', '--input', path.name,
                                     '--expected-sha256', 'a' * 64], cwd=temporary, capture_output=True, timeout=10)
            self.assertEqual(1, result.returncode)
            self.assertEqual(b'', result.stdout)
            self.assertNotIn(b'fixture-secret', result.stderr)

    def test_cli_names_cannot_escape_the_selected_private_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            private = root / 'private'
            private.mkdir()
            data = archive.canonical(bundle())
            outside = root / 'export-outside.json'
            outside.write_bytes(data)
            (private / 'export.json').write_bytes(data)
            (private / 'credentials.json').write_bytes(data)
            def invoke(name):
                return subprocess.run([sys.executable, archive.__file__, 'verify-export', '--input', name,
                                       '--expected-sha256', checksum(data)], cwd=private,
                                      capture_output=True, timeout=10)
            self.assertEqual(0, invoke('export.json').returncode)
            for name in ('../export-outside.json', str(outside), 'private/../export.json',
                         'private\\export.json', 'credentials.json'):
                with self.subTest(name=name):
                    self.assertNotEqual(0, invoke(name).returncode)
            linked = private / 'export-hardlinked.json'
            os.link(outside, linked)
            self.assertNotEqual(0, invoke(linked.name).returncode)
            if os.name == 'posix':
                symbolic = private / 'export-symbolic.json'
                symbolic.symlink_to(outside)
                self.assertNotEqual(0, invoke(symbolic.name).returncode)


class RootArchiveTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / 'archive'
        archive.initialize(self.root)

    def tearDown(self):
        self.temporary.cleanup()

    def read(self):
        with archive.archive_lock(self.root):
            return archive.inspect(self.root)

    def first_entry(self):
        return self.root / 'entries' / '000000000001'

    def alter(self, path, value):
        path.chmod(0o600)
        path.write_bytes(archive.canonical(value))
        path.chmod(0o400)

    def test_publication_is_idempotent_and_restart_retains_history(self):
        first = archive.publish(self.root, snapshot())
        contents = {p.name: p.read_bytes() for p in self.first_entry().iterdir()}
        self.assertEqual('created', first['status'])
        self.assertEqual('unchanged', archive.publish(self.root, snapshot())['status'])
        archive.initialize(self.root)
        self.assertEqual(2, archive.publish(self.root, snapshot(2))['snapshotCount'])
        self.assertEqual(contents, {p.name: p.read_bytes() for p in self.first_entry().iterdir()})
        self.assertEqual(2, len(self.read()[1]['events']))

    def test_source_deletion_and_rewrite_fail_without_changing_archive(self):
        archive.publish(self.root, snapshot(2))
        before = archive.export(self.root)
        changed = snapshot(2)
        changed['events'][0]['action'] = 'rewritten'
        for value in (snapshot(), changed):
            with self.assertRaises(archive.ArchiveError):
                archive.publish(self.root, value)
            self.assertEqual(before, archive.export(self.root))

    def test_outbox_changes_can_be_archived_without_resetting_events(self):
        archive.publish(self.root, snapshot())
        changed = snapshot()
        changed['pendingExportCount'] = 1
        self.assertEqual(2, archive.publish(self.root, changed)['snapshotCount'])

    def test_nonprivileged_process_cannot_read_or_overwrite_archive(self):
        archive.publish(self.root, snapshot())
        path = self.first_entry() / 'snapshot.json'
        code = 'from pathlib import Path; import sys; Path(sys.argv[1]).read_bytes()'
        for operation in (code, code.replace('read_bytes()', 'write_bytes(b"rewrite")')):
            result = subprocess.run([sys.executable, '-c', operation, str(path)],
                                    user=1654, group=1654, capture_output=True, timeout=10)
            self.assertNotEqual(0, result.returncode)
            self.assertIn(b'PermissionError', result.stderr)
        self.assertEqual(1, self.read()[0][0]['sequence'])

    def test_nonprivileged_cli_cannot_initialize_archive(self):
        result = subprocess.run([sys.executable, archive.__file__, 'init'],
                                user=1654, group=1654, capture_output=True, timeout=10)
        self.assertEqual(1, result.returncode)
        self.assertIn(b'Audit archive operation failed.', result.stderr)

    def test_archive_cli_cannot_override_fixed_root(self):
        for command in ('init', 'capture', 'verify', 'export'):
            result = subprocess.run([sys.executable, archive.__file__, command, '--root', str(self.root)],
                                    capture_output=True, timeout=10)
            self.assertEqual(2, result.returncode)
        self.assertEqual(([], None, 0), self.read())

    def test_symbolic_archive_root_is_rejected(self):
        alias = self.root.parent / 'alias'
        alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(archive.ArchiveError):
            archive.publish(alias, snapshot())

    def test_symbolic_parent_is_rejected(self):
        alias = self.root.parent / 'parent-alias'
        alias.symlink_to(self.root.parent, target_is_directory=True)
        with self.assertRaises(archive.ArchiveError):
            archive.initialize(alias / 'different-archive')

    def test_hardlinked_snapshot_is_rejected(self):
        archive.publish(self.root, snapshot())
        os.link(self.first_entry() / 'snapshot.json', self.root.parent / 'linked.json')
        with self.assertRaises(archive.ArchiveError):
            self.read()

    def test_symbolic_snapshot_and_lock_are_rejected(self):
        archive.publish(self.root, snapshot())
        path = self.first_entry() / 'snapshot.json'
        external = self.root.parent / 'external.json'
        path.rename(external)
        path.symlink_to(external)
        with self.assertRaises(archive.ArchiveError):
            self.read()
        path.unlink()
        external.rename(path)
        lock = self.root / '.lock'
        lock.unlink()
        lock.symlink_to(external)
        with self.assertRaises(OSError):
            self.read()

    def test_broad_permissions_fail_closed(self):
        archive.publish(self.root, snapshot())
        for path, correct in ((self.root, 0o700), (self.root / 'entries', 0o700),
                              (self.first_entry() / 'snapshot.json', 0o400)):
            path.chmod(correct | 0o020)
            with self.assertRaises(archive.ArchiveError):
                self.read()
            path.chmod(correct)

    def test_missing_extra_and_partial_entries_are_rejected(self):
        archive.publish(self.root, snapshot())
        extra = self.first_entry() / 'unexpected'
        extra.write_bytes(b'x')
        with self.assertRaises(archive.ArchiveError):
            self.read()
        extra.unlink()
        pending = self.root / '.pending-interrupted'
        pending.mkdir(mode=0o700)
        with self.assertRaises(archive.ArchiveError):
            self.read()
        pending.rmdir()
        (self.first_entry() / 'receipt.json').unlink()
        with self.assertRaises(archive.ArchiveError):
            self.read()

    def test_noncontiguous_sequences_and_corrupt_objects_are_rejected(self):
        archive.publish(self.root, snapshot())
        entry = self.first_entry()
        different = entry.with_name('000000000002')
        entry.rename(different)
        with self.assertRaises(archive.ArchiveError):
            self.read()
        different.rename(entry)
        value = snapshot()
        value['events'][0]['action'] = 'corrupt'
        self.alter(entry / 'snapshot.json', value)
        with self.assertRaises(archive.ArchiveError):
            self.read()

    def test_capacity_and_entry_limits_preserve_existing_archive(self):
        archive.publish(self.root, snapshot())
        before = archive.export(self.root)
        total = self.read()[2]
        for name, limit in (('MAX_ARCHIVE', total + 1), ('MAX_ENTRIES', 1)):
            with patch.object(archive, name, limit), self.assertRaises(archive.ArchiveError):
                archive.publish(self.root, snapshot(2))
            self.assertEqual(before, archive.export(self.root))

    def test_failed_sync_leaves_no_accepted_entry(self):
        with patch.object(archive.os, 'fsync', side_effect=OSError('fixture fsync failure')):
            with self.assertRaises(OSError):
                archive.publish(self.root, snapshot())
        self.assertEqual(([], None, 0), self.read())

    def test_real_low_space_filesystem_refuses_publication(self):
        with tempfile.TemporaryDirectory(dir='/lowspace') as directory:
            root = Path(directory) / 'archive'
            archive.initialize(root)
            with self.assertRaises(archive.ArchiveError):
                archive.publish(root, snapshot())
            with archive.archive_lock(root):
                self.assertEqual(([], None, 0), archive.inspect(root))

    def test_concurrent_processes_publish_once(self):
        code = ('import json,sys; from pathlib import Path; import audit_archive as a; '
                'print(a.publish(Path(sys.argv[1]),json.loads(sys.argv[2]))["status"])')
        processes = [subprocess.Popen([sys.executable, '-c', code, str(self.root),
                                       archive.canonical(snapshot()).decode('utf-8')],
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                      env={**os.environ, 'PYTHONPATH': str(Path(archive.__file__).parent)})
                     for _ in range(4)]
        results = [(process, process.communicate(timeout=20)) for process in processes]
        outputs = []
        for process, (output, errors) in results:
            self.assertEqual(0, process.returncode, errors.decode('utf-8'))
            outputs.append(output.decode('utf-8').strip())
        self.assertEqual(1, outputs.count('created'))
        self.assertEqual(3, outputs.count('unchanged'))
        self.assertEqual(1, len(self.read()[0]))

    def test_real_postgres_snapshot_excludes_future_sensitive_columns(self):
        path = Path(os.environ['ARCHIVE_SQL_FIXTURE'])
        data = archive.read_file(path, archive.MAX_SNAPSHOT, Path('/fixture'))
        self.assertNotIn(b'fixture-private-future-column', data)
        value = archive.parse(data, archive.MAX_SNAPSHOT)
        self.assertEqual(2, len(value['events']))
        self.assertEqual(1, value['pendingExportCount'])
        archive.publish(self.root, value)
        exported = archive.export(self.root)
        self.assertEqual(2, archive.verify_export(exported, checksum(exported))['eventCount'])

    def test_real_postgres_numeric_context_rewrite_cannot_collapse(self):
        path = Path(os.environ['ARCHIVE_SQL_FIXTURE'])
        initial = archive.parse(archive.read_file(path, archive.MAX_SNAPSHOT, Path('/fixture')), archive.MAX_SNAPSHOT)
        changed = archive.parse(archive.read_file(path.with_name('rewritten.json'), archive.MAX_SNAPSHOT, Path('/fixture')),
                                archive.MAX_SNAPSHOT)
        before = initial['events'][0]['context_json']
        after = changed['events'][0]['context_json']
        self.assertIsInstance(before, str)
        self.assertIn('9007199254740992.0', before)
        self.assertIn('9007199254740993.0', after)
        self.assertNotEqual(before, after)
        archive.publish(self.root, initial)
        with self.assertRaises(archive.ArchiveError):
            archive.publish(self.root, changed)

    def test_capture_uses_fixed_target_readonly_deadlines_and_sql(self):
        with patch.object(archive, 'bounded_command', return_value=snapshot()) as call:
            archive.capture(self.root)
        arguments = call.call_args.args[0]
        self.assertIn('fleetory-pilot-postgres-1', arguments)
        self.assertIn('999:999', arguments)
        self.assertTrue(any('default_transaction_read_only=on' in arg for arg in arguments))
        self.assertIn('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;', arguments[-1])
        self.assertNotIn('SELECT *', arguments[-1])


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.base = Path('/srv/fleetory')
        self.source = Path(archive.__file__).with_name('install-audit-archive.sh')
        self.units = Path('/etc/systemd/system')
        self.units.mkdir(mode=0o755, exist_ok=True)
        for directory in ('eng/pilot', 'infra/pilot'):
            (self.base / directory).mkdir(parents=True, mode=0o755)
        (self.base / 'eng/pilot/audit_archive.py').write_text('raise SystemExit(91)\n', encoding='utf-8')
        for suffix in ('service', 'timer'):
            (self.base / ('infra/pilot/audit-archive.' + suffix)).write_text('fixture-unit\n', encoding='utf-8')

    def tearDown(self):
        # These fixed paths belong only to this network-isolated fixture's tmpfs.
        self.assertEqual(Path('/srv/fleetory'), self.base.resolve())
        shutil.rmtree(self.base)
        for suffix in ('service', 'timer'):
            (self.units / ('fleetory-audit-archive.' + suffix)).unlink(missing_ok=True)

    def invoke(self):
        return subprocess.run(['/bin/bash', str(self.source)], capture_output=True, timeout=10).returncode

    def test_trusted_preflight_reaches_helper(self):
        self.assertEqual(91, self.invoke())

    def test_writable_ancestry_rejected_before_helper(self):
        for part in ('', 'eng', 'eng/pilot', 'infra', 'infra/pilot'):
            directory = self.base / part
            directory.chmod(0o775)
            try:
                self.assertEqual(1, self.invoke())
            finally:
                directory.chmod(0o755)

    def test_symbolic_and_foreign_owned_parent_rejected(self):
        directory = self.base / 'eng/pilot'
        real = directory.with_name('actual')
        directory.rename(real)
        directory.symlink_to(real, target_is_directory=True)
        try:
            self.assertEqual(1, self.invoke())
        finally:
            directory.unlink()
            real.rename(directory)
        os.chown(directory, 1654, 1654)
        try:
            self.assertEqual(1, self.invoke())
        finally:
            os.chown(directory, 0, 0)

    def test_insecure_or_changed_existing_unit_rejected_before_helper(self):
        target = self.units / 'fleetory-audit-archive.service'
        target.write_text('fixture-unit\n', encoding='utf-8')
        target.chmod(0o666)
        self.assertEqual(1, self.invoke())
        target.chmod(0o644)
        os.chown(target, 1654, 1654)
        self.assertEqual(1, self.invoke())
        os.chown(target, 0, 0)
        target.write_text('changed-unit\n', encoding='utf-8')
        self.assertEqual(1, self.invoke())


class NativeCommandTests(unittest.TestCase):
    def test_bounded_native_process_success_size_exit_and_timeout(self):
        result = archive.bounded_command([sys.executable, '-c', 'print("{\\"test\\":1}")'])
        self.assertEqual({'test': 1}, result)
        failures = ['import sys; sys.exit(17)', 'print("x"*200)', 'print("not-json")']
        for code in failures:
            with patch.object(archive, 'MAX_SNAPSHOT', 128):
                with self.assertRaises((archive.ArchiveError, ValueError)):
                    archive.bounded_command([sys.executable, '-c', code])
        started = time.monotonic()
        with patch.object(archive, 'COMMAND_TIMEOUT', 0.1), self.assertRaises(archive.queue.Empty):
            archive.bounded_command([sys.executable, '-c', 'import time;time.sleep(20)'])
        self.assertLess(time.monotonic() - started, 5)


if __name__ == '__main__':
    portable = '--portable' in sys.argv
    classes = [PortableExportTests] if portable else [PortableExportTests, RootArchiveTests, InstallerTests, NativeCommandTests]
    suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(value) for value in classes)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
