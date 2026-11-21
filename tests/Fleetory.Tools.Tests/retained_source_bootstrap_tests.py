"""Exercise the fixed bootstrap with real generated source and stale caches."""
from pathlib import Path
import os
import py_compile
import subprocess
import sys
import tempfile
import unittest

PILOT = Path(__file__).resolve().parents[2]/'eng/pilot'
BOOTSTRAP = PILOT/'historical/retained_source_bootstrap.py'
TARGETS = {'peer':'historical/retained_service_peer.py',
           'catalog':'historical/retained_code_catalog.py',
           'inventory':'pg_inventory_v2.py', 'observation':'audit_observation.py',
           'historical-observation':'historical_audit_observation.py'}


class SourceBootstrapTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='fleetory-source-bootstrap-')
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.pilot = self.root/'eng/pilot'
        self.wrapper = self.pilot/'historical/retained_source_bootstrap.py'
        self.wrapper.parent.mkdir(parents=True)
        self.wrapper.write_bytes(BOOTSTRAP.read_bytes())
        for relative in TARGETS.values():
            target = self.pilot/relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text('from public_cache_probe import VALUE\nprint(VALUE)\n')

    def cached(self, relative='public_cache_probe.py', kind='TIMESTAMP'):
        source = self.pilot/relative
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_bytes(b"VALUE='cachedx'\n")
        stamp = source.stat()
        cache = Path(py_compile.compile(str(source), doraise=True,
                     invalidation_mode=getattr(py_compile.PycInvalidationMode,kind)))
        source.write_bytes(b"VALUE='sourcex'\n")
        os.utime(source, ns=(stamp.st_atime_ns,stamp.st_mtime_ns))
        return source,cache

    def run_entry(self, key='catalog', *args, isolated=True):
        return subprocess.run([sys.executable,*(['-I','-S','-B'] if isolated else ['-B']),
                               str(self.wrapper),key,*args],capture_output=True,
                              cwd=self.root,timeout=15)

    def source_only(self, kind):
        self.cached(kind=kind)
        result=self.run_entry()
        self.assertEqual(0,result.returncode,result.stderr)
        self.assertEqual(b'sourcex',result.stdout.strip())

    def test_timestamp_valid_cache(self):self.source_only('TIMESTAMP')
    def test_checked_hash_cache(self):self.source_only('CHECKED_HASH')
    def test_unchecked_hash_cache(self):self.source_only('UNCHECKED_HASH')

    def test_control_proves_isolation_flags_still_consume_cache(self):
        self.cached()
        command='import sys;sys.path.insert(0,sys.argv[1]);import public_cache_probe;print(public_cache_probe.VALUE)'
        result=subprocess.run([sys.executable,'-I','-S','-B','-c',command,str(self.pilot)],
                              capture_output=True,timeout=15)
        self.assertEqual(0,result.returncode,result.stderr)
        self.assertEqual(b'cachedx',result.stdout.strip())

    def test_all_five_literal_entries_compile_source(self):
        self.cached()
        for key in TARGETS:
            with self.subTest(key=key):
                result=self.run_entry(key)
                self.assertEqual(0,result.returncode,result.stderr)
                self.assertEqual(b'sourcex',result.stdout.strip())

    def test_package_relative_import_ignores_cache(self):
        self.cached('public_cache_probe/leaf.py')
        (self.pilot/'public_cache_probe/__init__.py').write_text('from .leaf import VALUE\n')
        result=self.run_entry()
        self.assertEqual(0,result.returncode,result.stderr)
        self.assertEqual(b'sourcex',result.stdout.strip())

    def test_sourceless_legacy_cache_refused(self):
        source,cache=self.cached()
        source.with_suffix('.pyc').write_bytes(cache.read_bytes())
        source.unlink()
        result=self.run_entry()
        self.assertEqual(1,result.returncode)
        self.assertEqual(b'',result.stdout)
        self.assertEqual(b'Retained source bootstrap refused; no contents logged.',result.stderr.strip())

    def test_entry_cannot_select_arbitrary_path(self):
        for key in ('../other.py',str(self.root/'other.py'),'catalog/../peer',''):
            with self.subTest(key=key):
                result=self.run_entry(key)
                self.assertEqual(1,result.returncode)
                self.assertEqual(b'',result.stdout)

    def test_missing_isolation_refused(self):
        self.cached()
        result=self.run_entry(isolated=False)
        self.assertEqual(1,result.returncode)
        self.assertEqual(b'',result.stdout)

    def test_entry_has_real_main_module_identity(self):
        (self.pilot/TARGETS['catalog']).write_text('import sys\nprint(sys.modules[__name__].__dict__ is globals())\n')
        result=self.run_entry()
        self.assertEqual(0,result.returncode,result.stderr)
        self.assertEqual(b'True',result.stdout.strip())

    def test_actual_inventory_entry_works(self):
        result=subprocess.run([sys.executable,'-I','-S','-B',str(BOOTSTRAP),
                               'inventory','sql','--database','fleetory'],
                              capture_output=True,timeout=15)
        self.assertEqual(0,result.returncode,result.stderr)
        self.assertGreater(len(result.stdout),100)
        self.assertEqual(b'',result.stderr)


if __name__=='__main__':unittest.main()
