"""Retained native work ignores ambient Python bootstrap before input handling."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[2]
PILOT = REPO / 'eng/pilot'


class PythonIsolationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='fleetory-python-isolation-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.marker = self.root / 'ambient-bootstrap-ran'
        (self.root / 'sitecustomize.py').write_text(
            'from pathlib import Path\nPath(' + repr(str(self.marker)) + ').write_text("injected")\n',
            encoding='utf-8')
        self.env = dict(os.environ, PYTHONPATH=str(self.root))

    def run_python(self, args, body=b'{}', home=False):
        env = dict(self.env)
        if home:
            env['PYTHONHOME'] = str(self.root / 'not-a-python-runtime')
        return subprocess.run([sys.executable, *args], input=body, capture_output=True,
                              cwd=self.root, env=env, timeout=15)

    def test_control_confirms_ambient_site_hook_is_executable(self):
        value = self.run_python(['-B', '-c', 'pass'])
        self.assertEqual(0, value.returncode)
        self.assertTrue(self.marker.is_file())

    def test_peer_preparation_refuses_metadata_without_ambient_bootstrap(self):
        value = self.run_python(['-I', '-S', '-B', str(PILOT/'historical/retained_source_bootstrap.py'), 'peer', '--prepare'], home=True)
        self.assertEqual(1, value.returncode)
        self.assertEqual(b'Retained service peer refused; no input contents logged.\n', value.stderr.replace(b'\r\n', b'\n'))
        self.assertFalse(self.marker.exists())

    def test_inventory_sql_works_without_cwd_site_or_pythonhome(self):
        value = self.run_python(['-I', '-S', '-B', str(PILOT/'historical/retained_source_bootstrap.py'), 'inventory', 'sql', '--database', 'fleetory'], home=True)
        self.assertEqual(0, value.returncode)
        self.assertGreater(len(value.stdout), 100)
        self.assertEqual(b'', value.stderr)
        self.assertFalse(self.marker.exists())

    def test_both_observation_entries_remain_closed_on_invalid_input(self):
        for entry, extra in (('observation', []), ('historical-observation', ['build'])):
            with self.subTest(entry=entry):
                value = self.run_python(['-I', '-S', '-B', str(PILOT/'historical/retained_source_bootstrap.py'), entry, *extra], home=True)
                self.assertEqual(1, value.returncode)
                self.assertNotIn(b'ModuleNotFoundError', value.stderr)
                self.assertNotIn(b'Traceback', value.stderr)
                self.assertFalse(self.marker.exists())

    def test_retained_launch_sites_require_isolated_no_site_prefix(self):
        for name in ('RetainedServiceUseTransport.ps1', 'RetainedPostgresTarget.ps1',
                     'RetainedCoupledAudit.ps1', 'RetainedServerStage.ps1'):
            with self.subTest(name=name):
                text = (PILOT/'historical'/name).read_text(encoding='utf-8')
                self.assertIn("@('-I','-S','-B',", text)
                self.assertIn("retained_source_bootstrap.py", text)
                self.assertNotIn("@('-B',", text)


if __name__ == '__main__':
    unittest.main()
