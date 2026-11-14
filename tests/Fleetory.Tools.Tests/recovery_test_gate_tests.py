"""Execute the actual workflow blocks with native child failures, never real recovery inputs."""
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[2]
SUITES = ('recovery_files_tests.py', 'recovery_composition_tests.py', 'server_data_inputs_tests.py')


def workflow_block(name):
    lines = (REPO / '.github' / 'workflows' / 'quality.yml').read_text(encoding='utf-8').splitlines()
    start = lines.index('      - name: ' + name)
    assert lines[start + 1:start + 3] == ['        shell: pwsh', '        run: |']
    result = []
    for line in lines[start + 3:]:
        if not line.startswith('          '):
            break
        result.append(line[10:])
    return '\n'.join(result)


def execute(block, failures):
    executable = shutil.which('pwsh')
    if executable is None:
        raise RuntimeError('PowerShell 7 must be available for the native exit gate test.')
    with tempfile.TemporaryDirectory(prefix='fleetory-recovery-exit-') as directory:
        root = Path(directory)
        target = root / 'tests' / 'Fleetory.Tools.Tests'
        target.mkdir(parents=True)
        for index, name in enumerate(SUITES):
            source = 'from pathlib import Path\nimport sys\nPath(' + json.dumps(f'{index}.seen') + ').write_text("seen")\n'
            source += 'sys.exit(' + str(failures[index]) + ')\n'
            (target / name).write_text(source, encoding='utf-8')
        # Keep the workflow's complete control flow. Replace only interpreter lookup
        # so Windows Store aliases cannot affect this fixture; use literal PS quoting.
        interpreter = "'" + sys.executable.replace("'", "''") + "'"
        script = re.sub(r'(?m)^python3? -B ', lambda _: '& ' + interpreter + ' -B ', block)
        script = "$ErrorActionPreference='Stop'\n$PSNativeCommandUseErrorActionPreference=$false\n" + script
        script += '\nif (Test-Path -LiteralPath variable:\\LASTEXITCODE) { exit $LASTEXITCODE }'
        process = subprocess.run([executable, '-NoLogo', '-NoProfile', '-NonInteractive', '-Command', script],
                                 cwd=root, capture_output=True, timeout=15)
        return process.returncode, sorted(path.name for path in root.glob('*.seen'))


class RecoveryNativeExitGateTests(unittest.TestCase):
    def assert_block(self, name):
        block = workflow_block(name)
        self.assertEqual(len(re.findall(r'(?m)^python3? -B ', block)), 3)
        for failed in (None, 0, 1, 2):
            failures = [0, 0, 0]
            if failed is not None:
                failures[failed] = 7 + failed
            with self.subTest(block=name, failed=failed):
                code, seen = execute(block, failures)
                self.assertEqual(code, 0 if failed is None else failures[failed])
                count = 3 if failed is None else failed + 1
                self.assertEqual(seen, [f'{index}.seen' for index in range(count)])

    def test_windows_workflow_stops_after_first_middle_or_last_native_failure(self):
        self.assert_block('Verify pinned recovery files on Windows')

    def test_linux_workflow_stops_after_first_middle_or_last_native_failure(self):
        self.assert_block('Verify pinned recovery files')

    def test_prior_unguarded_sequence_masks_first_failure(self):
        block = workflow_block('Verify pinned recovery files on Windows')
        unguarded = '\n'.join(line for line in block.splitlines() if not line.startswith('if ($LASTEXITCODE'))
        code, seen = execute(unguarded, [7, 0, 0])
        self.assertEqual(code, 0)
        self.assertEqual(seen, ['0.seen', '1.seen', '2.seen'])


if __name__ == '__main__':
    unittest.main()
