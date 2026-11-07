"""Keep every native recovery gate when independent fixture jobs are rearranged."""
from pathlib import Path
from collections import Counter
import json
import os
import re
import shutil
import subprocess
import unittest

WORKFLOW = Path(__file__).resolve().parents[2] / '.github/workflows/quality.yml'
DATA = (
    ('NativeServerBackend.Tests.ps1', ''), ('NativePgDataRoundtrip.Tests.ps1', ''),
    ('NativePgInventoryV2.Tests.ps1', ''), ('NativeImmuDataRoundtrip.Tests.ps1', ''),
    ('NativeAuditHistory.Tests.ps1', ''), ('NativeAuditHistory.Tests.ps1', '-Profile observation'),
    ('NativeAuditHistory.Tests.ps1', '-Profile historical-observation'),
    ('NativeAuditHistory.Tests.ps1', '-Profile historical-controller'),
    ('NativeServerPair.Tests.ps1', ''), ('NativeServerPair.Tests.ps1', '-Profile v2'))
PROVIDER = tuple((name, '') for name in ('PilotProvisioning.Tests.ps1', 'IdentityBackup.Tests.ps1',
    'OpenBaoRaftRecovery.Tests.ps1', 'NativeSignerBackend.Tests.ps1', 'NativeJournalBackend.Tests.ps1'))


def jobs(text):
    text = text.split('jobs:\n', 1)[1]
    matches = list(re.finditer(r'^  ([a-z][a-z-]+):\s*$', text, re.MULTILINE))
    return {m[1]: text[m.start():matches[i + 1].start() if i + 1 < len(matches) else len(text)] for i, m in enumerate(matches)}


def validate(text):
    blocks = jobs(text)
    assert set(blocks) == {'windows-tls-chain', 'quality', 'native-data-recovery', 'native-provider-recovery', 'quality-gate'}
    expected = Counter(name for name, _ in DATA + PROVIDER)
    found = Counter(re.findall(r'\./tests/Fleetory.Tools.Tests/([A-Za-z0-9]+\.Tests\.ps1)', text))
    assert all(found[name] == count for name, count in expected.items())
    for key, cases, minutes in (('native-data-recovery', DATA, 20), ('native-provider-recovery', PROVIDER, 15)):
        block = blocks[key]
        assert '    runs-on: ubuntu-24.04\n' in block and f'    timeout-minutes: {minutes}\n' in block
        assert not re.search(r'^\s*(if:|needs:|continue-on-error:|SONAR_|env:)', block, re.MULTILINE)
        for action in ('actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803', 'actions/setup-dotnet@a98b56852c35b8e3190ac28c8c2271da59106c68'):
            assert action in block
        assert 'Copy-Item -LiteralPath eng/global.ci.json -Destination global.json' in block
        assert 'dotnet tool restore\n' in block
        assert 'dotnet restore Fleetory.sln --force -warnaserror -p:FleetoryRequireDependencyAudit=true -p:NuGetAudit=true -p:NuGetAuditMode=all -p:NuGetAuditLevel=low -p:RestoreUseStaticGraphEvaluation=false\n' in block
        assert 'dotnet build Fleetory.sln -c Release --no-restore --disable-build-servers --warnaserror\n' in block
        bootstrap = block.split('      - name: Verify ', 1)[0]
        assert bootstrap.count('if ($LASTEXITCODE -ne 0)') == 3
        commands = re.findall(r'^\s*(?:run: )?(\./tests/Fleetory.Tools.Tests/[^\n]+)', block, re.MULTILINE)
        for name, profile in cases:
            prefix = './tests/Fleetory.Tools.Tests/' + name + (' ' + profile if profile else '')
            matches = [line for line in commands if line == prefix or line.startswith(prefix + ' -Python ')]
            assert len(matches) == 1, (key, name, profile)
        assert len(commands) == len(cases)
    for key, platform, executable in (('windows-tls-chain', ' on Windows', 'python'), ('quality', '', 'python3')):
        for title, filename in (('held audit control namespace identity', 'audit_control_identity_tests.py'),
                ('owned process identity and lifetime fence', 'audit_process_fence_tests.py'),
                ('pinned payload reservation and controller binding', 'audit_payload_launch_tests.py')):
            step = ('      - name: Verify ' + title + platform + '\n'
                '        shell: pwsh\n'
                '        run: ' + executable + ' -B ./tests/Fleetory.Tools.Tests/' + filename + '\n')
            block = blocks[key]
            assert block.count(step) == 1
            start = block.index(step)
            end = block.find('      - name:', start + len(step))
            assert block[start:end if end >= 0 else len(block)].strip() == step.strip()
        step = ('      - name: Verify historical application input snapshots' + platform + '\n'
            '        shell: pwsh\n'
            '        run: ./tests/Fleetory.Tools.Tests/HistoricalAuditInputPins.Tests.ps1\n')
        block = blocks[key]
        assert block.count(step) == 1
        start = block.index(step)
        end = block.find('      - name:', start + len(step))
        assert block[start:end if end >= 0 else len(block)].strip() == step.strip()
    for command in ('./eng/verify-quality.ps1', './eng/verify-sonar-issues.ps1', './eng/report-sonar-metrics.ps1'):
        assert text.count(command) == 1 and command in blocks['quality']
    assert '    timeout-minutes: 30\n' in blocks['quality']
    assert '    timeout-minutes: 15\n' in blocks['windows-tls-chain']
    aggregate = blocks['quality-gate']
    assert '    name: Strict build, tests, coverage and Sonar\n' in aggregate
    assert '    needs: [quality, windows-tls-chain, native-data-recovery, native-provider-recovery]\n' in aggregate
    assert '    if: always()\n' in aggregate and 'continue-on-error:' not in aggregate
    assert '    name: Strict build, tests, coverage and Sonar execution\n' in blocks['quality']
    return True


class RecoveryCiLayoutTests(unittest.TestCase):
    def setUp(self):
        self.text = WORKFLOW.read_text(encoding='utf-8')

    def refused(self, text):
        with self.assertRaises(AssertionError):
            validate(text)

    def test_all_existing_gates_are_partitioned_with_strict_bootstrap(self):
        self.assertTrue(validate(self.text))

    def test_missing_duplicated_or_changed_native_command_refused(self):
        for name, profile in DATA + PROVIDER:
            needle = './tests/Fleetory.Tools.Tests/' + name + (' ' + profile if profile else '')
            self.refused(self.text.replace(needle, './tests/Fleetory.Tools.Tests/omitted.ps1', 1))
        self.refused(self.text + '\n      - name: Duplicate\n        run: ./tests/Fleetory.Tools.Tests/NativeJournalBackend.Tests.ps1\n')

    def test_skip_or_soft_failure_does_not_hide_a_required_job(self):
        for inserted in ('    if: false\n', '    continue-on-error: true\n', '    needs: quality\n'):
            self.refused(self.text.replace('  native-data-recovery:\n', '  native-data-recovery:\n' + inserted))

    def test_missing_audit_tools_build_or_native_exit_guard_refused(self):
        for old in ('dotnet tool restore', '-p:NuGetAuditLevel=low', ' --warnaserror\n', 'if ($LASTEXITCODE -ne 0)'):
            start = self.text.index('  native-provider-recovery:')
            self.refused(self.text[:start] + self.text[start:].replace(old, 'removed', 1))

    def test_deadlines_or_sonar_ownership_cannot_change_silently(self):
        self.refused(self.text.replace('timeout-minutes: 30', 'timeout-minutes: 60'))
        self.refused(self.text.replace('./eng/verify-sonar-issues.ps1', './eng/omitted.ps1'))
        self.refused(self.text.replace('  native-data-recovery:\n', '  native-data-recovery:\n    env:\n      SONAR_TOKEN: copied\n'))

    def test_control_identity_gate_is_required_once_and_cannot_be_softened(self):
        for executable in ('python', 'python3'):
            command = executable + ' -B ./tests/Fleetory.Tools.Tests/audit_control_identity_tests.py'
            self.refused(self.text.replace(command, 'omitted', 1))
            self.refused(self.text.replace(command, command + '\n          ' + command, 1))
            self.refused(self.text.replace('run: ' + command, 'continue-on-error: true\n        run: ' + command, 1))

    def test_process_fence_gate_is_required_once_and_cannot_be_softened(self):
        for executable in ('python', 'python3'):
            command = executable + ' -B ./tests/Fleetory.Tools.Tests/audit_process_fence_tests.py'
            self.refused(self.text.replace(command, 'omitted', 1))
            self.refused(self.text.replace(command, command + '\n          ' + command, 1))
            self.refused(self.text.replace('run: ' + command, 'continue-on-error: true\n        run: ' + command, 1))

    def test_payload_binding_gate_is_required_once_and_cannot_be_softened(self):
        for executable in ('python', 'python3'):
            command = executable + ' -B ./tests/Fleetory.Tools.Tests/audit_payload_launch_tests.py'
            self.refused(self.text.replace(command, 'omitted', 1))
            self.refused(self.text.replace(command, command + '\n          ' + command, 1))
            self.refused(self.text.replace('run: ' + command, 'continue-on-error: true\n        run: ' + command, 1))

    def test_application_input_gate_is_required_on_both_platforms(self):
        command = './tests/Fleetory.Tools.Tests/HistoricalAuditInputPins.Tests.ps1'
        for offset in (0, self.text.index('  quality:')):
            prefix, tail = self.text[:offset], self.text[offset:]
            self.refused(prefix + tail.replace(command, 'omitted', 1))
            self.refused(prefix + tail.replace(command, command + '\n          ' + command, 1))
            self.refused(prefix + tail.replace('run: ' + command, 'continue-on-error: true\n        run: ' + command, 1))

    def test_actual_aggregate_rejects_failed_cancelled_skipped_or_missing_jobs(self):
        block = jobs(self.text)['quality-gate']
        self.refused(self.text.replace('    if: always()\n', ''))
        script = '\n'.join(line[10:] for line in block.split('        run: |\n', 1)[1].splitlines())
        executable = shutil.which('pwsh')
        self.assertIsNotNone(executable)
        names = ('quality', 'windows-tls-chain', 'native-data-recovery', 'native-provider-recovery')
        success = {name: {'result': 'success', 'outputs': {}} for name in names}
        cases = [(success, True), ({}, False), ({**success, 'extra': {'result': 'success'}}, False)]
        for name in names:
            for result in ('failure', 'cancelled', 'skipped', None):
                cases.append(({**success, name: {'result': result}}, False))
            cases.append(({key: value for key, value in success.items() if key != name}, False))
        for value, accepted in cases:
            env = dict(os.environ, FLEETORY_GATE_RESULTS=json.dumps(value))
            run = subprocess.run([executable, '-NoProfile', '-Command', script], env=env, capture_output=True, timeout=10)
            self.assertEqual(run.returncode == 0, accepted)


if __name__ == '__main__':
    unittest.main()
