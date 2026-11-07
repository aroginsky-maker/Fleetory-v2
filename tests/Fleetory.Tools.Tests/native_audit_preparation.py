"""Actual historical PowerShell owner readiness/close/refusal. No backend or original bytes."""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import uuid
from unittest.mock import patch

from audit_native_preparation_tests import prep
from historical_audit_restore_tests import fixture
from private_runtime_fixture import private_git, private_powershell

REPO = Path(__file__).resolve().parents[2]


def sha(path):
    return prep.packet.digest(Path(path).read_bytes())


@contextmanager
def active_sdk_input():
    path = REPO / 'global.json'
    created = not path.exists()
    data = (REPO / 'eng/global.ci.json').read_bytes()
    if created:
        with path.open('xb') as stream:
            stream.write(data)
    try:
        yield
    finally:
        if created:
            prep.packet.require(path.parent == REPO and path.name == 'global.json' and path.read_bytes() == data)
            path.unlink()


def namespaces():
    root = REPO / 'artifacts'
    if not root.exists():
        return {}
    return {p.name: (p.lstat().st_dev, p.lstat().st_ino) for p in root.glob('native-audit-controller-*')}


def snapshot(powershell, directory):
    helper = directory / 'measure.ps1'
    helper.write_text("param([string]$Repository)\n$ErrorActionPreference='Stop'\n"
        "foreach($n in @('PilotNativeProcess.ps1','ProviderRecoveryPolicy.ps1','ImmuDataRoundtripPolicy.ps1','HistoricalAuditInputPins.ps1')){. (Join-Path $Repository ('eng/pilot/'+$n))}\n"
        "Get-HistoricalAuditCodeSnapshot $Repository | ConvertTo-Json -Compress\n", encoding='utf-8')
    result = subprocess.run([str(powershell), '-NoLogo', '-NoProfile', '-File', str(helper), str(REPO)], capture_output=True, timeout=30)
    prep.packet.require(result.returncode == 0 and result.stderr == b'')
    return prep.packet.strict_json(result.stdout, 4096)


def run():
    powershell = Path(shutil.which('pwsh') or '').resolve(strict=True)
    python = Path(sys.executable).resolve(strict=True)
    git = Path(shutil.which('git') or '').resolve(strict=True)
    if os.name == 'nt' and git.parent.name.lower() == 'cmd':
        git = git.parent.parent / 'mingw64/bin/git.exe'
    before = namespaces()
    with tempfile.TemporaryDirectory(prefix='fleetory-native-preparation-') as temp, active_sdk_input():
        root = Path(temp).resolve()
        powershell = private_powershell(powershell, root)
        git = private_git(git, root)
        measured = snapshot(powershell, root)
        pins = prep.measure_sources(REPO)
        git_pin = sha(git)
        shadow = root / 'shadow'
        shadow.mkdir(mode=0o700)
        shadow_git = shadow / git.name
        shadow_git.write_bytes(b'not an executable' if os.name == 'nt' else b'#!/bin/sh\nexit 93\n')
        shadow_git.chmod(0o700)

        def case(kind):
            plan, _ = fixture()
            plan.update(nonce=str(uuid.uuid4()), revision=measured['revision'], codeSha256=measured['sha256'])
            if kind == 'wrong-code':
                plan['codeSha256'] = '0' * 64
            raw = prep.canonical(plan)
            control_plan = dict(schema=prep.control.SCHEMA, purpose=prep.control.PURPOSE, nonce=plan['nonce'],
                revision=plan['revision'], nativePlanSha256=prep.packet.digest(raw), codeSha256=plan['codeSha256'],
                probeSha256=plan['probeSha256'], runtimes={'powershell': sha(powershell), 'python': sha(python)})
            encoded = prep.canonical(control_plan)
            return raw, prep.control.claim(root, encoded, prep.packet.digest(encoded))

        raw, claimed = case('wrong-git-preflight')
        with claimed as session, patch.object(prep.process, '_spawn') as spawn:
            denied = False
            try:
                prep.prepare_owner(REPO, powershell, python, git, raw, pins, session, git_sha256='0' * 64)
            except ValueError:
                denied = True
            prep.packet.require(denied and not session.report()['launchAttemptConsumed'])
            spawn.assert_not_called()
            prep.packet.require(not (session._directory.path / 'native-ready.json').exists())

        raw, claimed = case('positive')
        with claimed as session:
            environment = prep.process.environment

            def shadow_environment(*args):
                value = dict(environment(*args))
                value['PATH'] = str(shadow) + os.pathsep + value['PATH']
                return value

            try:
                with patch.object(prep.process, 'environment', side_effect=shadow_environment):
                    result = prep.prepare_owner(REPO, powershell, python, git, raw, pins, session, git_sha256=git_pin)
            except prep.process.LaunchError as error:
                stage = json.loads(error.evidence).get('payload', {}).get('refusalStage')
                if stage in ('header', 'git', 'code', 'close'):
                    print('Native readiness refusal stage=' + stage, file=sys.stderr)
                raise
            evidence = json.loads(result.evidence)
            metadata = evidence['payload']
            prep.packet.require(result.exit_code == 0 and result.stderr == b'' and evidence['processIdentityAuthenticated'] is True and
                evidence['fence']['noRunningMembersVerified'] is True and metadata['nativeReadinessBound'] is True and metadata['closeOnlyVerified'] is True and
                metadata['gitExecutablePinned'] is True and metadata['gitProcessIdentityAuthenticated'] is False)
            prep.packet.require(metadata['selectedSourceFilesPinned'] == 32 and
                all(metadata[n] is False for n in ('privateInputsAccepted', 'payloadCreated', 'backendCreated',
                    'backendNamespaceBound', 'transitiveLegacyContinuityVerified', 'gitRuntimeAuthenticated', 'originalInputsRead',
                    'cleanupAuthorized', 'fullSystemRecoveryVerified', 'phase7Complete')))
            prep.packet.require((session._directory.path / 'native-ready.json').exists() and
                (session._directory.path / 'native-close.json').exists())
            ready_fd = session._records['native-ready.json'][0]
            os.lseek(ready_fd, 0, os.SEEK_SET)
            ready = json.loads(os.read(ready_fd, prep.control.MAX_RECORD + 1))
            prep.packet.require(ready['gitExecutableSha256'] == git_pin and ready['gitExecutablePinned'] is True)
            denied = False
            try:
                prep.prepare_owner(REPO, powershell, python, git, raw, pins, session, git_sha256=git_pin)
            except ValueError:
                denied = True
            prep.packet.require(denied)

        for kind in ('wrong-code', 'private-continuation', 'wrong-git-header'):
            raw, claimed = case(kind)
            original_send = prep._PreparationPumps._send

            def tampered(pump, data):
                value = json.loads(data)
                if kind == 'wrong-git-header' and value.get('schema') == prep.SCHEMA:
                    value['gitSha256'] = '0' * 64
                if kind == 'private-continuation' and value.get('schema') == 'fleetory.native-preparation-close.v1':
                    value.update(decision='restore', archiveBase64='GENERATED_PRIVATE_INPUT_CANARY')
                if kind == 'wrong-git-header' or value.get('decision') == 'restore':
                    changed = prep.canonical(value) + b'\n'
                    pump.expected_input_bytes += len(changed) - len(data)
                    data = changed
                return original_send(pump, data)

            with claimed as session, patch.object(prep._PreparationPumps, '_send', tampered):
                denied = False
                try:
                    prep.prepare_owner(REPO, powershell, python, git, raw, pins, session, git_sha256=git_pin)
                except prep.process.LaunchError as error:
                    failure = json.loads(error.evidence)
                    prep.packet.require(failure['launchAttemptConsumed'] is True and failure['processIdentityAuthenticated'] is True and
                        failure['fence']['noRunningMembersVerified'] is True and failure['payload']['nativeReadinessBound'] is False)
                    if kind == 'wrong-git-header':
                        prep.packet.require(failure['payload']['refusalStage'] == 'git')
                    denied = True
                prep.packet.require(denied and session.report()['launchAttemptConsumed'] is True)
                prep.packet.require((session._directory.path / 'native-ready.json').exists() == (kind == 'private-continuation'))

    prep.packet.require(namespaces() == before)
    return dict(schema='fleetory.generated-native-preparation.v2', verified=True, actualOwnerCases=4, positiveCloseOnlyCases=1,
        typedNativeRefusals=3, preSpawnGitRefusals=1, gitExecutablePinned=True, absoluteGitWithPathShadowVerified=True,
        wrongGitHeaderRefused=True, gitProcessIdentityAuthenticated=False, consumedLaunchReplayRefused=True, selectedSourceFilesPinned=32, actualOwnerIdentityVerified=True,
        ownedProcessMembersAbsent=True, heldReadyAndCloseRecordsVerified=True, wrongCodeRefused=True,
        privateContinuationRefused=True, legacyPayloadNamespacesUnchanged=True, privateInputsAccepted=False,
        backendCreated=False, originalInputsRead=False, originalPrivatePkiUsed=False, fullLegacyExecutionContinuityVerified=False,
        backendNamespaceBound=False, abruptOwnerDeathBackendCleanupVerified=False, fullSystemRecoveryVerified=False, phase7Complete=False)


if __name__ == '__main__':
    print('NATIVE PREPARATION PASS: ' + json.dumps(run(), sort_keys=True))
