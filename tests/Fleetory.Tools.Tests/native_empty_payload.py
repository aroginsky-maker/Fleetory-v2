"""Actual native empty reservation on copied public components; no project backup/data."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import uuid
from unittest.mock import patch

from audit_native_payload_tests import policy, vector_payload, REPO
from native_audit_preparation import snapshot, sha, claim_plan
from private_runtime_fixture import private_git, private_powershell, windows_git_core


def public_repository(root, git):
    repository = root / 'repository'
    repository.mkdir(mode=0o700)
    for name in policy.SOURCES:
        source = REPO / name
        if name == 'global.json' and not source.exists():
            source = REPO / 'eng/global.ci.json'
        data = source.read_bytes()
        policy.packet.require(0 < len(data) <= 512 * 1024)
        target = repository / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        policy.packet.require(target.read_bytes() == data)
    (repository / 'src').mkdir()
    (repository / 'src/Fixture.cs').write_text('// Generated public fixture; never compiled.\n')
    (repository / 'artifacts').mkdir(mode=0o700)
    templates = root / 'empty-templates'
    templates.mkdir()
    args = [str(git), '-c', 'user.name=Generated fixture', '-c', 'user.email=fixture@example.invalid',
        '-c', 'commit.gpgsign=false', '-c', 'core.hooksPath=' + str(templates)]
    for command in (['init', '--quiet', '--template=' + str(templates), str(repository)],
            ['-C', str(repository), 'config', 'core.autocrlf', 'false'],
            ['-C', str(repository), 'add', '--all'],
            ['-C', str(repository), 'commit', '--quiet', '-m', 'Generated public native metadata fixture']):
        result = subprocess.run(args + command, capture_output=True, timeout=20)
        policy.packet.require(result.returncode == 0)
    return repository


def record(session, name):
    fd = session._records[name][0]
    os.lseek(fd, 0, os.SEEK_SET)
    return json.loads(os.read(fd, policy.control.MAX_RECORD + 1))


def run():
    powershell = Path(shutil.which('pwsh') or '').resolve(strict=True)
    python = Path(sys.executable).resolve(strict=True)
    git = Path(shutil.which('git') or '').resolve(strict=True)
    if os.name == 'nt':
        git = windows_git_core(git)
    fixture_root = None
    with tempfile.TemporaryDirectory(prefix='fleetory-native-empty-payload-') as temp:
        root = Path(temp).resolve()
        fixture_root = root
        powershell = private_powershell(powershell, root)
        git = private_git(git, root)
        repository = public_repository(root, git)
        measured = snapshot(powershell, root, repository)
        pins = policy.measure_sources(repository)
        control_root = root / 'control'
        control_root.mkdir(mode=0o700)
        sentinel = repository / 'artifacts/foreign-sentinel'
        sentinel.mkdir()
        (sentinel / 'keep').write_bytes(b'generated foreign metadata')
        for kind in ('positive', 'bad-authorization', 'foreign-namespace', 'bad-close', 'trailing-close', 'owner-exit'):
            _, original = vector_payload()
            plan = json.loads(original)
            plan.update(nonce=str(uuid.uuid4()), revision=measured['revision'], codeSha256=measured['sha256'])
            raw, claimed = claim_plan(control_root, plan, powershell, python)
            path = repository / 'artifacts' / policy.binding.payload_name(plan['nonce'])
            if kind == 'foreign-namespace':
                path.mkdir()
                (path / 'foreign').write_bytes(b'generated foreign namespace')
            original_send, original_wait = policy._NativePayloadPumps._send, policy._NativePayloadPumps._wait

            def tamper(pump, data):
                value = json.loads(data)
                if kind == 'trailing-close' and value.get('schema') == 'fleetory.native-empty-payload-remove.v1':
                    data += b'GENERATED_TRAILING_BYTES'
                    pump.expected_input_bytes += len(b'GENERATED_TRAILING_BYTES')
                if ((kind == 'bad-authorization' and value.get('schema') == 'fleetory.native-empty-payload-authorize.v1') or
                        (kind == 'bad-close' and value.get('schema') == 'fleetory.native-empty-payload-remove.v1')):
                    value.update(decision='restore', archiveBase64='GENERATED_PRIVATE_BODY_REFUSED')
                    changed = policy.prep.canonical(value) + b'\n'
                    pump.expected_input_bytes += len(changed) - len(data)
                    data = changed
                return original_send(pump, data)

            def wait(pump, event):
                original_wait(pump, event)
                if kind == 'owner-exit' and event is pump.payload_ready:
                    pump.process.kill()
                    raise ValueError('Generated owner exit after empty binding.')

            with claimed as session, \
                    patch.object(policy._NativePayloadPumps, '_send', tamper), patch.object(policy._NativePayloadPumps, '_wait', wait):
                try:
                    result = policy.reserve_owner(repository, powershell, python, git, raw, pins, session, git_sha256=sha(git))
                except policy.process.LaunchError as error:
                    if kind == 'positive':
                        print('Native empty payload refusal stage=' + str((json.loads(error.evidence).get('payload') or {}).get('refusalStage')), file=sys.stderr)
                        raise
                    evidence = json.loads(error.evidence)
                    policy.packet.require(evidence['launchAttemptConsumed'] is True and evidence['processIdentityAuthenticated'] is True and
                        evidence['fence']['noRunningMembersVerified'] is True and evidence['payload']['emptyPayloadRemovedVerified'] is False)
                    policy.packet.require('payload-binding.json' in session._records if kind in ('bad-close', 'trailing-close', 'owner-exit') else
                        'payload-binding.json' not in session._records)
                else:
                    policy.packet.require(kind == 'positive')
                    evidence = json.loads(result.evidence)
                    proof = evidence['payload']
                    policy.packet.require(evidence['fence']['noRunningMembersVerified'] is True and
                        all(proof[key] is True for key in ('nativeReadinessBound', 'emptyPayloadNamespaceBound', 'emptyPayloadRemovedVerified')))
                    policy.packet.require(proof['selectedSourceFilesPinned'] == 34 and not path.exists())
                    bound = record(session, 'payload-binding.json')
                    policy.packet.require(bound['actualOwnedProcess']['pid'] == evidence['osIdentity']['pid'])
                    for name in ('native-ready.json', 'native-payload-intent.json', 'payload-binding.json', 'payload-release.json', 'native-close.json'):
                        policy.packet.require(name in session._records)
                    intent = record(session, 'native-payload-intent.json')
                    policy.packet.require(intent['privateInputReleaseAuthorized'] is False and intent['backendCreationAuthorized'] is False)
                    denied = False
                    try:
                        policy.reserve_owner(repository, powershell, python, git, raw, pins, session, git_sha256=sha(git))
                    except ValueError:
                        denied = True
                    policy.packet.require(denied)
                for key in ('privateInputsAccepted', 'backendCreated', 'backendNamespaceBound', 'originalInputsRead',
                        'originalPrivatePkiUsed', 'cleanupAuthorized', 'fullLegacyExecutionContinuityVerified', 'fullSystemRecoveryVerified', 'phase7Complete'):
                    policy.packet.require(evidence['payload'][key] is False)
                if kind == 'bad-authorization':
                    policy.packet.require(not path.exists())
                if kind == 'foreign-namespace':
                    policy.packet.require((path / 'foreign').read_bytes() == b'generated foreign namespace')
                if kind in ('bad-close', 'trailing-close', 'owner-exit'):
                    policy.packet.require(path.is_dir() and set(os.listdir(path)) == {policy.binding.MARKER})
                    policy.packet.require(sha(path / policy.binding.MARKER) == record(session, 'payload-binding.json')['ownerSha256'])
                policy.packet.require((sentinel / 'keep').read_bytes() == b'generated foreign metadata')
        policy.packet.require(policy.measure_sources(repository) == pins)
    policy.packet.require(fixture_root is not None and not fixture_root.exists())
    return dict(schema='fleetory.generated-native-empty-payload.v1', verified=True, actualOwnerCases=6,
        positiveEmptyReservationAndRemoval=1, typedOrOwnerExitRefusals=5, sourceFilesHeld=34,
        copiedPublicComponentsMatched=True, fixtureRevisionSynthetic=True, fullApplicationSnapshotClaimed=False,
        directNativeParentDelegationVerified=True, actualOwnerOsIdentityVerified=True, heldControlRecordsVerified=True,
        originalHeldDirectoryRemovalVerified=True, consumedLaunchReplayRefused=True, privateAuthorizationRefused=True,
        foreignNamespaceAndSentinelPreserved=True, invalidCloseLeavesUnknownReservation=True, trailingInputBeforeRemovalRefused=True,
        ownerExitLeavesUnknownReservation=True, ownedProcessMembersAbsent=True, ownPublicFixtureDisposed=True,
        privateInputsAccepted=False, backendCreated=False, originalInputsRead=False, originalPrivatePkiUsed=False,
        backendNamespaceBound=False, abruptOwnerDeathBackendCleanupVerified=False, fullLegacyExecutionContinuityVerified=False,
        fullSystemRecoveryVerified=False, phase7Complete=False)


if __name__ == '__main__':
    print('NATIVE EMPTY PAYLOAD PASS: ' + json.dumps(run(), sort_keys=True))
