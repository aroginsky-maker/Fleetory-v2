"""Actual PowerShell receipt handshake on copied public components; no archives/private keys."""
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import time
import uuid
from unittest.mock import patch

from audit_native_resource_tests import policy, vector_payload, generated_pair
from native_empty_payload import public_repository, record
from native_audit_preparation import snapshot, sha, claim_plan
from private_runtime_fixture import private_git, private_powershell, windows_git_core

CASES = ('positive', 'bad-offer', 'bad-ack', 'owner-exit', 'expired-after-ack', 'bad-close')


def run(pair_factory=None, cases=CASES):
    policy.packet.require(type(cases) is tuple and cases and set(cases) <= set(CASES) and len(set(cases)) == len(cases))
    powershell = Path(shutil.which('pwsh') or '').resolve(strict=True)
    python = Path(sys.executable).resolve(strict=True)
    git = Path(shutil.which('git') or '').resolve(strict=True)
    if os.name == 'nt':
        git = windows_git_core(git)
    fixture_root = None
    with tempfile.TemporaryDirectory(prefix='fleetory-native-resource-ack-') as temp:
        root = Path(temp).resolve()
        fixture_root = root
        powershell = private_powershell(powershell, root)
        git = private_git(git, root)
        repository = public_repository(root, git, policy.SOURCES)
        measured = snapshot(powershell, root, repository)
        pins = policy.measure_sources(repository)
        control_root = root / 'control'
        control_root.mkdir(mode=0o700)
        sentinel = repository / 'artifacts/foreign-resource-sentinel'
        sentinel.mkdir()
        (sentinel / 'keep').write_bytes(b'generated foreign sentinel')
        for kind in cases:
            _, original = vector_payload()
            plan = json.loads(original)
            plan.update(nonce=str(uuid.uuid4()), revision=measured['revision'], codeSha256=measured['sha256'])
            raw, claimed = claim_plan(control_root, plan, powershell, python)
            path = repository / 'artifacts' / policy.payload.binding.payload_name(plan['nonce'])
            original_send, original_accept, original_wait = (policy._NativeResourcePumps._send,
                policy._NativeResourcePumps._accept_frame, policy._NativeResourcePumps._wait)

            def tamper(pump, data):
                value = json.loads(data)
                if ((kind == 'bad-offer' and value.get('schema') == 'fleetory.native-linked-resource-offer.v1') or
                        (kind == 'bad-close' and value.get('schema') == 'fleetory.native-empty-payload-remove.v1')):
                    value['decision'] = 'restore-private-data'
                    value['archiveBase64'] = 'GENERATED_REFUSED_BODY'
                    changed = policy.prep.canonical(value) + b'\n'
                    pump.expected_input_bytes += len(changed) - len(data)
                    data = changed
                return original_send(pump, data)

            def accept(pump, value, data):
                if kind == 'bad-ack' and value.get('schema') == 'fleetory.native-linked-resource-ack.v1':
                    value = {**value, 'containerId': 'f' * 64}
                    data = policy.prep.canonical(value)
                return original_accept(pump, value, data)

            def wait(pump, event):
                original_wait(pump, event)
                if event is pump.resource_ack:
                    if kind == 'owner-exit':
                        pump.process.kill()
                        raise ValueError('Generated owner exit after receipt ack.')
                    if kind == 'expired-after-ack':
                        pump.pair[0]._deadline = time.monotonic() - 1

            with claimed as session:
                pair = generated_pair(session) if pair_factory is None else pair_factory(session, root)
                before = {name: session._records[name][1] for name in ('image-binding.json', 'backend-binding.json')}
                with patch.object(policy._NativeResourcePumps, '_send', tamper), \
                        patch.object(policy._NativeResourcePumps, '_accept_frame', accept), patch.object(policy._NativeResourcePumps, '_wait', wait):
                    try:
                        result = policy.acknowledge_owner(repository, powershell, python, git, raw, pins, session, pair, git_sha256=sha(git))
                    except policy.process.LaunchError as error:
                        evidence = json.loads(error.evidence)
                        if kind == 'positive':
                            print('Native resource refusal: ' + str(evidence.get('payload')), file=sys.stderr)
                            raise
                        policy.packet.require(evidence['payload']['nativeOwnerResourceAcknowledged'] is False and
                            evidence['payload']['emptyPayloadRemovedVerified'] is False)
                        if kind in ('bad-offer', 'bad-ack'):
                            policy.packet.require('native-resource-ack.json' not in session._records)
                        else:
                            policy.packet.require('native-resource-ack.json' in session._records)
                        policy.packet.require(path.is_dir() and set(os.listdir(path)) == {policy.payload.binding.MARKER})
                        policy.packet.require(sha(path / policy.payload.binding.MARKER) == record(session, 'payload-binding.json')['ownerSha256'])
                    else:
                        policy.packet.require(kind == 'positive')
                        evidence = json.loads(result.evidence)
                        proof = evidence['payload']
                        policy.packet.require(all(proof[key] is True for key in ('nativeReadinessBound', 'emptyPayloadNamespaceBound',
                            'emptyPayloadRemovedVerified', 'nativeOwnerResourceAcknowledged')))
                        policy.packet.require(proof['selectedSourceFilesPinned'] == 40 and not path.exists())
                        bound = record(session, 'native-resource-ack.json')
                        intent = record(session, 'native-resource-intent.json')
                        policy.packet.require(bound['actualOwnedProcess']['pid'] == evidence['osIdentity']['pid'] == bound['acknowledgement']['pid'] and
                            bound['resourceIntentSha256'] == policy.packet.digest(session._records['native-resource-intent.json'][1]) and
                            intent['payloadBindingSha256'] == policy.packet.digest(session._records['payload-binding.json'][1]) and
                            intent['receipt'] == policy.pair_receipt(session, pair))
                        try:
                            policy.acknowledge_owner(repository, powershell, python, git, raw, pins, session, pair, git_sha256=sha(git))
                        except ValueError:
                            pass
                        else:
                            raise ValueError('Consumed native launch replay accepted.')
                policy.packet.require(evidence['launchAttemptConsumed'] is True and evidence['processIdentityAuthenticated'] is True and
                    evidence['fence']['noRunningMembersVerified'] is True)
                for key in ('privateInputsAccepted', 'backendCreated', 'backendNamespaceBound', 'originalInputsRead', 'originalPrivatePkiUsed',
                        'cleanupAuthorized', 'backendControlAuthorized', 'backendCleanupAuthorized', 'legacyApplicationImageVerified',
                        'legacyNativeOwnerIntegrated', 'dockerObservationAuthenticated', 'fullSystemRecoveryVerified', 'phase7Complete'):
                    policy.packet.require(evidence['payload'][key] is False)
                policy.packet.require(all(session._records[name][1] == data for name, data in before.items()))
                policy.packet.require((sentinel / 'keep').read_bytes() == b'generated foreign sentinel')
        policy.packet.require(policy.measure_sources(repository) == pins)
    policy.packet.require(fixture_root is not None and not fixture_root.exists())
    return dict(schema='fleetory.generated-native-resource-ack.v1', verified=True, actualOwnerCases=len(cases), cases=list(cases),
        sourceFilesHeld=40, fixtureRevisionSynthetic=True, fullApplicationSnapshotClaimed=False, copiedPublicComponentsMatched=True,
        typedImageContainerReceiptAckVerified=True, actualOwnerOsIdentityVerified=True, payloadBindingAndReadyPinsMatched=True,
        ackExclusivePublicationVerified=True, positiveEmptyReservationRemovalVerified=True, consumedLaunchReplayRefused=True,
        foreignSentinelAndSourceRecordsPreserved=True, invalidOrInterruptedAckNeverGrantsFinalAcceptance=True,
        unknownReservationPreserved=True, ownPublicFixtureDisposed=True, ownedProcessMembersAbsent=True,
        generatedReceiptMetadataOnly=True, originalInputsRead=False, originalPrivatePkiUsed=False, backendControlAuthorized=False,
        backendCleanupAuthorized=False, abruptOwnerDeathBackendCleanupVerified=False, legacyApplicationImageVerified=False,
        legacyNativeOwnerIntegrated=False, dockerObservationAuthenticated=False, fullSystemRecoveryVerified=False, phase7Complete=False)


if __name__ == '__main__':
    print('NATIVE RESOURCE ACK PASS: ' + json.dumps(run(), sort_keys=True))
