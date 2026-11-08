"""Actual historical PowerShell publishes only the public probe under its OS lifetime fence."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import uuid
from unittest.mock import patch

from native_audit_preparation import active_sdk_input,claim_plan,sha,REPO
from native_probe_image import publication
from historical_audit_restore_tests import fixture
from private_runtime_fixture import private_git,private_powershell,windows_git_core
import audit_native_publication as policy

C,H=policy.prep.canonical,policy.packet.digest


def wrong_manifest(raw):
    value=json.loads(raw)
    for entry in value['entries']:
        if entry['path']=='ServerBackendProbe.dll':entry['sha256']='b'*64
    lines=b'fleetory.historical.probe-bundle.v1\n'
    for entry in value['entries']:
        lines+=(entry['kind']+':'+entry['path']+'\n'+str(entry['bytes'])+'\n'+entry['sha256']+'\n').encode('ascii')
    value['sha256']=H(lines)
    return C(value)


def dispose_namespace(nonce,ready,owner_pid):
    path=REPO/'artifacts'/policy.ns.name(nonce)
    if not path.exists():return False
    policy.packet.require(path.parent==REPO/'artifacts' and path.name==policy.ns.name(nonce))
    with policy.control.DirectoryLease(path) as directory:
        policy.packet.require(set(os.listdir(path))=={policy.ns.MARKER,policy.ns.OUTPUT})
        marker=json.loads((path/policy.ns.MARKER).read_bytes())
        policy.packet.require(type(owner_pid) is int and marker['ownerPid']==owner_pid and marker['nonce']==nonce and
            marker['namespaceDirectorySha256']==policy.ns.empty.directory_hash(directory))
        if ready is not None:policy.packet.require(H((path/policy.ns.MARKER).read_bytes())==ready['ownerSha256'])
        policy.ns.bundle.tree(path/policy.ns.OUTPUT)
    shutil.rmtree(path)
    policy.packet.require(not path.exists());return True


def restore_public(dotnet):
    # The repository config defines auditSources, not packageSources. Name the public package feed explicitly.
    restored=subprocess.run([str(dotnet),'restore',str(REPO/'eng/ServerBackendProbe/ServerBackendProbe.csproj'),
        '--disable-parallel','--configfile',str(REPO/'NuGet.Config'),'--source','https://api.nuget.org/v3/index.json',
        '--verbosity','quiet'],cwd=REPO,capture_output=True,timeout=180)
    policy.packet.require(len(restored.stdout)<=262144 and len(restored.stderr)<=4096)
    if restored.returncode!=0:
        import re
        codes=sorted(set(re.findall(rb'\b(?:NU|MSB|NETSDK)[0-9]+\b',restored.stdout+restored.stderr)))
        raise RuntimeError('Public restore refused; exit='+str(restored.returncode)+'; codes='+','.join(c.decode('ascii') for c in codes))


def run():
    powershell=Path(shutil.which('pwsh') or '').resolve(strict=True)
    python=Path(sys.executable).resolve(strict=True);git=Path(shutil.which('git') or '').resolve(strict=True)
    dotnet=Path(shutil.which('dotnet') or '').resolve(strict=True)
    if os.name=='nt':git=windows_git_core(git)
    with tempfile.TemporaryDirectory(prefix='fleetory-native-publication-') as temp,active_sdk_input():
        root=Path(temp).resolve();powershell=private_powershell(powershell,root);git=private_git(git,root)
        public=root/'reference';public.mkdir()
        if not (REPO/'eng/ServerBackendProbe/obj/project.assets.json').exists():
            restore_public(dotnet)
        published=publication(public)
        policy.packet.require(published['sdkVersion']==policy.SDK and published['dotnetSha256']==sha(dotnet))
        (REPO/'artifacts').mkdir(exist_ok=True)
        before={p.name:(p.lstat().st_dev,p.lstat().st_ino) for p in (REPO/'artifacts').glob('native-probe-publication-*')}
        pins=policy.measure_sources(REPO);manifest=C(published['bundle']);outcomes=[]
        for kind in ('positive','wrong-code','wrong-dotnet-header','private-continuation','wrong-manifest'):
            plan,_=fixture();plan.update(nonce=str(uuid.uuid4()),revision=published['source']['revision'],codeSha256=published['source']['sha256'],
                probeBundleSha256=published['bundle']['sha256'],
                probeSha256=next(e['sha256'] for e in published['bundle']['entries'] if e['path']=='ServerBackendProbe.dll'))
            expected=wrong_manifest(manifest) if kind=='wrong-manifest' else manifest
            if kind=='wrong-manifest':
                plan.update(probeBundleSha256=json.loads(expected)['sha256'],probeSha256='b'*64)
            if kind=='wrong-code':plan['codeSha256']='0'*64
            raw,claimed=claim_plan(root,plan,powershell,python)
            original=policy._NativePublicationPumps._send;injected=[]
            def send(pump,data):
                value=json.loads(data)
                if kind=='wrong-dotnet-header' and value.get('schema')==policy.SCHEMA:
                    value['dotnetSha256']='0'*64
                elif kind=='private-continuation' and value.get('decision')=='publish':
                    value.update(decision='restore',archiveBase64='GENERATED_PRIVATE_CANARY')
                else:return original(pump,data)
                injected.append(True);changed=C(value)+b'\n'
                pump.expected_input_bytes+=len(changed)-len(data);return original(pump,changed)
            policy.packet.require(not (REPO/'artifacts'/policy.ns.name(plan['nonce'])).exists())
            ready=None;result=None;failure=None;evidence=None;removed=False
            with claimed as session:
                try:
                    with patch.object(policy._NativePublicationPumps,'_send',send):
                        result=policy.publish_owner(REPO,powershell,python,git,dotnet,raw,pins,session,
                            git_sha256=sha(git),dotnet_sha256=sha(dotnet),manifest=expected)
                    policy.packet.require(kind=='positive')
                    evidence=json.loads(result.evidence);metadata=evidence['payload']
                    policy.packet.require(metadata['actualNativePublicationVerified'] is True and metadata['namespaceHandoffVerified'] is True)
                    bound=json.loads(session._records['native-publication-receipt.json'][1])
                    ready=json.loads(session._records['publication-namespace.json'][1])
                    policy.packet.require(bound['actualOwnedProcess']['pid']==evidence['osIdentity']['pid'] and
                        bound['fileDescriptorsHeld']==published['bundle']['files'] and bound['manifestSha256']==H(manifest))
                    policy.packet.require(bound['compilerClosureAuthenticated'] is False and 'publication-release.json' in session._records)
                    replay=False
                    try:session.consume_launch_attempt()
                    except ValueError:replay=True
                    policy.packet.require(replay)
                except policy.process.LaunchError as error:
                    evidence=json.loads(error.evidence)
                    if kind=='positive':
                        print('Unexpected native publication failure: '+json.dumps(evidence,sort_keys=True),file=sys.stderr)
                        raise
                    failure=evidence['payload']['refusalStage']
                    policy.packet.require(failure=={'wrong-code':'code','wrong-dotnet-header':'sdk','private-continuation':'publish','wrong-manifest':'seal'}[kind])
                    policy.packet.require(evidence['payload']['actualNativePublicationVerified'] is False and 'native-publication-receipt.json' not in session._records)
                    if 'publication-namespace.json' in session._records:ready=json.loads(session._records['publication-namespace.json'][1])
                finally:
                    if evidence is not None and evidence['fence']['noRunningMembersVerified'] is True:
                        removed=dispose_namespace(plan['nonce'],ready,evidence['osIdentity']['pid'])
                policy.packet.require(evidence['fence']['noRunningMembersVerified'] is True and session.report()['launchAttemptConsumed'] is True)
                policy.packet.require(policy.measure_sources(REPO)==pins)
                outcomes.append(dict(case=kind,accepted=result is not None,refusalStage=failure,
                    injectionReached=bool(injected),ownedProcessMembersAbsent=True,actualOwnedProcess=evidence['osIdentity'],
                    metadata=evidence['payload'],namespaceDisposedByFixture=removed,consumedLaunchReplayRefused=kind=='positive',
                    manifestSha256=H(expected),nativePublisherReceipt=bound if kind=='positive' else None))
        after={p.name:(p.lstat().st_dev,p.lstat().st_ino) for p in (REPO/'artifacts').glob('native-probe-publication-*')}
        policy.packet.require(before==after)
    policy.packet.require(not root.exists())
    return dict(schema='fleetory.generated-native-publication-proof.v1',verified=True,referencePublication=published,cases=outcomes,
        actualNativePublicationVerified=True,actualOwnerPowerShell=True,nativeSeconds=30,publisherSeconds=20,selectedSourceFilesPinned=len(pins),
        publicExpectedManifestCompatibilityVerified=True,compilerClosureAuthenticated=False,imageBuildVerified=False,
        backendServicesStarted=0,originalInputsRead=False,originalPrivatePkiUsed=False,sourceVpsAccessed=False,
        fullSystemRecoveryVerified=False,phase7Complete=False)


if __name__=='__main__':print('NATIVE PUBLICATION PASS: '+json.dumps(run(),sort_keys=True))
