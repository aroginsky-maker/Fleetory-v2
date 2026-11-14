"""Actual public probe publication -> fixed untagged image -> stopped readback; no services/data."""
from contextlib import ExitStack
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import uuid
from unittest.mock import patch

from audit_probe_image_tests import policy, bundle, image, packet, control_plan
from native_audit_image_binding import NativeImages
from native_audit_preparation import active_sdk_input, REPO

BASE_FORMAT = ('{"id":{{json .Id}},"layers":{{json .RootFS.Layers}},'
    '"labels":{{if .Config.Labels}}{{json .Config.Labels}}{{else}}{}{{end}}}')
IMAGE_FORMAT = ('{"schema":"fleetory.audit-probe-image-observation.v1","id":{{json .Id}},'
    '"tags":{{if .RepoTags}}{{json .RepoTags}}{{else}}[]{{end}},'
    '"digests":{{if .RepoDigests}}{{json .RepoDigests}}{{else}}[]{{end}},'
    '"created":{{json .Created}},"labels":{{json .Config.Labels}},"rootfs":{{json .RootFS.Type}},'
    '"layers":{{json .RootFS.Layers}},"os":{{json .Os}},"architecture":{{json .Architecture}},"user":{{json .Config.User}}}')
STOP_FORMAT = ('{"id":{{json .Id}},"name":{{json .Name}},"image":{{json .Image}},"configImage":{{json .Config.Image}},'
    '"labels":{{json .Config.Labels}},"running":{{json .State.Running}},"status":{{json .State.Status}},"pid":{{json .State.Pid}},'
    '"network":{{json .HostConfig.NetworkMode}},"mounts":{{json .Mounts}},"readonly":{{json .HostConfig.ReadonlyRootfs}},'
    '"privileged":{{json .HostConfig.Privileged}},"user":{{json .Config.User}},"entrypoint":{{json .Config.Entrypoint}}}')


def bounded_docker(args, data=None, limit=262144, timeout=60):
    """Fixed fixture callers only; input/output bounded and no shell command construction."""
    packet.require(type(args) is list and (data is None or type(data) is bytes and len(data) <= bundle.MAX_CONTEXT))
    environment = {k:v for k,v in os.environ.items() if not k.startswith('COMPOSE_')}
    environment.update(DOCKER_BUILDKIT='0', DOCKER_API_VERSION='1.48', COMPOSE_DISABLE_ENV_FILE='1')
    with subprocess.Popen(['docker', *args], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            bufsize=0, env=environment) as child:
        pumps = bundle.process._Pumps(child, data or b'')
        for target, arguments in ((pumps._read, (child.stdout, pumps.stdout, limit, 'stdout-bound')),
                (pumps._read, (child.stderr, pumps.stderr, 4096, 'stderr-bound')), (pumps._write, ())):
            thread = threading.Thread(target=target, args=arguments, daemon=True)
            pumps.threads.append(thread);thread.start()
        deadline = time.monotonic() + timeout
        try:
            while child.poll() is None:
                packet.require(not pumps.errors and time.monotonic() < deadline)
                time.sleep(0.01)
            pumps.finish()
            packet.require(child.returncode == 0 and not pumps.errors and pumps.input_written == len(data or b''))
            return bytes(pumps.stdout)
        finally:
            if child.poll() is None:
                child.kill();child.wait(timeout=3)
            pumps.finish()


def publication(root, repository=REPO):
    powershell = shutil.which('pwsh')
    packet.require(powershell is not None)
    helper = root / 'publish.ps1'
    helper.write_text("""param([string]$Repository,[string]$Directory)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
foreach($name in @('PilotNativeProcess','ProviderRecoveryPolicy','ImmuDataRoundtripPolicy','HistoricalAuditInputPins')){. (Join-Path $Repository ('eng/pilot/'+$name+'.ps1'))}
foreach($name in @('NativeSignerFixture','NativeWorkerRuntime')){. (Join-Path $Repository ('tests/Fleetory.Tools.Tests/'+$name+'.ps1'))}
$dotnet=(Get-Command dotnet).Source;$pin=(Get-HistoricalInputFileHash $dotnet 67108864).sha256
$first=Get-HistoricalAuditCodeSnapshot $Repository
$published=Publish-NativeProbe $Repository 'ServerBackendProbe' $Directory
$second=Get-HistoricalAuditCodeSnapshot $Repository
Assert-ImmuData ($first.sha256 -ceq $second.sha256 -and $first.revision -ceq $second.revision) 'probe-source-stable'
Assert-ImmuData ((Get-HistoricalInputFileHash $dotnet 67108864).sha256 -ceq $pin) 'publisher-entrypoint-stable'
$bundle=Get-HistoricalProbeBundle $published
$sdkVersion=(& $dotnet --version).Trim();Assert-ImmuData ($LASTEXITCODE -eq 0 -and $sdkVersion -ceq (Get-Content -LiteralPath (Join-Path $Repository 'global.json') -Raw|ConvertFrom-Json).sdk.version) 'publisher-sdk-version'
@{source=$second;bundle=$bundle;dotnetSha256=$pin;sdkVersion=$sdkVersion}|ConvertTo-Json -Depth 12 -Compress
""", encoding='utf-8')
    result = subprocess.run([powershell, '-NoLogo', '-NoProfile', '-NonInteractive', '-File', str(helper), str(repository), str(root)],
        capture_output=True, timeout=180)
    packet.require(result.returncode == 0 and result.stderr == b'')
    value = packet.strict_json(result.stdout, bundle.MAX_MANIFEST + 4096)
    packet.keys(value, 'source bundle dotnetSha256 sdkVersion')
    packet.hex_value(value['dotnetSha256'])
    return value


class ProbeBuild:
    def __init__(self):
        self.metadata = NativeImages()
        self.images, self.containers = [], []

    def base(self, reference):
        data = packet.strict_json(self.metadata.call(['image', 'inspect', '--format', BASE_FORMAT, reference]), 8192)
        return dict(reference=reference, **data)

    def observed(self, identifier):
        image.image_id(identifier)
        return packet.strict_json(self.metadata.call(['image', 'inspect', '--format', IMAGE_FORMAT, identifier]), 8192)

    def build(self, resource):
        raw = resource.build_bytes()
        output = bounded_docker(['build', '--quiet', '--network=none', '--pull=false', '--no-cache', '--force-rm',
            '--file', 'Dockerfile', '-'], raw, timeout=60)
        identifier = output.decode('ascii').strip();image.image_id(identifier)
        self.images.append((identifier, resource.intent))
        return identifier

    def stopped(self, identifier, image_id, intent):
        name = 'fleetory-probe-copy-' + intent['nonce'].replace('-', '')
        labels = dict(intent['labels'], **{'fleetory.audit.control.copy': 'public-probe-readback.v1'})
        expected = dict(id=identifier, name='/' + name, image=image_id, configImage=image_id, labels=labels,
            running=False, status='created', pid=0, network='none', mounts=[], readonly=True, privileged=False,
            user='3322:3322', entrypoint=['/bin/true'])
        value = packet.strict_json(self.metadata.call(['container', 'inspect', '--format', STOP_FORMAT, identifier]), 8192)
        packet.require(value == expected and value['running'] is False and value['privileged'] is False and value['readonly'] is True)

    def create(self, image_id, intent):
        name = 'fleetory-probe-copy-' + intent['nonce'].replace('-', '')
        packet.require(not self.metadata.call(['container', 'ls', '-a', '--filter', 'name=^/' + name + '$', '--format', '{{.ID}}']).strip())
        identifier = self.metadata.call(['create', '--name', name, '--label', 'fleetory.audit.control.copy=public-probe-readback.v1',
            '--network=none', '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges:true', '--memory=64m',
            '--cpus=0.25', '--pids-limit=32', '--restart=no', '--entrypoint=/bin/true', image_id]).decode().strip()
        packet.require(len(identifier) == 64 and all(c in '0123456789abcdef' for c in identifier))
        self.containers.append((identifier, image_id, intent))
        self.stopped(identifier, image_id, intent)
        return identifier

    def cleanup(self):
        for identifier, image_id, intent in reversed(self.containers):
            self.stopped(identifier, image_id, intent)
            self.metadata.call(['container', 'rm', identifier])
            packet.require(not self.metadata.call(['container', 'ls', '-a', '--no-trunc', '--filter', 'id=' + identifier, '--format', '{{.ID}}']).strip())
        for identifier, intent in reversed(self.images):
            value = self.observed(identifier)
            packet.require(value['id'] == identifier and value['labels'] == intent['labels'] and value['user'] == '3322:3322' and
                value['tags'] == value['digests'] == [])
            self.metadata.call(['image', 'rm', '--no-prune', identifier])
            found = self.metadata.call(['image', 'ls', '-a', '--no-trunc', '--filter',
                'label=fleetory.audit.control.reservation=' + intent['controlSha256'], '--format', '{{.ID}}']).decode().split()
            packet.require(identifier not in found)


def run(runtime_check=None, control_factory=None, repository=REPO):
    client = ProbeBuild();version = client.metadata.preflight()
    bases = []
    for reference in policy.BASES:
        try:
            value = client.base(reference)
        except RuntimeError:
            client.metadata.call(['pull', '--quiet', reference], timeout=120)
            value = client.base(reference)
        bases.append(value)
    policy.bases(bases)
    with tempfile.TemporaryDirectory(prefix='fleetory-public-probe-image-') as temp, active_sdk_input(repository), ExitStack() as stack:
        root = Path(temp).resolve()
        published = publication(root, repository)
        encoded = image.canonical(published['bundle'])
        held = stack.enter_context(bundle.HeldProbeBundle(root / 'publish', encoded, packet.digest(encoded)))
        directory = root / 'control';directory.mkdir(mode=0o700)
        def session():
            value = control_plan(str(uuid.uuid4()))
            value.update(revision=published['source']['revision'], codeSha256=published['source']['sha256'],
                probeSha256=held.entries['ServerBackendProbe.dll']['sha256'])
            if control_factory is not None:value = control_factory(value)
            raw = image.canonical(value)
            return stack.enter_context(bundle.control.claim(directory, raw, packet.digest(raw)))
        try:
            current = session();raw = policy.prepare(current, held, bases)
            resource = policy.ProbeImageBinding(current, raw, packet.digest(raw), held)
            identifier = client.build(resource)
            observed = client.observed(identifier)
            report = resource.bind(image.canonical(observed), identifier)
            packet.require(report['generatedProbeImageRecipeBound'] is True)
            foreign = session();raw = policy.prepare(foreign, held, bases)
            target = policy.ProbeImageBinding(foreign, raw, packet.digest(raw), held)
            try:target.bind(image.canonical(observed), identifier)
            except ValueError:pass
            else:raise ValueError('Foreign probe image accepted.')
            packet.require('image-binding-attempt.json' in foreign._records and 'image-binding.json' not in foreign._records)
            try:target.bind(image.canonical(observed), identifier)
            except ValueError:pass
            else:raise ValueError('Consumed probe image observation replay accepted.')
            store = client.create(identifier, resource.intent)
            copied = bounded_docker(['cp', store + ':/tool/.', '-'], limit=bundle.MAX_CONTEXT)
            checked = bundle.verify_readback(copied, held)
            changed = bytearray(copied)
            with tarfile.open(fileobj=io.BytesIO(copied), mode='r:') as archive:
                first = next(item for item in archive if item.isfile())
                changed[first.offset_data] ^= 1
            try:bundle.verify_readback(bytes(changed), held)
            except ValueError:pass
            else:raise ValueError('Corrupt public readback accepted.')
            client.stopped(store, identifier, resource.intent)
            held.check();resource.report()
            publication_info = dict(sourceRevision=published['source']['revision'], codeSnapshotSha256=published['source']['sha256'],
                dotnetSha256=published['dotnetSha256'], sdkVersion=published['sdkVersion'], bundleManifestSha256=held.pin, bundleSha256=checked['bundleSha256'],
                files=checked['files'], bytes=checked['bytes'], contextSha256=resource.intent['contextSha256'],
                contextBytes=resource.intent['contextBytes'], imageId=identifier)
            runtime_observation = runtime_check(current, resource, session) if runtime_check is not None else None
        finally:
            client.cleanup()
            packet.require([client.base(reference) for reference in policy.BASES] == bases)
    result = dict(schema='fleetory.generated-native-probe-image.v1', verified=True, dockerVersion=version, publication=publication_info,
        actualCurrentProbePublished=True, currentSourceSnapshotStable=True, heldPublicBundleVerified=True, deterministicContextBound=True,
        fixedThreeBaseRecipeVerified=True, untaggedBuildIdBound=True, foreignObservationRefused=True, consumedObservationReplayRefused=True,
        stoppedFullBundleReadbackVerified=True, corruptReadbackRefused=True, containersCreated=1, servicesStarted=0,
        finalImagesBuilt=1, mutableTagsCreated=0, ownStoppedContainersAbsent=True, finalImageReceiptIdsAbsent=True,
        cachedBaseImagesPreserved=True, cleanupFromOwnReceiptsOnly=True, selectedInspectFieldsOnly=True,
        intermediateBuildCacheCleanupVerified=False, nativeOwnerResourceAcknowledged=False, legacyNativeOwnerIntegrated=False,
        publicationOriginAuthenticated=False, deployedReleaseVerified=False, dockerObservationAuthenticated=False,
        backendControlAuthorized=False, backendCleanupAuthorized=False, abruptOwnerDeathBackendCleanupVerified=False,
        originalInputsRead=False, originalPrivatePkiUsed=False, sourceVpsAccessed=False, fullSystemRecoveryVerified=False, phase7Complete=False)
    if runtime_check is not None:
        result['runtimeObservation'] = runtime_observation
    return result


if __name__ == '__main__':
    print('NATIVE PROBE IMAGE PASS: ' + json.dumps(run(), sort_keys=True))
