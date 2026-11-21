"""Fresh local label-only untagged builds; no container, private input or original service."""
from contextlib import ExitStack
import json
import os
from pathlib import Path
import tempfile
import uuid
from unittest.mock import patch

from audit_backend_binding_tests import control_plan
from audit_image_binding_tests import image, control
from recovery_isolation_tests import DockerRehearsal

FORMAT = ('{"schema":"fleetory.audit-generated-image-observation.v1","id":{{json .Id}},'
    '"tags":{{if .RepoTags}}{{json .RepoTags}}{{else}}[]{{end}},'
    '"digests":{{if .RepoDigests}}{{json .RepoDigests}}{{else}}[]{{end}},'
    '"parent":{{json .Parent}},"created":{{json .Created}},"labels":{{json .Config.Labels}},'
    '"rootfs":{{json .RootFS.Type}},"layers":{{json .RootFS.Layers}},"os":{{json .Os}},"architecture":{{json .Architecture}}}')
MINIMUM = ('{"id":{{json .Id}},"tags":{{if .RepoTags}}{{json .RepoTags}}{{else}}[]{{end}},'
    '"digests":{{if .RepoDigests}}{{json .RepoDigests}}{{else}}[]{{end}},'
    '"labels":{{json .Config.Labels}},"parent":{{json .Parent}}}')


class NativeImages(DockerRehearsal):
    def __init__(self):
        super().__init__()
        self.image_receipts = []

    def call(self, args, data=None, timeout=30):
        # Parent is omitted by newer inspect APIs. Pin the common 28/29 metadata API,
        # rather than treating the missing parent field as an authenticated match.
        with patch.dict(os.environ, {'DOCKER_API_VERSION': '1.48'}):
            return super().call(args, data, timeout)

    def observed(self, identifier):
        image.image_id(identifier)
        return image.packet.strict_json(self.call(['image', 'inspect', '--format', FORMAT, identifier]), image.container.MAX_OBSERVATION)

    def build(self, intent, directory):
        empty = directory / ('context-' + uuid.uuid4().hex)
        empty.mkdir(mode=0o700)
        with control.DirectoryLease(empty) as held:
            image.packet.require(list(empty.iterdir()) == [])
            held.check()
            with patch.dict(os.environ, {'DOCKER_BUILDKIT': '0'}):
                result = self.call(['build', '--quiet', '--network=none', '--pull=false', '--no-cache',
                    '--file', '-', str(empty)], image.definition(intent), timeout=60)
            # Quiet build stdout is the separate immutable-ID receipt. No tag is requested.
            identifier = result.decode('ascii').strip()
            image.image_id(identifier)
            self.image_receipts.append((identifier, intent))
            held.check()
            image.packet.require(list(empty.iterdir()) == [])
        return identifier

    def present(self, identifier):
        intents = [value for receipt, value in self.image_receipts if receipt == identifier]
        image.packet.require(len(intents) == 1)
        selector = 'label=fleetory.audit.control.reservation=' + intents[0]['controlSha256']
        # Include tagged and intermediate objects too; absence is not a dangling-only query.
        return self.call(['image', 'ls', '-a', '--no-trunc', '--format', '{{.ID}}', '--filter', selector]).decode().split().count(identifier)

    def cleanup(self):
        for identifier, intent in reversed(self.image_receipts):
            value = image.packet.strict_json(self.call(['image', 'inspect', '--format', MINIMUM, identifier]), image.container.MAX_OBSERVATION)
            image.packet.require(value['id'] == identifier and value['parent'] == intent['baseId'] and
                value['labels'] == intent['labels'] and value['tags'] == [] and value['digests'] == [])
            # No force, tag adoption or untagged-parent pruning is allowed by this fixture.
            self.call(['image', 'rm', '--no-prune', identifier])
            image.packet.require(self.present(identifier) == 0)

    def run(self):
        version = self.preflight()
        base = image.packet.strict_json(self.call(['image', 'inspect', '--format', FORMAT, image.IMAGE]), image.container.MAX_OBSERVATION)
        with tempfile.TemporaryDirectory(prefix='fleetory-native-image-binding-') as temp, ExitStack() as stack:
            root = Path(temp).resolve()

            def reserve():
                raw = image.canonical(control_plan(str(uuid.uuid4())))
                session = stack.enter_context(control.claim(root, raw, image.packet.digest(raw)))
                data = image.prepare(session, base['id'], base['layers'])
                return session, image.ImageBinding(session, data, image.packet.digest(data))

            try:
                _, sentinel = reserve()
                foreign_id = self.build(sentinel.intent, root)
                before = self.observed(foreign_id)
                _, target = reserve()
                target_id = self.build(target.intent, root)
                result = target.bind(image.canonical(self.observed(target_id)), target_id)
                image.packet.require(result['generatedImageIdBound'] is True and result['imageId'] == target_id)
                refused_session, refused = reserve()
                denied = False
                try:
                    refused.bind(image.canonical(self.observed(foreign_id)), foreign_id)
                except ValueError:
                    denied = True
                image.packet.require(denied and refused.report()['generatedImageIdBound'] is False and
                    (refused_session._directory.path / 'image-binding-attempt.json').is_file() and
                    not (refused_session._directory.path / 'image-binding.json').exists())
                image.packet.require(self.observed(foreign_id) == before)
                proof = dict(schema='fleetory.generated-native-image-binding.v1', verified=True, dockerVersion=version, inspectApiVersion='1.48',
                    builtUntaggedImages=2, controllerIntents=3, acceptedImageBindings=1, foreignImageRefused=True,
                    refusedObservationConsumed=True, sentinelPreserved=True, fixedDefinitionVerified=True, emptyContextsVerified=True,
                    mutableTagsCreated=0, containersStarted=0, originalInputsRead=False, originalPrivatePkiUsed=False,
                    dockerObservationAuthenticated=False, buildProvenanceAuthenticated=False, legacyNativeOwnerIntegrated=False,
                    abruptOwnerDeathCleanupVerified=False, cleanupAuthorized=False, privateInputsReleased=False,
                    fullSystemRecoveryVerified=False, phase7Complete=False)
            finally:
                self.cleanup()
                after = image.packet.strict_json(self.call(['image', 'inspect', '--format', FORMAT, image.IMAGE]), image.container.MAX_OBSERVATION)
                image.packet.require(after == base)
        proof.update(ownedImagesAbsent=True, baseCachePreserved=True)
        return proof


def verify_failure_cleanup():
    client = NativeImages()
    refused = False
    with patch.object(client, 'observed', side_effect=RuntimeError('generated image inspect refusal')):
        try:
            client.run()
        except RuntimeError as error:
            image.packet.require(str(error) == 'generated image inspect refusal')
            refused = True
    image.packet.require(refused and len(client.image_receipts) == 1 and client.present(client.image_receipts[0][0]) == 0)


if __name__ == '__main__':
    result = NativeImages().run()
    verify_failure_cleanup()
    result.update(observationFailureCleanupVerified=True, observationFailureImagesRemoved=1)
    print('AUDIT IMAGE DOCKER PASS: ' + json.dumps(result, sort_keys=True))
