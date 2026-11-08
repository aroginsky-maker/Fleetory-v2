"""Real Docker receipts acknowledged by native owner; generated resources, no original data."""
from contextlib import ExitStack
import json
from pathlib import Path
import tempfile
import uuid

from native_resource_ack import run as acknowledge, policy
from native_audit_linked_pair import NativePairs
from native_audit_image_binding import FORMAT
from audit_backend_binding_tests import control_plan


def run():
    client = NativePairs()
    version = client.images.preflight()
    policy.packet.require(client.derived.preflight() == version and client.base.preflight() == version)
    base = policy.packet.strict_json(client.images.call(['image', 'inspect', '--format', FORMAT, policy.linked.image.IMAGE]),
        policy.linked.container.MAX_OBSERVATION)
    with tempfile.TemporaryDirectory(prefix='fleetory-native-resource-docker-') as temp, ExitStack() as stack:
        directory = Path(temp).resolve()
        raw = policy.prep.canonical(control_plan(str(uuid.uuid4())))
        session = stack.enter_context(policy.payload.control.claim(directory, raw, policy.packet.digest(raw)))
        raw = policy.linked.container.prepare(session, base['id'])
        sentinel = policy.linked.container.ContainerBinding(session, raw, policy.packet.digest(raw))
        try:
            sentinel_id = client.base.create(sentinel.intent)
            before = client.base.observed(sentinel_id)
            def build(held, root):
                raw = policy.linked.image.prepare(held, base['id'], base['layers'])
                source = policy.linked.image.ImageBinding(held, raw, policy.packet.digest(raw))
                image_id = client.images.build(source.intent, root)
                source.bind(policy.prep.canonical(client.images.observed(image_id)), image_id)
                raw = policy.linked.prepare(held, source)
                target = policy.linked.LinkedContainerBinding(held, raw, policy.packet.digest(raw), source)
                identifier = client.derived.create(target.intent)
                target.bind(policy.prep.canonical(client.derived.observed(identifier)), identifier)
                return source, target
            proof = acknowledge(build, ('positive', 'bad-offer', 'owner-exit'))
            policy.packet.require(client.base.observed(sentinel_id) == before)
        finally:
            client.derived.cleanup()
            client.base.cleanup()
            client.images.cleanup()
            after = policy.packet.strict_json(client.images.call(['image', 'inspect', '--format', FORMAT, policy.linked.image.IMAGE]),
                policy.linked.container.MAX_OBSERVATION)
            policy.packet.require(after == base)
    policy.packet.require(len(client.images.image_receipts) == len(client.derived.receipts) == 3 and len(client.base.receipts) == 1)
    return dict(schema='fleetory.generated-native-resource-docker.v1', verified=True, dockerVersion=version,
        native=proof, builtUntaggedImages=3, createdDerivedContainers=3, foreignFixtureContainers=1,
        genuineBuildAndCreateReceiptsUsed=True, selectedInspectFieldsOnly=True, sentinelPreserved=True,
        ownedContainersAbsent=True, ownedImagesAbsent=True, baseCachePreserved=True, mutableTagsCreated=0,
        cleanupAuthorityFromFixtureReceiptsOnly=True, originalInputsRead=False, originalPrivatePkiUsed=False,
        backendControlAuthorized=False, backendCleanupAuthorized=False, abruptOwnerDeathBackendCleanupVerified=False,
        legacyApplicationImageVerified=False, legacyNativeOwnerIntegrated=False, dockerObservationAuthenticated=False,
        fullSystemRecoveryVerified=False, phase7Complete=False)


if __name__ == '__main__':
    print('NATIVE RESOURCE DOCKER ACK PASS: ' + json.dumps(run(), sort_keys=True))
