"""Actual untagged image -> constrained container in one held control; no app/data."""
from contextlib import ExitStack
import json
from pathlib import Path
import tempfile
import uuid
from unittest.mock import patch

from audit_linked_binding_tests import linked, control, control_plan
from native_audit_image_binding import NativeImages, FORMAT as IMAGE_FORMAT
from native_audit_resource_binding import NativeBinding


class DerivedContainers(NativeBinding):
    def source_reference(self, intent):
        linked.container.image_id(intent['image'])
        return intent['image']


class NativePairs:
    def __init__(self):
        self.images = NativeImages()
        self.derived = DerivedContainers()
        self.base = NativeBinding()

    def run(self):
        version = self.images.preflight()
        linked.packet.require(self.derived.preflight() == version and self.base.preflight() == version)
        base = linked.packet.strict_json(self.images.call(['image','inspect','--format',IMAGE_FORMAT,linked.image.IMAGE]),
            linked.container.MAX_OBSERVATION)
        with tempfile.TemporaryDirectory(prefix='fleetory-linked-pair-') as temp, ExitStack() as stack:
            root = Path(temp).resolve()

            def session():
                raw = linked.container.canonical(control_plan(str(uuid.uuid4())))
                return stack.enter_context(control.claim(root, raw, linked.packet.digest(raw)))

            def build():
                held = session()
                raw = linked.image.prepare(held, base['id'], base['layers'])
                bound_image = linked.image.ImageBinding(held, raw, linked.packet.digest(raw))
                identifier = self.images.build(bound_image.intent, root)
                bound_image.bind(linked.container.canonical(self.images.observed(identifier)), identifier)
                raw = linked.prepare(held, bound_image)
                target = linked.LinkedContainerBinding(held, raw, linked.packet.digest(raw), bound_image)
                return held, bound_image, raw, target

            try:
                held, source, raw, target = build()
                identifier = self.derived.create(target.intent)
                observed = self.derived.observed(identifier)
                result = target.bind(linked.container.canonical(observed), identifier)
                linked.packet.require(result['generatedImageContainerPairBound'] is True and
                    observed['imageId'] == observed['configImage'] == source.report()['imageId'] and
                    target.intent['expiresNs'] == source.intent['expiresNs'])
                record = json.loads(held._records['backend-binding.json'][1])
                linked.packet.require(record['imageBindingSha256'] == linked.packet.digest(held._records['image-binding.json'][1]))

                sentinel_session = session()
                sentinel_raw = linked.container.prepare(sentinel_session, base['id'])
                sentinel = linked.container.ContainerBinding(sentinel_session, sentinel_raw, linked.packet.digest(sentinel_raw))
                sentinel_id = self.base.create(sentinel.intent)
                sentinel_before = self.base.observed(sentinel_id)

                bad_session, _, _, bad_target = build()
                wrong_creation = dict(bad_target.intent, image=linked.image.IMAGE, imageId=base['id'])
                wrong_id = self.base.create(wrong_creation)
                refused = False
                try:
                    bad_target.bind(linked.container.canonical(self.base.observed(wrong_id)), wrong_id)
                except ValueError:
                    refused = True
                linked.packet.require(refused and bad_target.report()['generatedImageContainerPairBound'] is False and
                    'backend-binding-attempt.json' in bad_session._records and 'backend-binding.json' not in bad_session._records)

                foreign = session()
                refused = False
                try:
                    linked.LinkedContainerBinding(foreign, raw, linked.packet.digest(raw), source)
                except ValueError:
                    refused = True
                linked.packet.require(refused and 'backend-attempt.json' in foreign._records and
                    'backend-intent.json' not in foreign._records)
                linked.packet.require(self.base.observed(sentinel_id) == sentinel_before)
                proof = dict(schema='fleetory.generated-native-linked-pair.v1',verified=True,dockerVersion=version,
                    builtUntaggedImages=2,createdContainers=3,acceptedPairs=1,wrongBaseContainerRefused=True,
                    wrongObservationAttemptConsumed=True,foreignControllerRefused=True,foreignAttemptConsumed=True,
                    sentinelPreserved=True,immutableConfigImageMatched=True,sameControllerImageRecordMatched=True,
                    sharedExpiryMatched=True,selectedInspectFieldsOnly=True,mutableTagsCreated=0,
                    privateInputsReleased=False,originalInputsRead=False,originalPrivatePkiUsed=False,
                    dockerObservationAuthenticated=False,legacyNativeOwnerIntegrated=False,
                    nativeOwnerResourceAcknowledged=False,legacyApplicationImageVerified=False,
                    abruptOwnerDeathCleanupVerified=False,backendCleanupAuthorized=False,
                    fullSystemRecoveryVerified=False,phase7Complete=False)
            finally:
                self.derived.cleanup()
                self.base.cleanup()
                self.images.cleanup()
                after = linked.packet.strict_json(self.images.call(['image','inspect','--format',IMAGE_FORMAT,linked.image.IMAGE]),
                    linked.container.MAX_OBSERVATION)
                linked.packet.require(after == base)
        proof.update(ownedContainersAbsent=True,ownedImagesAbsent=True,baseCachePreserved=True)
        return proof


def verify_failure_cleanup():
    client = NativePairs()
    refused = False
    with patch.object(client.derived, 'observed', side_effect=RuntimeError('Generated linked inspect refusal')):
        try:
            client.run()
        except RuntimeError as error:
            linked.packet.require(str(error) == 'Generated linked inspect refusal')
            refused = True
    linked.packet.require(refused and len(client.images.image_receipts) == 1 and len(client.derived.receipts) == 1)
    linked.packet.require(client.derived.listed_id(client.derived.receipts[0][0]) == [])
    linked.packet.require(client.images.present(client.images.image_receipts[0][0]) == 0)


if __name__ == '__main__':
    value = NativePairs().run()
    verify_failure_cleanup()
    value.update(observationFailureCleanupVerified=True,observationFailureImagesRemoved=1,observationFailureContainersRemoved=1)
    print('AUDIT LINKED PAIR DOCKER PASS: '+json.dumps(value,sort_keys=True))
