"""Container intent tied to the same held controller's bound untagged image; metadata only."""
import json
import time

import audit_backend_binding as container
import audit_image_binding as image

packet = container.packet
SCHEMA = 'fleetory.audit-linked-container-intent.v1'
PURPOSE = 'generated-image-container-control-binding.v1'


def anchor(session, bound_image):
    packet.require(type(bound_image) is image.ImageBinding and bound_image.session is session)
    report = bound_image.report()
    packet.require(report['generatedImageIdBound'] is True)
    raw = session._records['image-binding.json'][1]
    record = json.loads(raw)
    packet.require(record['imageId'] == report['imageId'] and record['intentSha256'] == report['intentSha256'] and
        record['reservationSha256'] == session.report()['reservationSha256'])
    return dict(imageId=container.image_id(report['imageId']), imageBindingSha256=packet.digest(raw),
        imageIntentSha256=report['intentSha256'])


def labels(session, image_pin):
    report = session.report()
    result = container.labels(report['nonce'], report['reservationSha256'])
    result['fleetory.audit.control.profile'] = PURPOSE
    result['fleetory.audit.control.image.binding'] = image_pin
    return result


def prepare(session, bound_image):
    source = anchor(session, bound_image)
    report = session.report()
    now = time.time_ns()
    return container.canonical(dict(schema=SCHEMA, purpose=PURPOSE, nonce=report['nonce'],
        revision=session._plan['revision'], controlSha256=report['reservationSha256'],
        image=source['imageId'], **source, name=container.container_name(report['nonce']),
        labels=labels(session, source['imageBindingSha256']), openedNs=now, expiresNs=bound_image.intent['expiresNs']))


class LinkedContainerBinding(container.ContainerBinding):
    """One-use backend slot; no build, Docker, deletion, native-owner or data authority."""
    _intent_schema = SCHEMA

    def __init__(self, session, data, expected_pin, bound_image):
        self._source = bound_image
        super().__init__(session, data, expected_pin)

    def _admit(self, data, expected, session):
        packet.hex_value(expected)
        packet.require(type(data) in (bytes, bytearray) and 0 < len(data) <= container.MAX_INTENT)
        frozen = bytes(data)
        packet.require(packet.digest(frozen) == expected)
        value = packet.strict_json(frozen, container.MAX_INTENT)
        packet.keys(value, 'schema purpose nonce revision controlSha256 image imageId imageBindingSha256 imageIntentSha256 name labels openedNs expiresNs')
        source = anchor(session, self._source)
        report = session.report()
        packet.require(value['schema'] == SCHEMA and value['purpose'] == PURPOSE and
            value['nonce'] == report['nonce'] and value['revision'] == session._plan['revision'] and
            value['controlSha256'] == report['reservationSha256'])
        for key, item in source.items():
            packet.require(value[key] == item)
        packet.require(value['image'] == source['imageId'] and value['name'] == container.container_name(report['nonce']) and
            value['labels'] == labels(session, source['imageBindingSha256']))
        packet.require(type(value['openedNs']) is int and type(value['expiresNs']) is int and
            value['expiresNs'] == self._source.intent['expiresNs'] and
            0 < value['expiresNs'] - value['openedNs'] <= container.WINDOW_NS and
            session._created <= value['openedNs'] <= time.time_ns() < value['expiresNs'])
        return value, frozen

    def _check(self):
        source = anchor(self.session, self._source)
        packet.require(all(self.intent[key] == value for key, value in source.items()))
        super()._check()

    @staticmethod
    def _observe(data, intent, returned_id, now):
        return container._observation_for_reference(data, intent, returned_id, now, intent['imageId'])

    def _record(self, value, created, now, frozen):
        record = super()._record(value, created, now, frozen)
        record.update(schema='fleetory.audit-linked-container-binding.v1',
            imageBindingSha256=self.intent['imageBindingSha256'], imageIntentSha256=self.intent['imageIntentSha256'])
        return record

    def report(self):
        result = super().report()
        result.update(imageBindingSha256=self.intent['imageBindingSha256'],
            imageIntentSha256=self.intent['imageIntentSha256'], immutableImageReference=True,
            generatedImageContainerPairBound=self._bound is not None, nativeOwnerResourceAcknowledged=False,
            legacyApplicationImageVerified=False)
        return result


if __name__ == '__main__':
    raise SystemExit('Linked binding is a metadata library; no Docker, cleanup, command or data CLI is provided.')
