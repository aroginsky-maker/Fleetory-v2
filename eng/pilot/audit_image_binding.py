"""Consumed untagged image-ID binding. No build, Docker, deletion or data API."""
import time

import audit_backend_binding as container
from audit_backend_binding import canonical, image_id, packet, timestamp_ns, IMAGE, WINDOW_NS

SCHEMA = 'fleetory.audit-generated-image-intent.v1'
PURPOSE = 'generated-untagged-image-control-binding.v1'
MAX_INTENT = 4096


def build_labels(nonce, reservation):
    value = container.labels(nonce, reservation)
    value['fleetory.audit.control.profile'] = PURPOSE
    return value


def definition(intent):
    # The recipe admits only FROM plus fixed labels; no path, context content or command.
    expected = build_labels(intent['nonce'], intent['controlSha256'])
    packet.require(intent['labels'] == expected)
    text = 'FROM ' + IMAGE + '\nLABEL ' + ' '.join(name + '="' + value + '"' for name, value in expected.items()) + '\n'
    return text.encode('ascii')


def layers(value):
    packet.require(type(value) is list and 0 < len(value) <= 16)
    for item in value:
        image_id(item)
    return value


def prepare(session, base_id, base_layers):
    report = session.report()
    now = time.time_ns()
    value = dict(schema=SCHEMA, purpose=PURPOSE, nonce=report['nonce'], revision=session._plan['revision'],
        controlSha256=report['reservationSha256'], base=IMAGE, baseId=image_id(base_id), baseLayers=list(layers(base_layers)),
        labels=build_labels(report['nonce'], report['reservationSha256']), openedNs=now, expiresNs=now + WINDOW_NS)
    value['definitionSha256'] = packet.digest(definition(value))
    return canonical(value)


def admit(data, expected, session):
    packet.hex_value(expected)
    packet.require(type(data) in (bytes, bytearray) and 0 < len(data) <= MAX_INTENT)
    frozen = bytes(data)
    packet.require(packet.digest(frozen) == expected)
    value = packet.strict_json(frozen, MAX_INTENT)
    packet.keys(value, 'schema purpose nonce revision controlSha256 base baseId baseLayers labels openedNs expiresNs definitionSha256')
    report = session.report()
    packet.require(value['schema'] == SCHEMA and value['purpose'] == PURPOSE and value['base'] == IMAGE)
    packet.require(value['nonce'] == report['nonce'] and value['revision'] == session._plan['revision'] and
                   value['controlSha256'] == report['reservationSha256'])
    image_id(value['baseId'])
    layers(value['baseLayers'])
    packet.require(value['definitionSha256'] == packet.digest(definition(value)))
    packet.require(type(value['openedNs']) is int and type(value['expiresNs']) is int and
                   value['expiresNs'] - value['openedNs'] == WINDOW_NS and
                   session._created <= value['openedNs'] <= time.time_ns() < value['expiresNs'])
    return value, frozen


def observation(data, intent, returned_id, now):
    image_id(returned_id)
    value = packet.strict_json(data, container.MAX_OBSERVATION)
    packet.keys(value, 'schema id tags digests parent created labels rootfs layers os architecture')
    packet.require(value['schema'] == 'fleetory.audit-generated-image-observation.v1' and
                   value['id'] == returned_id and value['id'] != intent['baseId'] and value['parent'] == intent['baseId'])
    packet.require(value['tags'] == [] and value['digests'] == [] and value['labels'] == intent['labels'])
    packet.require(value['rootfs'] == 'layers' and value['layers'] == intent['baseLayers'] and
                   value['os'] == 'linux' and value['architecture'] == 'amd64')
    created = timestamp_ns(value['created'])
    packet.require(intent['openedNs'] <= created <= now < intent['expiresNs'])
    return value, created


class ImageBinding(container.ContainerBinding):
    """Same held/consumed publication mechanism; distinct immutable image record slots."""
    _slot, _kind, _intent_schema = 'image', 'image', SCHEMA
    _admit, _observe = staticmethod(admit), staticmethod(observation)

    def _consume(self, session):
        session.consume_image_attempt()

    def _record(self, value, created, now, frozen):
        return dict(schema='fleetory.audit-generated-image-binding.v1', nonce=self.intent['nonce'],
            reservationSha256=self.intent['controlSha256'], intentSha256=self._pin, imageId=value['id'],
            baseId=value['parent'], definitionSha256=self.intent['definitionSha256'], createdNs=created,
            observedAtNs=now, observationSha256=packet.digest(frozen), cleanupAuthorized=False)

    def report(self):
        value = super().report()
        value.update(mutableTagClaimed=False, buildProvenanceAuthenticated=False, registryAvailabilityVerified=False)
        return value


if __name__ == '__main__':
    raise SystemExit('Image binding is a metadata library; no build, Docker, deletion or data CLI is provided.')
