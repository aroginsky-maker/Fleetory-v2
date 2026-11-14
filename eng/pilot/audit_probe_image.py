"""Separate fixed generated ServerBackendProbe image recipe and consumed build-ID binding."""
import json
import re
import time

import audit_image_binding as image
import audit_probe_bundle as bundle

packet, container = image.packet, image.container
SCHEMA = 'fleetory.audit-probe-image-intent.v1'
PURPOSE = 'generated-probe-image-control-binding.v1'
BASES = (
    'codenotary/immudb:1.11.2@sha256:f2efcf6a3de73b31691e0afb8dfec972642aaf0699b93387d1ec6074aedb2953',
    'codenotary/immuadmin:1.11.2@sha256:fd52f498485dcaf792677bf7d4b5b12c3bc77af80ab0718981aea9fd085ee8bd',
    'mcr.microsoft.com/dotnet/aspnet:10.0@sha256:de0ee358cdd672f7017a003bed21e9ac9ed48a27c922a59b18175b6e82fa7fee')


def bases(value):
    packet.require(type(value) is list and len(value) == 3)
    identifiers = set()
    for item, reference in zip(value, BASES):
        packet.keys(item, 'reference id layers labels')
        packet.require(item['reference'] == reference)
        identifiers.add(image.image_id(item['id']))
        image.layers(item['layers'])
        packet.require(type(item['labels']) is dict and len(item['labels']) <= 16)
        for key, text in item['labels'].items():
            packet.require(type(key) is str and re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}', key) and
                not key.startswith('fleetory.audit.control.') and type(text) is str and len(text) <= 1024 and
                all(ord(c) >= 32 for c in text))
    packet.require(len(identifiers) == 3)
    return value


def own_labels(intent):
    packet.identity(intent['nonce'])
    for key in ('controlSha256', 'bundleManifestSha256'):
        packet.hex_value(intent[key])
    return {'fleetory.audit.control.nonce': intent['nonce'], 'fleetory.audit.control.reservation': intent['controlSha256'],
        'fleetory.audit.control.profile': PURPOSE, 'fleetory.audit.control.probe.bundle': intent['bundleManifestSha256']}


def definition(intent):
    bases(intent['bases'])
    labels = own_labels(intent)
    text = ('FROM ' + BASES[0] + ' AS upstream\nFROM ' + BASES[1] + ' AS cli\nFROM ' + BASES[2] + '\n'
        'COPY --from=upstream /usr/sbin/immudb /usr/sbin/immudb\n'
        'COPY --from=cli /usr/local/bin/immuadmin /usr/local/bin/immuadmin\n'
        'COPY publish/ /tool/\nLABEL ' + ' '.join(k + '="' + v + '"' for k, v in labels.items()) + '\nUSER 3322:3322\n')
    return text.encode('ascii')


def prepare(session, held, base_values):
    packet.require(type(held) is bundle.HeldProbeBundle)
    held.check()
    report = session.report()
    now = time.time_ns()
    value = dict(schema=SCHEMA, purpose=PURPOSE, nonce=report['nonce'], revision=session._plan['revision'],
        controlSha256=report['reservationSha256'], sourceCodeSha256=session._plan['codeSha256'],
        probeSha256=held.entries['ServerBackendProbe.dll']['sha256'], bundleManifestSha256=held.pin,
        bundleSha256=held.value['sha256'], bundleFiles=held.value['files'], bundleBytes=held.value['bytes'],
        bases=bases(base_values), openedNs=now, expiresNs=now + image.WINDOW_NS)
    packet.require(value['probeSha256'] == session._plan['probeSha256'])
    value['labels'] = dict(value['bases'][2]['labels'], **own_labels(value))
    recipe = definition(value)
    context = held.context(recipe)
    value.update(definitionSha256=packet.digest(recipe), contextSha256=packet.digest(context), contextBytes=len(context))
    return image.canonical(value)


class ProbeImageBinding(image.ImageBinding):
    """Own schema/recipe; the original Python image and linked/native modes stay fixed."""
    _intent_schema = SCHEMA

    def __init__(self, session, data, expected_pin, held):
        packet.require(type(held) is bundle.HeldProbeBundle)
        self._bundle = held
        self._context = None
        super().__init__(session, data, expected_pin)

    def _admit(self, data, expected, session):
        packet.hex_value(expected)
        packet.require(type(data) in (bytes, bytearray) and 0 < len(data) <= image.MAX_INTENT and packet.digest(data) == expected)
        frozen = bytes(data)
        value = packet.strict_json(frozen, image.MAX_INTENT)
        packet.keys(value, 'schema purpose nonce revision controlSha256 sourceCodeSha256 probeSha256 bundleManifestSha256 '
            'bundleSha256 bundleFiles bundleBytes bases openedNs expiresNs labels definitionSha256 contextSha256 contextBytes')
        self._bundle.check()
        report = session.report()
        packet.require(value['schema'] == SCHEMA and value['purpose'] == PURPOSE and value['nonce'] == report['nonce'] and
            value['revision'] == session._plan['revision'] and value['controlSha256'] == report['reservationSha256'] and
            value['sourceCodeSha256'] == session._plan['codeSha256'] and value['probeSha256'] == session._plan['probeSha256'] and
            value['probeSha256'] == self._bundle.entries['ServerBackendProbe.dll']['sha256'])
        packet.require(value['bundleManifestSha256'] == self._bundle.pin and value['bundleSha256'] == self._bundle.value['sha256'] and
            type(value['bundleFiles']) is int and value['bundleFiles'] == self._bundle.value['files'] and
            type(value['bundleBytes']) is int and value['bundleBytes'] == self._bundle.value['bytes'])
        bases(value['bases'])
        packet.require(value['labels'] == dict(value['bases'][2]['labels'], **own_labels(value)))
        recipe = definition(value)
        self._context = self._bundle.context(recipe)
        packet.require(value['definitionSha256'] == packet.digest(recipe) and value['contextSha256'] == packet.digest(self._context) and
            type(value['contextBytes']) is int and value['contextBytes'] == len(self._context))
        packet.require(type(value['openedNs']) is int and type(value['expiresNs']) is int and
            value['expiresNs'] - value['openedNs'] == image.WINDOW_NS and
            session._created <= value['openedNs'] <= time.time_ns() < value['expiresNs'])
        return value, frozen

    def _check(self):
        self._bundle.check()
        super()._check()

    def build_bytes(self):
        self._check()
        packet.require(type(self._context) is bytes and packet.digest(self._context) == self.intent['contextSha256'])
        return self._context

    @staticmethod
    def _observe(data,intent,returned_id,now):
        value,created=ProbeImageBinding._profile_observation(data,intent,returned_id)
        packet.require(intent['openedNs'] <= created <= now < intent['expiresNs'])
        return value,created

    @staticmethod
    def _profile_observation(data,intent,returned_id):
        """Fixed profile only. Caller ownership and admission windows remain separate requirements."""
        image.image_id(returned_id)
        value = packet.strict_json(data, container.MAX_OBSERVATION)
        packet.keys(value, 'schema id tags digests created labels rootfs layers os architecture user')
        packet.require(value['schema'] == 'fleetory.audit-probe-image-observation.v1' and value['id'] == returned_id and
            returned_id not in {b['id'] for b in intent['bases']} and value['tags'] == [] and value['digests'] == [] and
            value['labels'] == intent['labels'] and value['user'] == '3322:3322' and value['os'] == 'linux' and
            value['architecture'] == 'amd64' and value['rootfs'] == 'layers')
        actual = image.layers(value['layers'])
        prefix = intent['bases'][2]['layers']
        packet.require(actual[:len(prefix)] == prefix and len(actual) == len(prefix) + 3)
        created = image.timestamp_ns(value['created'])
        return value, created

    def _record(self, value, created, now, frozen):
        return dict(schema='fleetory.audit-probe-image-binding.v1', nonce=self.intent['nonce'],
            reservationSha256=self.intent['controlSha256'], intentSha256=self._pin, imageId=value['id'],
            definitionSha256=self.intent['definitionSha256'], contextSha256=self.intent['contextSha256'],
            bundleManifestSha256=self.intent['bundleManifestSha256'], bundleSha256=self.intent['bundleSha256'],
            sourceCodeSha256=self.intent['sourceCodeSha256'], probeSha256=self.intent['probeSha256'],
            createdNs=created, observedAtNs=now, observationSha256=packet.digest(frozen), cleanupAuthorized=False)

    def report(self):
        value = super().report()
        value.update(generatedProbeImageRecipeBound=self._bound is not None, publicContextBytesBound=True,
            publicationOriginAuthenticated=False, deployedReleaseVerified=False, legacyApplicationImageVerified=False,
            nativeOwnerResourceAcknowledged=False, backendCleanupAuthorized=False,
            contextSha256=self.intent['contextSha256'], bundleManifestSha256=self.intent['bundleManifestSha256'])
        return value


if __name__ == '__main__':
    raise SystemExit('Probe image binding library; no Docker, command, cleanup or original-data CLI.')
