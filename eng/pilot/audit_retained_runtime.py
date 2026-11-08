"""Separate retained-publication sleep runtime metadata; no Docker, service or cleanup authority."""
from contextlib import ExitStack
import os
import time

import audit_publication_continuation as publication
import audit_probe_runtime as runtime

packet, container = runtime.packet, runtime.container
SCHEMA = 'fleetory.retained-probe-runtime-intent.v1'
PURPOSE = 'retained-publication-sleep-control-binding.v1'
OBSERVATION_SCHEMA = 'fleetory.retained-probe-runtime-observation.v1'
EXTRA_SOURCES = tuple('eng/pilot/' + name for name in
    ('audit_retained_runtime.py','audit_probe_runtime.py','audit_linked_binding.py','probe-runtime-profile.json'))
EXTRA_FIELDS = ('publicationContinuationSha256','publicationReadbackSha256','heldDescriptorsSha256','runtimeCodeSha256')


def _source(session, image):
    packet.require(type(image) is publication.RetainedProbeImageBinding and image.session is session)
    retained = image._continuation
    packet.require(type(retained) is publication.RetainedPublication and retained.session is session)
    report = retained.report()
    packet.require(report['readbackVerified'] is True and runtime.runtime_profile() == runtime.PROFILE)
    pins = runtime._image_pins(session, image)
    binding = publication._record(session, 'publication-continuation-binding.json')
    copied = publication._record(session, 'publication-continuation-readback.json')
    packet.require(binding['controllerPid'] == os.getpid() and binding['nonce'] == session._plan['nonce'] and
        copied['schema'] == 'fleetory.publication-continuation-readback.v1' and
        copied['nonce'] == session._plan['nonce'] and copied['continuationSha256'] == report['bindingSha256'] and
        copied['imageBindingSha256'] == pins['imageBindingSha256'] and copied['imageId'] == pins['imageId'] and
        copied['bundleManifestSha256'] == pins['bundleManifestSha256'])
    return dict(pins, publicationContinuationSha256=report['bindingSha256'],
        publicationReadbackSha256=publication._pin(session, 'publication-continuation-readback.json'),
        heldDescriptorsSha256=report['heldDescriptorsSha256'])


def _source_pins(values):
    packet.require(type(values) is dict and set(values) == set(EXTRA_SOURCES))
    for value in values.values():packet.hex_value(value)
    return packet.digest(publication.prep.canonical(values))


def measure_sources(image):
    _source(image.session, image)
    return publication.prep._measure_sources(image._continuation._delivery.root.path, EXTRA_SOURCES)


def labels(image, pins):
    value = runtime.labels(image, pins)
    value.update({'fleetory.audit.control.profile':PURPOSE,
        'fleetory.audit.control.publication':pins['publicationContinuationSha256'],
        'fleetory.audit.control.runtime.code':pins['runtimeCodeSha256']})
    return value


def expiry(image):
    return min(image.intent['expiresNs'], image._continuation.expires)


def prepare(session, image, source_pins):
    pins = dict(_source(session, image), runtimeCodeSha256=_source_pins(source_pins))
    report = session.report()
    return container.canonical(dict(schema=SCHEMA, purpose=PURPOSE, nonce=report['nonce'], revision=session._plan['revision'],
        controlSha256=report['reservationSha256'], image=pins['imageId'], **pins, name=runtime.name(report['nonce']),
        labels=labels(image,pins), openedNs=time.time_ns(), expiresNs=expiry(image)))


class RetainedRuntimeBinding(runtime.ProbeRuntimeBinding):
    """One consumed backend slot with the exact retained source and four additional held code inputs."""
    _intent_schema, _purpose = SCHEMA, PURPOSE
    _record_schema = 'fleetory.retained-probe-runtime-binding.v1'
    _source_fields = runtime.SOURCE_FIELDS + EXTRA_FIELDS

    def __init__(self, session, data, expected_pin, image, *, source_pins):
        session.consume_backend_attempt()
        self._reserved_session, self._closed = session, False
        self._extra, self._pins = ExitStack(), []
        try:
            _source(session, image)
            self._code_pin = _source_pins(source_pins)
            root = image._continuation._delivery.root.path
            self._pins = [self._extra.enter_context(publication.prep._RootInputPin(root/name, source_pins[name]))
                for name in EXTRA_SOURCES]
            super().__init__(session, data, expected_pin, image)
        except BaseException:self.close();raise

    def _consume(self, session):
        packet.require(self._reserved_session is session)
        self._reserved_session = None

    def _source_anchor(self, session, image):
        packet.require(not self._closed)
        for pin in self._pins:pin.check()
        return dict(_source(session, image), runtimeCodeSha256=self._code_pin)

    def _source_expiry(self):
        return expiry(self._source)

    def _labels(self, session, pins):
        return labels(self._source, pins)

    @staticmethod
    def _observe(data, intent, returned_id, now):
        return runtime._observe_runtime(data, intent, returned_id, now, OBSERVATION_SCHEMA)

    def report(self):
        value = super().report()
        value.update(retainedPublicationSleepRuntimeBound=self._bound is not None,
            publicationContinuationSha256=self.intent['publicationContinuationSha256'],
            publicationReadbackSha256=self.intent['publicationReadbackSha256'],
            heldDescriptorsSha256=self.intent['heldDescriptorsSha256'], runtimeCodeSha256=self._code_pin,
            additionalRuntimeSourcesHeld=len(self._pins), admissionExpiresNs=self.intent['expiresNs'],
            liveServiceLeaseAuthorized=False, controllerDeathCleanupVerified=False)
        return value

    def close(self):
        self._closed = True
        self._extra.close()

    def __enter__(self):return self
    def __exit__(self,*_):self.close()


if __name__ == '__main__':raise SystemExit('Retained sleep metadata library only; no Docker, service, secret, PKI or cleanup CLI.')
