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


def guardian_preparation_name(nonce,*,ready=False):
    packet.require(type(ready) is bool)
    return ('retained-public-guard-ready-' if ready else 'retained-public-guard-attempt-')+packet.identity(nonce)+'.json'


class RetainedGuardPreparation:
    """Typed live-source preparation only. Persisted metadata cannot authorize a launcher."""
    def __init__(self,session,target,trusted_operator_root,*,python_path,python_sha256,docker_path,docker_sha256,source_pins):
        # Local imports keep the old retained runtime's import/source inventories unchanged.
        import audit_public_cleanup_guard as guard
        from pathlib import Path
        import sys
        self._guard,self._held,self._closed=guard,ExitStack(),False
        self._caller,self._session,self._target=os.getpid(),session,target
        self._ready=None
        try:
            packet.require(type(session) is publication.native.control.ControlIdentity)
            current=session.report();nonce=current['nonce']
            consumed=dict(schema='fleetory.retained-guard-preparation-attempt.v1',nonce=nonce,
                status='PREPARATION_CONSUMED',reservationSha256=current['reservationSha256'],assertedControllerPid=self._caller,
                launchAuthorized=False,cleanupAuthorized=False)
            self._attempt=self._held.enter_context(guard.attempts._claim_record(trusted_operator_root,guardian_preparation_name(nonce),consumed))
            self._source()
            self._root=target._source._continuation._delivery.root.path
            packet.require(type(source_pins) is dict and set(source_pins)==set(guard.SOURCES))
            frozen=dict(source_pins)
            self._sources=tuple(self._held.enter_context(guard.process.PinnedFile(self._root/name,frozen[name])) for name in guard.SOURCES)
            self._python=self._held.enter_context(guard.process.PinnedFile(python_path,python_sha256,True))
            packet.require(self._python.path==Path(sys.executable).resolve(strict=True))
            self._docker=self._held.enter_context(guard.process.PinnedFile(docker_path,docker_sha256,True))
            packet.require(self._docker.path.name.lower() in ('docker','docker.exe'))
            actual=guard.identity.current_identity(self._python)
            self._peer=self._held.enter_context(guard.identity.HeldLocalPeer('self',self._python,actual))
            self._snapshot=publication.prep.canonical(self._capture(actual,frozen))
            self.check()
            ready=packet.strict_json(self._snapshot,8192)
            self._ready=self._held.enter_context(guard.attempts._claim_record(trusted_operator_root,guardian_preparation_name(nonce,ready=True),ready))
            self.check()
        except BaseException:self.close();raise

    def _source(self):
        packet.require(not self._closed and os.getpid()==self._caller and type(self._target) is RetainedRuntimeBinding and self._target.session is self._session)
        result=self._target.report()
        packet.require(self._target._bound is None and not self._target._attempted and
            result['retainedPublicationSleepRuntimeBound'] is False and not result['observationAttemptConsumed'] and
            'backend-binding-attempt.json' not in self._session._records and 'backend-binding.json' not in self._session._records)
        recorded=publication._record(self._session,'backend-intent.json')
        packet.require(recorded['schema']==SCHEMA and recorded['intentSha256']==self._target._pin and
            publication.prep.canonical(recorded['intent'])==publication.prep.canonical(self._target.intent) and
            packet.digest(self._target._intent_bytes)==recorded['intentSha256'])
        self._target._source._continuation.check()
        return self._target._source._continuation.report()

    def _capture(self,actual,pins):
        source=self._source();intent=self._target.intent
        return dict(schema='fleetory.retained-guard-preparation.v1',purpose='retained-publication-guardian-preparation.v1',
            status='PREPARED_NO_DISPATCH',nonce=intent['nonce'],revision=intent['revision'],controller=actual,
            reservationSha256=intent['controlSha256'],runtimeIntentSha256=self._target._pin,
            frozenRuntimeIntentSha256=packet.digest(self._target._intent_bytes),
            lineage={key:intent[key] for key in runtime.SOURCE_FIELDS+EXTRA_FIELDS},
            publicationDescriptorsHeld=source['fileDescriptorsHeld'],sourcePinsSha256=packet.digest(publication.prep.canonical(pins)),
            sourceFilesPinned=len(self._sources),pythonSha256=self._python.digest,dockerSha256=self._docker.digest,
            admissionExpiresNs=intent['expiresNs'],actualPreparingControllerIdentityVerified=True,
            exactUnboundRetainedSourceChecked=True,publicationAndReadbackCapabilitiesHeld=True,
            localPreparationAttemptFlushed=True,preparationReplayRefusedWhileRecordRetained=True,
            guardianProcessStarted=False,ownDockerCreateReceiptAvailable=False,dockerOperationsPerformed=0,
            launchAuthorized=False,cleanupAuthorized=False,retainedControllerDeathCleanupVerified=False,
            retainedExpiryCleanupVerified=False,publicationOriginAuthenticated=False,dependenciesAuthenticated=False,
            independentRollbackResistanceVerified=False,originalInputsRead=False,originalPrivatePkiUsed=False,
            sourceVpsAccessed=False,fullSystemRecoveryVerified=False,phase7Complete=False)

    def check(self):
        self._source();self._attempt.check()
        for source in self._sources:source.check()
        self._python.check();self._docker.check()
        peer=self._peer.snapshot();packet.require(peer['state']=='live')
        # Capture contains no current timestamps, mutable resource ID or caller-owned dictionary.
        saved=packet.strict_json(self._snapshot,8192)
        current=self._capture(peer['identity'],{name:pin.digest for name,pin in zip(self._guard.SOURCES,self._sources)})
        packet.require(publication.prep.canonical(current)==self._snapshot and
            saved['runtimeIntentSha256']==saved['frozenRuntimeIntentSha256'])
        if self._ready is not None:self._ready.check()

    def report(self):
        self.check()
        packet.require(self._ready is not None)
        return packet.strict_json(self._snapshot,8192)

    def close(self):
        self._closed=True
        self._held.close()

    def __enter__(self):return self
    def __exit__(self,*_):self.close()


if __name__ == '__main__':raise SystemExit('Retained sleep metadata library only; no Docker, service, secret, PKI or cleanup CLI.')
