"""Held public native publication -> one fixed image/readback attempt; no Docker or private-input CLI."""
from contextlib import ExitStack, contextmanager
import json
import os
import re
import time

import audit_native_publication as native
import audit_probe_image as probe

packet, prep, ns = native.packet, native.prep, native.ns
WINDOW_NS = 60_000_000_000
SOURCES = (*native.SOURCES, 'eng/pilot/audit_backend_binding.py', 'eng/pilot/audit_image_binding.py',
    'eng/pilot/audit_probe_image.py', 'eng/pilot/audit_publication_continuation.py')


def _record(session, name):
    session.check()
    return json.loads(session._records[name][1])


def _pin(session, name):
    session.check()
    return packet.digest(session._records[name][1])


_Delivery = native.process._PublicationDelivery


class RetainedPublication:
    """An in-process capability. Native release does not close the transferred descriptors."""
    def __init__(self, bound, delivery):
        packet.require(type(bound) is ns.BoundPublication and type(delivery) is _Delivery and delivery.item is None)
        bound.check();delivery.check()
        packet.require(bound.acknowledged and type(bound.published) is ns.bundle.HeldProbeBundle)
        self.session, self._tree, self._delivery = bound.session, bound, delivery
        self._bundle, self.owner = bound.published, bound.owner_identity()
        self._closed, self._active, self._used, self._readback_attempted = False, False, False, False
        self._controller = os.getpid()
        self.opened, self._monotonic = time.time_ns(), time.monotonic_ns()
        self.expires = self.opened + WINDOW_NS
        self.release_pin, self.native_result = None, None
        self.descriptor_pin = self._descriptor_identity()
        receipt = _record(self.session, 'native-publication-receipt.json')
        packet.require(receipt['actualNativePublicationVerified'] is True and receipt['actualOwnedProcess'] == self.owner and
            receipt['manifestSha256'] == self._bundle.pin and receipt['fileDescriptorsHeld'] == len(self._bundle.pins))
        self.session._write_once('publication-continuation-attempt.json', dict(schema='fleetory.publication-continuation-attempt.v1',
            nonce=self.session._plan['nonce'], controllerPid=self._controller, actualOwnedProcess=self.owner,
            publicationReceiptSha256=_pin(self.session, 'native-publication-receipt.json'),
            bundleManifestSha256=self._bundle.pin, heldDescriptorsSha256=self.descriptor_pin, selectedSourceFiles=len(SOURCES),
            openedNs=self.opened, expiresNs=self.expires, operationalLeaseAuthorized=False))
        # Ownership moves before native release. No path is reopened to establish continuation.
        self._held = bound._held.pop_all()

    def _descriptor_identity(self):
        values = []
        for name, pin in self._bundle.pins.items():
            state = os.fstat(pin.fd)
            values.append([name, pin.fd, state.st_dev, state.st_ino])
        return packet.digest(prep.canonical(values))

    def _check_time(self):
        packet.require(not self._closed and os.getpid() == self._controller and
            self.opened <= time.time_ns() < self.expires and
            0 <= time.monotonic_ns() - self._monotonic < WINDOW_NS)

    def activate(self, result):
        packet.require(not self._active and type(result) is native.process.FencedResult and
            result.exit_code == 0 and result.stderr == b'')
        self._check_time();self._delivery.check();self.session.check();self._tree._check_tree()
        value = json.loads(result.evidence)
        packet.require(value['profile'] == 'native-publication-retain' and value['osIdentity'] == self.owner and
            value['processIdentityAuthenticated'] is True and value['launchAttemptConsumed'] is True and
            value['fence']['noRunningMembersVerified'] is True and
            value['payload']['actualNativePublicationVerified'] is True and
            value['payload']['publicationDescriptorsRetained'] is True and
            value['payload']['selectedSourceFilesPinned'] == len(SOURCES) and
            self._tree.released and self.release_pin == _pin(self.session, 'publication-release.json'))
        self.session._write_once('publication-continuation-binding.json', dict(schema='fleetory.publication-continuation-binding.v1',
            nonce=self.session._plan['nonce'], controllerPid=self._controller, actualOwnedProcess=self.owner,
            attemptSha256=_pin(self.session, 'publication-continuation-attempt.json'),
            releaseSha256=self.release_pin, nativeResultSha256=packet.digest(result.evidence),
            bundleManifestSha256=self._bundle.pin, fileDescriptorsHeld=len(self._bundle.pins),
            openedNs=self.opened, expiresNs=self.expires, nativeOwnerExited=True,
            backendCleanupAuthorized=False, operationalLeaseAuthorized=False))
        self._active, self.native_result = True, value
        self.check()

    def check(self):
        self._check_time();packet.require(self._active)
        self._delivery.check();self.session.check();self._tree._check_tree()
        packet.require(self._descriptor_identity() == self.descriptor_pin)

    def image(self, bases):
        self.check()
        packet.require(not self._used);self._used = True
        self.session._write_once('publication-continuation-use.json', dict(schema='fleetory.publication-continuation-use.v1',
            nonce=self.session._plan['nonce'], status='ATTEMPT_CONSUMED',
            continuationSha256=_pin(self.session, 'publication-continuation-binding.json')))
        self.check()
        data = probe.prepare(self.session, self._bundle, bases)
        return RetainedProbeImageBinding(self, data)

    def complete(self, resource, identifier, observation, copied):
        packet.require(not self._readback_attempted);self._readback_attempted = True
        self.session._write_once('publication-continuation-readback-attempt.json',
            dict(schema='fleetory.publication-continuation-readback-attempt.v1', nonce=self.session._plan['nonce'], status='ATTEMPT_CONSUMED'))
        self.check()
        packet.require(type(resource) is RetainedProbeImageBinding and resource._continuation is self and
            resource.session is self.session and resource._bound is not None and
            type(identifier) is str and re.fullmatch('[a-f0-9]{64}', identifier))
        resource.report()
        value = packet.strict_json(observation, probe.container.MAX_OBSERVATION)
        expected = dict(id=identifier, name='/fleetory-probe-copy-' + self.session._plan['nonce'].replace('-', ''),
            image=resource._bound, configImage=resource._bound,
            labels=dict(resource.intent['labels'], **{'fleetory.audit.control.copy':'public-probe-readback.v1'}),
            running=False, status='created', pid=0, network='none', mounts=[], readonly=True, privileged=False,
            user='3322:3322', entrypoint=['/bin/true'])
        packet.keys(value, ' '.join(expected))
        packet.require(value == expected and type(value['pid']) is int and value['running'] is False and
            value['readonly'] is True and value['privileged'] is False)
        checked = ns.bundle.verify_readback(copied, self._bundle)
        self.check();resource.report()
        self.session._write_once('publication-continuation-readback.json', dict(schema='fleetory.publication-continuation-readback.v1',
            nonce=self.session._plan['nonce'], continuationSha256=_pin(self.session, 'publication-continuation-binding.json'),
            imageBindingSha256=_pin(self.session, 'image-binding.json'), imageId=resource._bound, containerId=identifier,
            stoppedObservationSha256=packet.digest(observation), readbackSha256=packet.digest(copied),
            bundleManifestSha256=self._bundle.pin, files=checked['files'], bytes=checked['bytes'],
            operationalLeaseAuthorized=False, backendCleanupAuthorized=False))
        self.check();return checked

    def report(self):
        self.check()
        return dict(schema='fleetory.publication-continuation-result.v1', nativeOwnerExited=True,
            samePublicationDescriptorsHeld=True, fileDescriptorsHeld=len(self._bundle.pins),
            bindingSha256=_pin(self.session, 'publication-continuation-binding.json'), heldDescriptorsSha256=self.descriptor_pin,
            bundleManifestSha256=self._bundle.pin, openedNs=self.opened, expiresNs=self.expires,
            imageAttemptConsumed=self._used, readbackVerified='publication-continuation-readback.json' in self.session._records,
            controllerDeathCleanupVerified=False, operationalLeaseAuthorized=False, backendCleanupAuthorized=False,
            fullSystemRecoveryVerified=False, phase7Complete=False)

    def close(self):
        self._closed = True
        self._held.close()


class RetainedProbeImageBinding(probe.ProbeImageBinding):
    def __init__(self, continuation, data):
        packet.require(type(continuation) is RetainedPublication)
        self._continuation = continuation
        continuation.check()
        packet.require(continuation._used and 'publication-continuation-use.json' in continuation.session._records)
        super().__init__(continuation.session, data, packet.digest(data), continuation._bundle)
        self._check()

    def _check(self):
        self._continuation.check()
        super()._check()


class _ContinuationPumps(native._NativePublicationPumps):
    source_names = SOURCES
    profile = 'native-publication-retain'

    def _release_publication(self):
        delivery = self.command.continuation
        packet.require(type(delivery) is _Delivery and delivery.item is None)
        delivery.item = RetainedPublication(self.bound, delivery)
        pin = super()._release_publication()
        delivery.item.release_pin = pin
        return pin

    def finalize_binding(self, child, ended, failed):
        super().finalize_binding(child, ended, failed)
        self.resource_metadata.update(selectedSourceFilesPinned=len(SOURCES),
            publicationDescriptorsRetained=self.command.continuation.item is not None and
                self.resource_metadata['actualNativePublicationVerified'] is True)


@contextmanager
def retain_owner(repository, powershell, python, git, dotnet, native_plan, source_pins, session, *, git_sha256, dotnet_sha256, manifest):
    """One fixed native publication, then a controller-only 60-second capability; close never deletes files."""
    packet.require(type(source_pins) is dict and set(source_pins) == set(SOURCES))
    with ExitStack() as held:
        root = held.enter_context(native.control.DirectoryLease(repository))
        sources = tuple(held.enter_context(prep._RootInputPin(root.path / name, source_pins[name])) for name in SOURCES)
        delivery = _Delivery(root, sources)
        try:
            result = prep._prepare_owner(root.path, powershell, python, git, native_plan, source_pins, session, git_sha256,
                _ContinuationPumps, publication=(dotnet, dotnet_sha256, manifest), continuation=delivery)
            packet.require(delivery.item is not None)
            delivery.item.activate(result)
            yield delivery.item
        finally:
            if delivery.item is not None:delivery.item.close()


def measure_sources(repository):
    return prep._measure_sources(repository, SOURCES)


if __name__ == '__main__':raise SystemExit('Public continuation library only; no command, Docker, secret, PKI or cleanup CLI.')
