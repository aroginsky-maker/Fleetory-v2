"""Fixed generated probe runtime metadata; no Docker, launch, cleanup or private-input authority."""
import json
from pathlib import Path
import time

import audit_linked_binding as linked
import audit_probe_image as probe

container, packet = linked.container, linked.packet
SCHEMA = 'fleetory.audit-probe-runtime-intent.v1'
PURPOSE = 'generated-probe-runtime-control-binding.v1'
OBSERVATION_SCHEMA = 'fleetory.audit-probe-runtime-observation.v1'
PROFILE_SHA256 = '5402adcd0d010f4bc2e6b7c78d6f16ddbcbd3f3ad4ebab5f111e8c9fb17e034f'


def runtime_profile():
    # Container paths are declarative Docker data, never host filesystem targets.
    # Only this fixed public profile file is opened; its complete bytes are pinned.
    with probe.bundle.control.DirectoryLease(Path(__file__).absolute().parent) as directory:
        digest, _, raw = probe.bundle.files.inspect_file(directory.path, directory.fd,
            'probe-runtime-profile.json', 4096, retain=True)
    packet.require(digest == PROFILE_SHA256)
    value = packet.strict_json(raw, 4096)
    packet.keys(value, 'schema user entrypoint command tmpfs environment memoryBytes nanoCpus pidsLimit ulimits')
    packet.require(value['schema'] == 'fleetory.probe-runtime-profile.v1')
    return value


PROFILE = runtime_profile()
COMMAND, TMPFS, ENVIRONMENT = PROFILE['command'], PROFILE['tmpfs'], PROFILE['environment']
SOURCE_FIELDS = ('imageId', 'imageBindingSha256', 'imageIntentSha256', 'bundleManifestSha256', 'sourceCodeSha256', 'runtimeProfileSha256')


def anchor(session, source):
    packet.require(runtime_profile() == PROFILE)
    packet.require(type(source) is probe.ProbeImageBinding and source.session is session)
    return _image_pins(session, source)


def _image_pins(session, source):
    report = source.report()
    packet.require(report['generatedProbeImageRecipeBound'] is True)
    raw = session._records['image-binding.json'][1]
    saved = json.loads(raw)
    packet.require(saved['schema'] == 'fleetory.audit-probe-image-binding.v1' and saved['imageId'] == report['imageId'] and
        saved['intentSha256'] == report['intentSha256'] and saved['reservationSha256'] == session.report()['reservationSha256'])
    packet.require(saved['bundleManifestSha256'] == source.intent['bundleManifestSha256'] and
        saved['sourceCodeSha256'] == session._plan['codeSha256'] and saved['contextSha256'] == source.intent['contextSha256'])
    return dict(imageId=container.image_id(report['imageId']), imageBindingSha256=packet.digest(raw),
        imageIntentSha256=report['intentSha256'], bundleManifestSha256=saved['bundleManifestSha256'],
        sourceCodeSha256=saved['sourceCodeSha256'], runtimeProfileSha256=PROFILE_SHA256)


def name(nonce):
    return 'fleetory-probe-runtime-' + packet.identity(nonce).replace('-', '')


def labels(source, pins):
    value = dict(source.intent['labels'])
    value.update({'fleetory.audit.control.profile': PURPOSE, 'fleetory.audit.control.image.binding': pins['imageBindingSha256'],
        'fleetory.audit.control.runtime.profile': PROFILE_SHA256})
    return value


def prepare(session, source):
    pins = anchor(session, source)
    report = session.report()
    return container.canonical(dict(schema=SCHEMA, purpose=PURPOSE, nonce=report['nonce'], revision=session._plan['revision'],
        controlSha256=report['reservationSha256'], image=pins['imageId'], **pins, name=name(report['nonce']),
        labels=labels(source, pins), openedNs=time.time_ns(), expiresNs=source.intent['expiresNs']))


def _observe_runtime(data, intent, returned_id, now, schema):
    value, created = container._container_identity(data, intent, returned_id, now, schema,
        container.OBSERVATION_FIELDS + ' environment ulimits')
    _runtime_profile(value,intent)
    return value,created


def _runtime_profile(value,intent):
    packet.require(value['configImage'] == intent['imageId'] and value['user'] == PROFILE['user'] and
        value['entrypoint'] == PROFILE['entrypoint'] and value['command'] == COMMAND and value['environment'] == ENVIRONMENT)
    container._container_sandbox(value)
    packet.require(all(type(value[n]) is int and value[n] == limit for n, limit in
        (('memory', PROFILE['memoryBytes']), ('nanoCpus', PROFILE['nanoCpus']), ('pidsLimit', PROFILE['pidsLimit']))))
    packet.require(value['tmpfs'] == TMPFS and value['ulimits'] == PROFILE['ulimits'])
    packet.require(all(type(value['ulimits'][0][key]) is int for key in ('Soft', 'Hard')))


class ProbeRuntimeBinding(linked.LinkedContainerBinding):
    """A distinct fixed profile; source expiry remains the 60-second image admission lease."""
    _intent_schema, _purpose = SCHEMA, PURPOSE
    _record_schema = 'fleetory.audit-probe-runtime-binding.v1'
    _source_fields, _source_anchor = SOURCE_FIELDS, staticmethod(anchor)
    _name = staticmethod(name)

    def _labels(self, session, pins):
        return labels(self._source, pins)

    @staticmethod
    def _observe(data, intent, returned_id, now):
        return _observe_runtime(data, intent, returned_id, now, OBSERVATION_SCHEMA)

    def report(self):
        result = super().report()
        result.update(generatedProbeRuntimeBound=self._bound is not None, sourceImageAdmissionExpiryNs=self.intent['expiresNs'],
            sourceBundleManifestSha256=self.intent['bundleManifestSha256'], runtimeProfileSha256=PROFILE_SHA256, operationalLeaseAuthorized=False,
            backendServiceStartedVerified=False, actualProbeNativeOwnerAcknowledged=False, backendCleanupAuthorized=False)
        return result


if __name__ == '__main__':
    raise SystemExit('Probe runtime metadata library; no Docker, command, secret, cleanup or original-data CLI.')
