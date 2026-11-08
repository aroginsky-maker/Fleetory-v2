"""Fixed generated probe runtime metadata; no Docker, launch, cleanup or private-input authority."""
import json
import time

import audit_linked_binding as linked
import audit_probe_image as probe

container, packet = linked.container, linked.packet
SCHEMA = 'fleetory.audit-probe-runtime-intent.v1'
PURPOSE = 'generated-probe-runtime-control-binding.v1'
OBSERVATION_SCHEMA = 'fleetory.audit-probe-runtime-observation.v1'
COMMAND = ['-c', 'exec /bin/sleep 660']
TMPFS = {'/data': 'rw,noexec,nosuid,nodev,size=256m,uid=3322,gid=3322,mode=0700',
    '/tmp': 'rw,noexec,nosuid,nodev,size=32m,uid=3322,gid=3322,mode=0700'}
ENVIRONMENT = ['PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', 'APP_UID=1654',
    'ASPNETCORE_HTTP_PORTS=8080', 'DOTNET_RUNNING_IN_CONTAINER=true', 'DOTNET_VERSION=10.0.14', 'ASPNET_VERSION=10.0.14']
SOURCE_FIELDS = ('imageId', 'imageBindingSha256', 'imageIntentSha256', 'bundleManifestSha256', 'sourceCodeSha256')


def anchor(session, source):
    packet.require(type(source) is probe.ProbeImageBinding and source.session is session)
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
        sourceCodeSha256=saved['sourceCodeSha256'])


def name(nonce):
    return 'fleetory-probe-runtime-' + packet.identity(nonce).replace('-', '')


def labels(source, pins):
    value = dict(source.intent['labels'])
    value.update({'fleetory.audit.control.profile': PURPOSE, 'fleetory.audit.control.image.binding': pins['imageBindingSha256']})
    return value


def prepare(session, source):
    pins = anchor(session, source)
    report = session.report()
    return container.canonical(dict(schema=SCHEMA, purpose=PURPOSE, nonce=report['nonce'], revision=session._plan['revision'],
        controlSha256=report['reservationSha256'], image=pins['imageId'], **pins, name=name(report['nonce']),
        labels=labels(source, pins), openedNs=time.time_ns(), expiresNs=source.intent['expiresNs']))


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
        value, created = container._container_identity(data, intent, returned_id, now, OBSERVATION_SCHEMA,
            container.OBSERVATION_FIELDS + ' environment ulimits')
        packet.require(value['configImage'] == intent['imageId'] and value['user'] == '3322:3322' and
            value['entrypoint'] == ['/bin/sh'] and value['command'] == COMMAND and value['environment'] == ENVIRONMENT)
        container._container_sandbox(value)
        packet.require(all(type(value[n]) is int and value[n] == limit for n, limit in
            (('memory', 402653184), ('nanoCpus', 1000000000), ('pidsLimit', 128))))
        packet.require(value['tmpfs'] == TMPFS and value['ulimits'] == [{'Name': 'core', 'Soft': 0, 'Hard': 0}])
        packet.require(all(type(value['ulimits'][0][key]) is int for key in ('Soft', 'Hard')))
        return value, created

    def report(self):
        result = super().report()
        result.update(generatedProbeRuntimeBound=self._bound is not None, sourceImageAdmissionExpiryNs=self.intent['expiresNs'],
            sourceBundleManifestSha256=self.intent['bundleManifestSha256'], operationalLeaseAuthorized=False,
            backendServiceStartedVerified=False, actualProbeNativeOwnerAcknowledged=False, backendCleanupAuthorized=False)
        return result


if __name__ == '__main__':
    raise SystemExit('Probe runtime metadata library; no Docker, command, secret, cleanup or original-data CLI.')
