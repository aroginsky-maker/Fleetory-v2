"""Consumed generated-container metadata binding. No Docker, cleanup or original-data API."""
import calendar
from datetime import datetime
import json
import re
import time

import fresh_server_pair as packet
from recovery_isolation import IMAGE

SCHEMA = 'fleetory.audit-generated-container-intent.v1'
PURPOSE = 'generated-container-control-binding.v1'
MAX_INTENT, MAX_OBSERVATION = 4096, 8192
WINDOW_NS = 60_000_000_000
COMMAND = ['-I', '-B', '-c', 'import time; time.sleep(120)']


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode('ascii')


def container_name(nonce):
    return 'fleetory-audit-bound-' + packet.identity(nonce).replace('-', '')


def labels(nonce, reservation):
    packet.identity(nonce)
    packet.hex_value(reservation)
    return {'fleetory.audit.control.nonce': nonce, 'fleetory.audit.control.reservation': reservation,
            'fleetory.audit.control.profile': PURPOSE}


def image_id(value):
    packet.require(type(value) is str and re.fullmatch('sha256:[a-f0-9]{64}', value))
    return value


def prepare(session, expected_image_id):
    """Trusted caller preparation; neither image-origin nor execution authorization."""
    report = session.report()
    now = time.time_ns()
    return canonical(dict(schema=SCHEMA, purpose=PURPOSE, nonce=report['nonce'],
        revision=session._plan['revision'], controlSha256=report['reservationSha256'], image=IMAGE,
        imageId=image_id(expected_image_id), name=container_name(report['nonce']),
        labels=labels(report['nonce'], report['reservationSha256']), openedNs=now, expiresNs=now + WINDOW_NS))


def admit(data, expected, session):
    packet.hex_value(expected)
    packet.require(type(data) in (bytes, bytearray) and 0 < len(data) <= MAX_INTENT)
    frozen = bytes(data)
    packet.require(packet.digest(frozen) == expected)
    value = packet.strict_json(frozen, MAX_INTENT)
    packet.keys(value, 'schema purpose nonce revision controlSha256 image imageId name labels openedNs expiresNs')
    report = session.report()
    packet.require(value['schema'] == SCHEMA and value['purpose'] == PURPOSE and value['image'] == IMAGE)
    packet.require(value['nonce'] == report['nonce'] and value['revision'] == session._plan['revision'] and
                   value['controlSha256'] == report['reservationSha256'])
    packet.require(value['name'] == container_name(report['nonce']) and
                   value['labels'] == labels(report['nonce'], report['reservationSha256']))
    image_id(value['imageId'])
    packet.require(type(value['openedNs']) is int and type(value['expiresNs']) is int and
                   value['expiresNs'] - value['openedNs'] == WINDOW_NS and
                   session._created <= value['openedNs'] <= time.time_ns() < value['expiresNs'])
    return value, frozen


def timestamp_ns(value):
    packet.require(type(value) is str)
    match = re.fullmatch(r'([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})(?:\.([0-9]{1,9}))?Z', value)
    packet.require(match is not None)
    seconds = calendar.timegm(datetime.strptime(match[1], '%Y-%m-%dT%H:%M:%S').timetuple())
    return seconds * 1_000_000_000 + int((match[2] or '').ljust(9, '0'))


def observation(data, intent, returned_id, now):
    packet.require(type(returned_id) is str and re.fullmatch('[a-f0-9]{64}', returned_id))
    value = packet.strict_json(data, MAX_OBSERVATION)
    packet.keys(value, 'schema id name imageId created labels configImage user entrypoint command running paused restarting dead '
        'networkMode networks readonly privileged capDrop capAdd securityOpt memory nanoCpus pidsLimit mounts ports '
        'portBindings binds tmpfs volumesFrom devices deviceRequests pidMode ipcMode utsMode usernsMode restart autoRemove publishAllPorts')
    packet.require(value['schema'] == 'fleetory.audit-generated-container-observation.v1' and
                   value['id'] == returned_id and value['name'] == '/' + intent['name'] and
                   value['imageId'] == intent['imageId'] and value['labels'] == intent['labels'])
    created = timestamp_ns(value['created'])
    packet.require(intent['openedNs'] <= created <= now < intent['expiresNs'])
    packet.require(value['configImage'] == IMAGE and value['user'] == '65534:65534' and
                   value['entrypoint'] == ['python'] and value['command'] == COMMAND)
    packet.require(value['running'] is True and all(value[n] is False for n in ('paused', 'restarting', 'dead', 'privileged', 'publishAllPorts')))
    packet.require(value['networkMode'] == 'none' and type(value['networks']) is dict and set(value['networks']) == {'none'})
    packet.require(value['readonly'] is True and value['autoRemove'] is True and value['capDrop'] == ['ALL'] and
                   value['securityOpt'] == ['no-new-privileges:true'])
    packet.require(all(type(value[n]) is int and value[n] == limit for n, limit in
        (('memory', 67108864), ('nanoCpus', 250000000), ('pidsLimit', 32))))
    packet.require(value['mounts'] == [] and all(value[n] is None or value[n] == [] for n in
        ('capAdd', 'binds', 'volumesFrom', 'devices', 'deviceRequests')))
    packet.require(all(value[n] is None or value[n] == {} for n in ('ports', 'portBindings', 'tmpfs')))
    packet.require(all(value[n] == '' for n in ('pidMode', 'utsMode', 'usernsMode')) and value['ipcMode'] == 'private')
    packet.require(value['restart'] == {'Name': 'no', 'MaximumRetryCount': 0} and
                   type(value['restart']['MaximumRetryCount']) is int)
    return value, created


class ContainerBinding:
    """One held controller, one consumed intent and one consumed observation attempt."""
    def __init__(self, session, data, expected_pin):
        session.consume_backend_attempt()
        self.session = session
        self.intent, self._intent_bytes = admit(data, expected_pin, session)
        self._pin = expected_pin
        self._attempted, self._bound = False, None
        self._deadline = time.monotonic() + min(60, (self.intent['expiresNs'] - time.time_ns()) / 1_000_000_000)
        session._write_once('backend-intent.json', dict(schema=SCHEMA, intent=self.intent,
            intentSha256=expected_pin, backendCreationAuthorized=False, cleanupAuthorized=False))
        self._check()

    def _check(self):
        self.session.check()
        packet.require(self.intent['openedNs'] <= time.time_ns() < self.intent['expiresNs'] and time.monotonic() < self._deadline)
        packet.require(packet.digest(canonical(self.intent)) == packet.digest(canonical(json.loads(self._intent_bytes))))

    def bind(self, data, returned_id):
        self._check()
        packet.require(not self._attempted)
        self._attempted = True
        self.session._write_once('backend-binding-attempt.json', dict(schema='fleetory.audit-backend-binding-attempt.v1',
            nonce=self.intent['nonce'], intentSha256=self._pin, status='ATTEMPT_CONSUMED', cleanupAuthorized=False))
        packet.require(type(data) in (bytes, bytearray) and 0 < len(data) <= MAX_OBSERVATION)
        frozen = bytes(data)
        now = time.time_ns()
        value, created = observation(frozen, self.intent, returned_id, now)
        self._check()
        self.session._write_once('backend-binding.json', dict(schema='fleetory.audit-generated-container-binding.v1',
            nonce=self.intent['nonce'], reservationSha256=self.intent['controlSha256'], intentSha256=self._pin,
            containerId=value['id'], name=value['name'], imageId=value['imageId'], createdNs=created,
            observedAtNs=now, observationSha256=packet.digest(frozen), cleanupAuthorized=False))
        # A flush that crosses either deadline must not return an accepted binding.
        self._check()
        self._bound = value['id']
        return self.report()

    def report(self):
        self._check()
        return dict(schema='fleetory.audit-generated-container-binding-result.v1', nonce=self.intent['nonce'],
            intentSha256=self._pin, intentRecorded=True, observationAttemptConsumed=self._attempted,
            generatedContainerIdBound=self._bound is not None, containerId=self._bound,
            dockerObservationAuthenticated=False, runtimeContinuityVerified=False, legacyNativeOwnerIntegrated=False,
            backendNamespaceBound=False, cleanupAuthorized=False, backendCleanupVerified=False,
            originalInputsRead=False, executionAuthorized=False, fullSystemRecoveryVerified=False, phase7Complete=False)


if __name__ == '__main__':
    raise SystemExit('Generated container binding is a metadata library; no Docker, cleanup or data CLI is provided.')
