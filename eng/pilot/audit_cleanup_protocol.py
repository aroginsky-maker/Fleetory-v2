"""Metadata-only public sleep cleanup protocol model. No executor or cleanup capability is provided."""
import re
import time

import audit_retained_runtime as runtime

packet, C = runtime.packet, runtime.container.canonical
SCHEMA = 'fleetory.public-sleep-cleanup-protocol.v1'
PURPOSE = 'one-own-sleep-worker-cleanup-model.v1'
PROCESS_SCHEMA = 'fleetory.asserted-cleanup-process.v1'
RESOURCE_SCHEMA = 'fleetory.asserted-own-sleep-container.v1'
CREATE_SCHEMA = 'fleetory.asserted-own-sleep-create.v1'
MAX_FRAME = 8192
GRACE_NS = 10_000_000_000
ADMISSION_NS = 60_000_000_000
HASHES = ('reservationSha256 imageBindingSha256 runtimeIntentSha256 runtimeBindingSha256 publicationContinuationSha256 '
    'publicationReadbackSha256 heldDescriptorsSha256 runtimeCodeSha256 bundleManifestSha256 labelsSha256 createReceiptSha256').split()
FIELDS = ('schema purpose nonce supervisorNonce controller supervisor imageId containerId containerName '
    'openedNs createdNs admissionExpiresNs cleanupExpiresNs commandLifetimeSeconds runtimeProfileSha256 ' + ' '.join(HASHES))


def _identity(value):
    packet.keys(value, 'pid birthKind birthToken executableSha256')
    packet.require(type(value['pid']) is int and 0 < value['pid'] <= 0xffffffff and
        value['birthKind'] in ('windows-filetime','linux-proc-start-ticks') and
        type(value['birthToken']) is str and re.fullmatch('[1-9][0-9]{0,19}',value['birthToken']))
    packet.hex_value(value['executableSha256'])


def _frame(data):
    packet.require(type(data) in (bytes,bytearray) and 0 < len(data) <= MAX_FRAME)
    return packet.strict_json(bytes(data),MAX_FRAME)


def _ticket(data, expected):
    packet.hex_value(expected)
    value = _frame(data);packet.require(packet.digest(data)==expected)
    packet.keys(value,FIELDS)
    packet.require(value['schema']==SCHEMA and value['purpose']==PURPOSE)
    packet.identity(value['nonce']);packet.identity(value['supervisorNonce'])
    packet.require(value['nonce']!=value['supervisorNonce'])
    _identity(value['controller']);_identity(value['supervisor'])
    packet.require(value['controller']['pid']!=value['supervisor']['pid'] and
        value['controller']['birthKind']==value['supervisor']['birthKind'])
    for key in HASHES:packet.hex_value(value[key])
    runtime.container.image_id(value['imageId']);packet.hex_value(value['containerId'])
    packet.require(value['containerName']==runtime.runtime.name(value['nonce']) and
        value['runtimeProfileSha256']==runtime.runtime.PROFILE_SHA256 and
        type(value['commandLifetimeSeconds']) is int and value['commandLifetimeSeconds']==660)
    packet.require(all(type(value[k]) is int for k in ('openedNs','createdNs','admissionExpiresNs','cleanupExpiresNs')))
    packet.require(0 < value['openedNs'] <= value['createdNs'] < value['admissionExpiresNs'] and
        0 < value['admissionExpiresNs']-value['openedNs'] <= ADMISSION_NS and
        value['cleanupExpiresNs']==value['admissionExpiresNs']+GRACE_NS)
    return value


def _process(data, identity, *, supervisor=False):
    value = _frame(data)
    packet.keys(value,'schema identity state')
    _identity(value['identity'])
    packet.require(value['schema']==PROCESS_SCHEMA and value['identity']==identity and
        value['state'] in (('live',) if supervisor else ('live','exited')))
    return value['state']


def _container(value, ticket):
    packet.require(value['id']==ticket['containerId'] and
        value['name']=='/'+ticket['containerName'] and value['imageId']==ticket['imageId'])
    labels=value['labels']
    packet.require(type(labels) is dict and 0 < len(labels) <= 16)
    for key,text in labels.items():
        packet.require(type(key) is str and re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}',key) and
            type(text) is str and len(text)<=1024 and all(ord(c)>=32 for c in text))
    pins={'nonce':'nonce','reservation':'reservationSha256','image.binding':'imageBindingSha256',
        'publication':'publicationContinuationSha256','runtime.code':'runtimeCodeSha256',
        'probe.bundle':'bundleManifestSha256','runtime.profile':'runtimeProfileSha256'}
    packet.require(all(labels.get('fleetory.audit.control.'+label)==ticket[key] for label,key in pins.items()) and
        labels.get('fleetory.audit.control.profile')==runtime.PURPOSE and packet.digest(C(labels))==ticket['labelsSha256'])


def _resource(data, ticket):
    value=_frame(data);packet.keys(value,'schema id name imageId labels')
    packet.require(value['schema']==RESOURCE_SCHEMA)
    _container(value,ticket)


def _receipt(data, ticket):
    value=_frame(data)
    packet.keys(value,'schema nonce reservationSha256 id name imageId labels createdNs runtimeIntentSha256')
    packet.require(packet.digest(data)==ticket['createReceiptSha256'] and value['schema']==CREATE_SCHEMA and
        value['nonce']==ticket['nonce'] and value['reservationSha256']==ticket['reservationSha256'] and
        type(value['createdNs']) is int and value['createdNs']==ticket['createdNs'] and
        value['runtimeIntentSha256']==ticket['runtimeIntentSha256'])
    _container(value,ticket)


class CleanupProtocolModel:
    """Candidate checks only. A model result never authorizes a Docker or process operation."""
    def __init__(self, data, expected):
        self._value = _ticket(data,expected)
        self._data,self._pin = bytes(data),expected
        self._value_pin = packet.digest(C(self._value))
        now,mono=time.time_ns(),time.monotonic_ns()
        packet.require(type(now) is int and type(mono) is int and
            self._value['createdNs'] <= now < self._value['admissionExpiresNs'])
        self._last_wall,self._last_mono = now,mono
        self._deadline = mono+self._value['cleanupExpiresNs']-now
        self._state,self._reason,self._request = 'armed',None,None

    def _clock(self):
        packet.require(packet.digest(self._data)==self._pin and packet.digest(C(self._value))==self._value_pin)
        now,mono=time.time_ns(),time.monotonic_ns()
        packet.require(type(now) is int and type(mono) is int and
            self._last_wall <= now < self._value['cleanupExpiresNs'] and self._last_mono <= mono < self._deadline)
        self._last_wall,self._last_mono=now,mono
        return now

    def evaluate(self, controller, supervisor, create_receipt, resource):
        packet.require(self._state=='armed')
        try:
            now=self._clock()
            state=_process(controller,self._value['controller'])
            _process(supervisor,self._value['supervisor'],supervisor=True)
            _receipt(create_receipt,self._value)
            _resource(resource,self._value)
            if state=='live' and now<self._value['admissionExpiresNs']:
                return self.report()
            # Consume before returning a proposal to a future independently verified enforcer.
            self._state='consumed'
            self._reason='asserted-controller-exit' if state=='exited' else 'model-admission-expired'
            self._request=dict(schema='fleetory.cleanup-model-candidate.v1',ticketSha256=self._pin,
                nonce=self._value['nonce'],supervisorNonce=self._value['supervisorNonce'],
                containerId=self._value['containerId'],imageId=self._value['imageId'],
                controllerAssertionSha256=packet.digest(controller),supervisorAssertionSha256=packet.digest(supervisor),
                createReceiptSha256=packet.digest(create_receipt),resourceAssertionSha256=packet.digest(resource),reason=self._reason,observedAtNs=now,
                cleanupAuthorized=False)
            return self.report()
        except Exception:
            self._state,self._reason='refused','protocol-model-refused'
            raise ValueError('Cleanup protocol model refused.') from None

    def report(self):
        return dict(schema='fleetory.cleanup-protocol-model-result.v1',state=self._state,reason=self._reason,
            attemptConsumed=self._state!='armed',candidate=None if self._request is None else dict(self._request),
            decision='await-model-trigger' if self._state=='armed' else ('trusted-enforcer-required' if self._state=='consumed' else 'refused'),
            ticketSha256=self._pin,actualProcessIdentityVerified=False,createReceiptOriginAuthenticated=False,
            durableAttemptStoreVerified=False,actualCleanupExecuted=False,independentExpiryEnforcementVerified=False,
            controllerDeathCleanupVerified=False,supervisorDeathCleanupVerified=False,operationalLeaseAuthorized=False,
            backendCleanupAuthorized=False,originalInputsRead=False,originalPrivatePkiUsed=False,sourceVpsAccessed=False,
            fullSystemRecoveryVerified=False,phase7Complete=False)


if __name__=='__main__':raise SystemExit('Cleanup protocol model only; no Docker, process, path, deletion, secret or PKI executor CLI.')
