"""Distinct trusted-operator four-file purpose. No permission, native or root CLI."""
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
import os
import re
from pathlib import Path
import threading
import time
import weakref

from historical import retained_service_use as legacy

packet, C, H = legacy.packet, legacy.C, legacy.H
SCHEMA = 'fleetory.original-four-use-plan.v1'
PURPOSE = 'existing-original-four-private-consumer.v1'
KINDS = frozenset(('application-postgres','signer-postgres','audit-immudb','audit-export'))
MAX_PLAN = 8192
_LIVE = weakref.WeakKeyDictionary()


@dataclass(frozen=True)
class ExpectedOriginalFour:
    # Supplied by trusted operator code from independently pinned retained records,
    # never constructed from a peer request as evidence of user permission.
    root: str
    artifacts: tuple
    revision: str
    image_id: str
    probe_sha256: str
    configuration_sha256: str
    execution_inventory_sha256: str
    policy_sha256: str


def _expected(value):
    packet.require(type(value) is ExpectedOriginalFour)
    packet.require(type(value.root) is str and Path(value.root).is_absolute())
    packet.require(type(value.artifacts) is tuple and len(value.artifacts)==4)
    refs = {}
    for entry in value.artifacts:
        packet.require(type(entry) is tuple and len(entry)==4)
        kind,path,size,digest = entry
        packet.require(type(kind) is str and kind in KINDS and kind not in refs)
        legacy.inputs.files.relative_parts(path)
        packet.require(type(size) is int and 0<size<=legacy.private.MAX_INPUT)
        refs[kind] = dict(path=path,bytes=size,sha256=packet.hex_value(digest))
    packet.require(refs.keys()==KINDS and len({v['sha256'] for v in refs.values()})==4)
    packet.require(sum(v['bytes'] for v in refs.values())<=legacy.private.MAX_INPUT)
    packet.require(type(value.revision) is str and re.fullmatch('[a-f0-9]{40}',value.revision))
    packet.require(type(value.image_id) is str and re.fullmatch('sha256:[a-f0-9]{64}',value.image_id))
    for digest in (value.probe_sha256,value.configuration_sha256,value.execution_inventory_sha256,value.policy_sha256):packet.hex_value(digest)
    return refs


def _admit(raw, pin, service_raw, service_pin, metadata, expected, parent):
    refs = _expected(expected)
    packet.require(type(parent) is legacy.identity.HeldLocalPeer and parent.role=='parent')
    observed = parent.snapshot()
    packet.require(observed['state']=='live')
    packet.require(H(raw)==packet.hex_value(pin) and H(service_raw)==packet.hex_value(service_pin))
    plan = packet.strict_json(raw,MAX_PLAN)
    packet.keys(plan,'schema purpose nonce root artifacts servicePlanSha256 executionInventorySha256 consumerIdentitySha256')
    packet.require(plan['schema']==SCHEMA and plan['purpose']==PURPOSE)
    packet.identity(plan['nonce'])
    packet.require(plan['root']==expected.root and plan['artifacts']==refs)
    packet.require(plan['servicePlanSha256']==service_pin and plan['executionInventorySha256']==expected.execution_inventory_sha256)
    packet.require(plan['consumerIdentitySha256']==H(C(observed['identity'])))
    service = legacy._admit(service_raw,service_pin,metadata,Path(expected.root))
    packet.require(service['nonce']==plan['nonce'] and service['revision']==expected.revision)
    for key, wanted in (('imageId',expected.image_id),('probeSha256',expected.probe_sha256),('configurationSha256',expected.configuration_sha256)):
        packet.require(service[key]==wanted)
    selected,_ = legacy.inputs.selection.decode_report(metadata['selection'],service['pins']['selection'])
    export = legacy.inputs.expectations.source_plan({n:metadata[n] for n in ('manifest','checkpoint')},
                                                   {n:service['pins'][n] for n in ('manifest','checkpoint')})
    actual = {v.kind:dict(path=v.path,bytes=v.bytes,sha256=v.sha256) for v in (*selected.artifacts,export.artifact)}
    packet.require(actual==refs)
    return plan


class LiveOriginalFour:
    __slots__ = ('__weakref__',)

    def _registered(self):
        packet.require(type(self) is LiveOriginalFour and self in _LIVE)
        state = _LIVE[self]
        packet.require(state['pid']==os.getpid() and state['thread']==threading.get_ident())
        return state

    def _check(self, state):
        packet.require(0<=time.monotonic_ns()-state['mono']<legacy.LIFETIME_NS)
        packet.require(state['wall']<=time.time_ns()<state['wall']+legacy.LIFETIME_NS)
        packet.require(state['parent'].snapshot()['state']=='live')
        state['attempt'].check();state['policy'].check()
        packet.require(state['inventory_check']() is True)
        return state['inner'].report()

    def capture(self):
        state = self._registered()
        packet.require(state['stage']=='ready')
        state['stage']='capture-consumed'  # Burn before liveness/source checks as well as raw I/O.
        self._check(state)
        state['inner'].capture()
        self._check(state)
        state['stage']='captured'

    def dispatch(self):
        state = self._registered()
        packet.require(state['stage']=='captured')
        state['stage']='dispatch-consumed'
        self._check(state)
        result = state['inner'].dispatch()
        self._check(state)
        state['stage']='returned-unverified'
        return result

    def report(self):
        state = self._registered();inner=self._check(state)
        return dict(schema='fleetory.original-four-use.v1',purpose=PURPOSE,nonce=state['nonce'],stage=state['stage'],
                    exactFourArtifactsPinned=True,actualParentIdentityBound=True,distinctAttemptFlushed=True,
                    heldProcessIdentity=inner['heldProcessIdentity'],
                    existingDataConsentAuthenticated=False,executionInventoryOriginAuthenticated=False,
                    nativeResultAuthenticated=False,nativeLaunchAuthorized=False,executionAuthorized=False,
                    fullSystemRecoveryVerified=False,phase7Complete=False)


@contextmanager
def use(trusted_operator_root, trusted_repository, expected, trusted_parent, trusted_inventory_check,
        plan_bytes, plan_pin, service_bytes, service_pin, metadata, trusted_consumer):
    # Session authorization for the existing four original inputs remains external
    # to this library. Neither this plan nor an observation report grants it.
    mono,wall = time.monotonic_ns(),time.time_ns()
    raw = legacy._freeze(plan_bytes,MAX_PLAN)
    service_raw = legacy._freeze(service_bytes,legacy.MAX_PLAN)
    packet.keys(metadata,'selection manifest checkpoint ci local')
    frozen = {n:legacy._freeze(v,524288 if n=='ci' else 131072 if n in ('manifest','checkpoint') else 16384) for n,v in metadata.items()}
    plan = _admit(raw,plan_pin,service_raw,service_pin,frozen,expected,trusted_parent)
    packet.require(callable(trusted_inventory_check) and trusted_inventory_check() is True and callable(trusted_consumer))
    operator,repository = Path(trusted_operator_root).absolute(),Path(trusted_repository).absolute()
    record = dict(schema='fleetory.original-four-attempt.v1',purpose=PURPOSE,nonce=plan['nonce'],planSha256=H(raw),
                  servicePlanSha256=H(service_raw),executionInventorySha256=expected.execution_inventory_sha256,
                  status='ATTEMPT_CONSUMED',originalPermissionGranted=False,nativeLaunchAuthorized=False,phase7Complete=False)
    with ExitStack() as held:
        attempt = held.enter_context(legacy.attempts._claim_record(operator,'original-four-use-'+plan['nonce']+'.json',record))
        policy = held.enter_context(legacy.identity.process.PinnedFile(Path(__file__).resolve(),expected.policy_sha256))
        inner = held.enter_context(legacy.use(operator,Path(expected.root),repository,service_raw,service_pin,frozen,trusted_consumer))
        value = LiveOriginalFour()
        _LIVE[value] = dict(pid=os.getpid(),thread=threading.get_ident(),mono=mono,wall=wall,stage='ready',nonce=plan['nonce'],
                            parent=trusted_parent,inventory_check=trusted_inventory_check,attempt=attempt,policy=policy,inner=inner)
        try:
            value._check(_LIVE[value]);yield value
        finally:_LIVE.pop(value,None)


if __name__=='__main__':raise SystemExit('Original four-input use is a trusted library; no permission or native CLI.')
