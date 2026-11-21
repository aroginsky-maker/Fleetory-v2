"""Fixed read-only cleanup supervisor probe. It cannot execute cleanup or accept host paths/commands."""
from contextlib import ExitStack
from pathlib import Path
import sys

sys.path.insert(0,str(Path(__file__).resolve().parent))
import audit_supervisor_identity as identity

protocol,process=identity.protocol,identity.process
packet,C=identity.packet,identity.protocol.C
MAX_INPUT=49152
SOURCES=tuple(dict.fromkeys((*protocol.runtime.publication.SOURCES,*protocol.runtime.EXTRA_SOURCES,
    'eng/pilot/audit_cleanup_protocol.py','eng/pilot/audit_supervisor_identity.py','eng/pilot/Observe-CleanupSupervisor.py')))


def observe(data):
    packet.require(type(data) is bytes and 0<len(data)<=MAX_INPUT)
    value=packet.strict_json(data,MAX_INPUT)
    packet.keys(value,'schema sourcePins ticketBase64 ticketSha256 createReceiptBase64 resourceBase64')
    packet.require(value['schema']=='fleetory.readonly-supervisor-handoff.v1' and type(value['sourcePins']) is dict and set(value['sourcePins'])==set(SOURCES))
    ticket=packet.decode(value['ticketBase64'],protocol.MAX_FRAME)
    declared=protocol._ticket(ticket,value['ticketSha256'])
    receipt=packet.decode(value['createReceiptBase64'],protocol.MAX_FRAME);resource=packet.decode(value['resourceBase64'],protocol.MAX_FRAME)
    root=Path(__file__).resolve().parents[2]
    with ExitStack() as held:
        held.enter_context(process.control.DirectoryLease(root))
        pins=[held.enter_context(protocol.runtime.publication.prep._RootInputPin(root/name,value['sourcePins'][name])) for name in SOURCES]
        executable=held.enter_context(process.PinnedFile(Path(sys.executable),declared['supervisor']['executableSha256'],True))
        parent=held.enter_context(identity.HeldLocalPeer('parent',executable,declared['controller']))
        own=held.enter_context(identity.HeldLocalPeer('self',executable,declared['supervisor']))
        first,parent_state=own.snapshot(),parent.snapshot()
        packet.require(first['state']==parent_state['state']=='live')
        model=protocol.CleanupProtocolModel(ticket,value['ticketSha256'])
        def frame(snapshot):return C(dict(schema=protocol.PROCESS_SCHEMA,identity=snapshot['identity'],state=snapshot['state']))
        result=model.evaluate(frame(parent_state),frame(first),receipt,resource)
        packet.require(result['state']=='armed' and result['decision']=='await-model-trigger' and result['candidate'] is None)
        packet.require(parent.snapshot()==parent_state and own.snapshot()==first)
        for pin in pins:pin.check()
        return dict(schema='fleetory.actual-readonly-supervisor-handoff.v1',sourceFilesPinned=len(pins),
            sourcePinsSha256=packet.digest(C(value['sourcePins'])),controller=parent_state,supervisor=first,
            ticketSha256=packet.digest(ticket),createReceiptSha256=packet.digest(receipt),resourceSha256=packet.digest(resource),
            model=result,actualControllerIdentityVerified=True,actualSupervisorIdentityVerified=True,
            receiptBytesTransportBound=True,createReceiptOriginAuthenticated=False,durableAttemptStoreVerified=False,
            independentExpiryEnforcementVerified=False,controllerDeathCleanupVerified=False,supervisorIndependenceVerified=False,
            cleanupAuthorized=False,actualCleanupExecuted=False,operationalLeaseAuthorized=False,fullSystemRecoveryVerified=False,phase7Complete=False)


if __name__=='__main__':
    try:
        packet.require(len(sys.argv)==1)
        print(C(observe(sys.stdin.buffer.read(MAX_INPUT+1))).decode('ascii'))
    except Exception:
        print('Read-only supervisor handoff refused.',file=sys.stderr);raise SystemExit(1)
