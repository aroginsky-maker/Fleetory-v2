"""Actual fixed supervisor verifies parent/self OS objects and generated asserted-receipt bytes."""
from contextlib import ExitStack
import base64
import importlib.util
import json
from pathlib import Path
import sys
import threading
import time
from types import SimpleNamespace

import cleanup_protocol_tests as generated
import audit_supervisor_identity as identity
from native_audit_preparation import active_sdk_input

process,packet=identity.process,identity.packet
C,H=identity.protocol.C,identity.protocol.packet.digest
ROOT=Path(__file__).resolve().parents[2]
ENTRY=ROOT/'eng/pilot/Observe-CleanupSupervisor.py'
spec=importlib.util.spec_from_file_location('supervisor_fixed_worker',ENTRY)
worker=importlib.util.module_from_spec(spec);spec.loader.exec_module(worker)
CASES=('positive','wrong-controller-pid','wrong-controller-birth','wrong-supervisor-birth','wrong-source-pin','changed-receipt')


def encode(data):return base64.b64encode(data).decode('ascii')


def run():
    outcomes=[]
    with active_sdk_input(), ExitStack() as held:
        root=held.enter_context(process.control.DirectoryLease(ROOT))
        values=identity.protocol.runtime.publication.prep._measure_sources(root.path,worker.SOURCES)
        sources=[held.enter_context(identity.protocol.runtime.publication.prep._RootInputPin(root.path/name,values[name])) for name in worker.SOURCES]
        path=Path(sys.executable).resolve();executable=held.enter_context(process.PinnedFile(path,H(path.read_bytes()),True))
        controller=identity.current_identity(executable)
        with identity.HeldLocalPeer('self',executable,controller) as own:
            for case in CASES:
                own.snapshot()
                command=SimpleNamespace(executable=executable,arguments=('-I','-B',str(ENTRY)),directory=ROOT,env=process.environment(executable))
                child=fence=pumps=None;observed=None;ended=None;failure=None
                try:
                    child=process._spawn(command);fence=process._create_fence(child);observed=fence.identity(child,executable)
                    supervisor=dict(pid=observed['pid'],birthKind=observed['birthKind'],birthToken=observed['birthToken'],executableSha256=observed['imageSha256'])
                    fixture=generated.CleanupProtocolContracts();fixture.setUp()
                    ticket=fixture.value;ticket.update(controller=dict(controller),supervisor=supervisor)
                    if case=='wrong-controller-pid':ticket['controller']['pid']+=100000
                    elif case=='wrong-controller-birth':ticket['controller']['birthToken']='1'
                    elif case=='wrong-supervisor-birth':ticket['supervisor']['birthToken']='1'
                    pins=dict(values)
                    if case=='wrong-source-pin':pins[worker.SOURCES[-1]]='f'*64
                    receipt=C(fixture.receipt) if case!='changed-receipt' else C(dict(fixture.receipt,id='f'*64))
                    raw=C(dict(schema='fleetory.readonly-supervisor-handoff.v1',sourcePins=pins,
                        ticketBase64=encode(C(ticket)),ticketSha256=H(C(ticket)),createReceiptBase64=encode(receipt),resourceBase64=encode(C(fixture.resource))))
                    packet.require(len(raw)<=worker.MAX_INPUT)
                    pumps=process._Pumps(child,raw)
                    for target,args in ((pumps._read,(child.stdout,pumps.stdout,8192,'stdout-bound')),
                            (pumps._read,(child.stderr,pumps.stderr,4096,'stderr-bound')),(pumps._write,())):
                        thread=threading.Thread(target=target,args=args,daemon=True);pumps.threads.append(thread);thread.start()
                    process._wait_for_owner(child,fence,pumps,time.monotonic_ns(),10)
                finally:
                    ended,failure=process._finish_owned(child,fence,pumps)
                packet.require(failure is None and ended['noRunningMembersVerified'] is True and pumps is not None and
                    not pumps.errors and pumps.input_written==len(raw))
                stdout,stderr=bytes(pumps.stdout),bytes(pumps.stderr)
                if case=='positive':
                    packet.require(child.returncode==0 and stderr==b'')
                    result=packet.strict_json(stdout,8192)
                    packet.require(result['controller']['identity']==controller and result['supervisor']['identity']==supervisor and
                        result['actualControllerIdentityVerified'] is result['actualSupervisorIdentityVerified'] is result['receiptBytesTransportBound'] is True)
                    packet.require(result['ticketSha256']==H(C(ticket)) and result['createReceiptSha256']==H(receipt) and
                        result['sourcePinsSha256']==H(C(values)) and result['sourceFilesPinned']==len(worker.SOURCES)==47)
                    for key in ('createReceiptOriginAuthenticated','durableAttemptStoreVerified','independentExpiryEnforcementVerified',
                            'controllerDeathCleanupVerified','supervisorIndependenceVerified','cleanupAuthorized','actualCleanupExecuted',
                            'operationalLeaseAuthorized','fullSystemRecoveryVerified','phase7Complete'):packet.require(result[key] is False)
                    packet.require(result['model']['state']=='armed' and result['model']['candidate'] is None)
                else:
                    packet.require(child.returncode!=0 and stdout==b'' and stderr.strip()==b'Read-only supervisor handoff refused.')
                    result=None
                for source in sources:source.check()
                packet.require(identity.protocol.runtime.publication.prep._measure_sources(ROOT,worker.SOURCES)==values)
                outcomes.append(dict(case=case,accepted=case=='positive',actualOwnedSupervisor=observed,ownedProcessMembersAbsent=True,
                    boundedInputFullyWritten=True,result=result))
    return dict(schema='fleetory.generated-actual-supervisor-observation.v1',verified=True,cases=outcomes,sourcePins=values,
        sourceFilesPinned=47,actualControllerAndSupervisorIdentityVerified=True,generatedReceiptTransportBound=True,
        allOwnedSupervisorProcessesAbsent=True,createReceiptOriginAuthenticated=False,durableAttemptStoreVerified=False,
        independentExpiryEnforcementVerified=False,controllerDeathCleanupVerified=False,supervisorIndependenceVerified=False,
        actualCleanupExecuted=False,dockerOperationsPerformed=0,originalInputsRead=False,originalPrivatePkiUsed=False,sourceVpsAccessed=False,
        fullSystemRecoveryVerified=False,phase7Complete=False)


if __name__=='__main__':print('ACTUAL SUPERVISOR OBSERVATION PASS: '+json.dumps(run(),sort_keys=True))
