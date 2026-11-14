"""Independent own-created public test worker cleanup; no adopted resource or secret API."""
from contextlib import ExitStack
from pathlib import Path
import json
import os
import re
import sys
import threading
import time
from types import SimpleNamespace

import audit_cleanup_attempt as attempts
import audit_supervisor_identity as identity
import audit_native_probe_create as native
import audit_backend_binding as container

process,packet=identity.process,identity.packet
C,H=identity.protocol.C,packet.digest
PURPOSE='fixed-public-independent-cleanup.v1'
LEASE_NS=3_000_000_000
ACTION_NS=25_000_000_000
COMMAND=['-I','-B','-c','import time; time.sleep(30)']
OBSERVATION='fleetory.fixed-public-guard-observation.v1'
FIELDS={k:v for k,v in native.FIELDS.items() if k not in ('environment','ulimits')}
FORMAT='{"schema":"'+OBSERVATION+'",'+','.join(json.dumps(k)+':{{json '+v+'}}' for k,v in FIELDS.items())+'}'
# Fixed public source inventory. Runtime callers cannot add paths or launch arguments.
SOURCES=(
    'eng/pilot/Observe-CleanupSupervisor.py',
    'eng/pilot/PublicCleanupController.py',
    'eng/pilot/Run-PublicCleanupGuard.py',
    'eng/pilot/RetainedContextController.py',
    'eng/pilot/api-client.py',
    'eng/pilot/audit_archive.py',
    'eng/pilot/audit_archive_input.py',
    'eng/pilot/audit_backend_binding.py',
    'eng/pilot/audit_cleanup_attempt.py',
    'eng/pilot/audit_cleanup_protocol.py',
    'eng/pilot/audit_control_identity.py',
    'eng/pilot/audit_expectation_diagnostic.py',
    'eng/pilot/audit_expectation_source.py',
    'eng/pilot/audit_history_inputs.py',
    'eng/pilot/audit_image_binding.py',
    'eng/pilot/audit_launch_bundle.py',
    'eng/pilot/audit_linked_binding.py',
    'eng/pilot/audit_native_payload.py',
    'eng/pilot/audit_native_preparation.py',
    'eng/pilot/audit_native_probe_create.py',
    'eng/pilot/audit_native_probe_runtime.py',
    'eng/pilot/audit_native_publication.py',
    'eng/pilot/audit_native_resources.py',
    'eng/pilot/audit_observation.py',
    'eng/pilot/audit_payload_binding.py',
    'eng/pilot/audit_payload_launch.py',
    'eng/pilot/audit_payload_owner.py',
    'eng/pilot/audit_probe_bundle.py',
    'eng/pilot/audit_probe_image.py',
    'eng/pilot/audit_probe_runtime.py',
    'eng/pilot/audit_process_fence.py',
    'eng/pilot/audit_process_posix.py',
    'eng/pilot/audit_process_windows.py',
    'eng/pilot/audit_public_cleanup_guard.py',
    'eng/pilot/audit_publication_continuation.py',
    'eng/pilot/audit_publication_namespace.py',
    'eng/pilot/audit_retained_runtime.py',
    'eng/pilot/audit_retained_context_transport.py',
    'eng/pilot/audit_supervisor_identity.py',
    'eng/pilot/audit_use_admission.py',
    'eng/pilot/audit_use_transaction.py',
    'eng/pilot/fresh_server_pair.py',
    'eng/pilot/historical_audit_observation.py',
    'eng/pilot/historical_audit_restore.py',
    'eng/pilot/identity_backup.py',
    'eng/pilot/pg_inventory_v2.py',
    'eng/pilot/recovery_build.py',
    'eng/pilot/recovery_composition.py',
    'eng/pilot/recovery_configuration.py',
    'eng/pilot/recovery_files.py',
    'eng/pilot/recovery_isolation.py',
    'eng/pilot/recovery_login.py',
    'eng/pilot/recovery_postgres_tls.py',
    'eng/pilot/recovery_target.py',
    'eng/pilot/recovery_tls.py',
    'eng/pilot/release_inputs.py',
    'eng/pilot/retained_input_selection.py',
    'eng/pilot/retained_pair_review.py',
    'eng/pilot/server_data_inputs.py',
    'eng/pilot/v2_server_composition.py',
    'eng/pilot/probe-runtime-profile.json',
)


def _process_identity(value):
    return dict(pid=value['pid'],birthKind=value['birthKind'],birthToken=value['birthToken'],executableSha256=value['imageSha256'])


def _identifier(value):
    packet.require(type(value) is str and re.fullmatch('[a-f0-9]{64}',value))
    return value


def _name(nonce):return 'fleetory-public-guard-'+packet.identity(nonce).replace('-','')


def _ledger(kind,nonce):
    packet.require(kind in ('start','ready','cleanup'))
    return 'public-sleep-guard-'+kind+'-'+packet.identity(nonce)+'.json'


def _arguments(name,image,labels):
    args=['run','-d','--pull=never','--name',name,'--rm','--network=none','--read-only',
        '--user=65534:65534','--cap-drop=ALL','--security-opt=no-new-privileges:true',
        '--memory=64m','--cpus=0.25','--pids-limit=32','--restart=no','--entrypoint=python']
    for key,value in sorted(labels.items()):args.extend(['--label',key+'='+value])
    return args+[image,*COMMAND]


def _observation(raw,receipt):
    value=packet.strict_json(raw,container.MAX_OBSERVATION)
    packet.keys(value,'schema '+' '.join(FIELDS))
    packet.require(value['schema']==OBSERVATION and value['id']==receipt['containerId'] and
        value['name']=='/'+receipt['name'] and value['imageId']==value['configImage']==receipt['imageId'] and value['labels']==receipt['labels'])
    created=container.timestamp_ns(value['created'])
    packet.require(receipt['createStartedNs']<=created<=receipt['createFinishedNs'])
    container._container_sandbox(value)
    packet.require(value['user']=='65534:65534' and value['entrypoint']==['python'] and value['command']==COMMAND)
    packet.require(all(type(value[n]) is int and value[n]==limit for n,limit in
        (('memory',67108864),('nanoCpus',250000000),('pidsLimit',32))))
    packet.require(value['tmpfs'] is None or value['tmpfs']=={})
    return value


class _Controller:
    """Own unreaped child/job, with the guardian retaining the sole stdin writer."""
    def __init__(self,repository,executable,nonce,parent):
        self.child=self.fence=self.pumps=None
        command=SimpleNamespace(executable=executable,arguments=('-I','-B',str(repository/'eng/pilot/PublicCleanupController.py')),
            directory=repository,env=process.environment(executable))
        try:
            self.child=process._spawn(command);self.fence=process._create_fence(self.child)
            self.observed=_process_identity(self.fence.identity(self.child,executable))
            self.pumps=process._Pumps(self.child,b'')
            for stream,target,bound in ((self.child.stdout,self.pumps.stdout,4096),(self.child.stderr,self.pumps.stderr,4096)):
                thread=threading.Thread(target=self.pumps._read,args=(stream,target,bound,'controller-output-bound'),daemon=True)
                self.pumps.threads.append(thread);thread.start()
            self.pumps._send(C(dict(schema='fleetory.fixed-idle-controller.v1',nonce=nonce,
                parent=parent,controller=self.observed,pythonSha256=executable.digest))+b'\n')
            deadline=time.monotonic_ns()+5_000_000_000
            while b'\n' not in self.pumps.stdout:
                packet.require(not self.exited() and not self.pumps.errors and time.monotonic_ns()<deadline)
                time.sleep(0.01)
            ready=packet.strict_json(bytes(self.pumps.stdout),4096)
            packet.require(ready==dict(schema='fleetory.fixed-idle-ready.v1',nonce=nonce,parent=parent,controller=self.observed))
            packet.require(not self.pumps.stderr and self.state(executable)=='live')
        except BaseException:self.close();raise

    def exited(self):return self.child.poll() is not None if os.name=='nt' else self.fence.exited()

    def state(self,executable):
        packet.require(not self.pumps.errors and not self.pumps.stderr)
        if self.exited():return 'exited'
        try:observed=_process_identity(self.fence.identity(self.child,executable))
        except (OSError,ValueError):
            if self.exited():return 'exited'
            raise
        packet.require(observed==self.observed)
        return 'live'

    def close(self):
        _,failure=process._finish_owned(self.child,self.fence,self.pumps)
        self.child=None
        packet.require(failure is None)


class PublicCleanupGuard:
    """Trusted local fixed profile. A caller-supplied ID/receipt is never accepted."""
    def __init__(self,repository,operator_root,nonce,python_path,python_sha256,docker_path,docker_sha256,source_pins):
        self._held=ExitStack();self._controller=None;self._receipt=None;self._closed=False
        self._caller=os.getpid();self._nonce=packet.identity(nonce);self._root=Path(operator_root)
        self._repository=Path(repository).resolve(strict=True)
        try:
            packet.require(type(source_pins) is dict and set(source_pins)==set(SOURCES))
            frozen=dict(source_pins)
            self._held.enter_context(process.control.DirectoryLease(self._repository))
            self._sources=tuple(self._held.enter_context(process.PinnedFile(self._repository/name,frozen[name])) for name in SOURCES)
            self._python=self._held.enter_context(process.PinnedFile(python_path,python_sha256,True))
            packet.require(self._python.path==Path(sys.executable).resolve(strict=True))
            docker=self._held.enter_context(process.PinnedFile(docker_path,docker_sha256,True))
            self._parent=identity.current_identity(self._python)
            self._source_digest=H(C(frozen))
            start=dict(schema='fleetory.fixed-public-guard-start.v1',nonce=nonce,purpose=PURPOSE,
                status='START_CONSUMED',supervisor=self._parent,sourcePinsSha256=self._source_digest)
            self._start=self._held.enter_context(attempts._claim_record(self._root,_ledger('start',nonce),start))
            self._docker=native._Docker(docker)
            self._controller=_Controller(self._repository,self._python,nonce,self._parent)
            self._check()
        except BaseException:self.close();raise

    def _check(self):
        packet.require(not self._closed and os.getpid()==self._caller)
        self._start.check()
        for source in self._sources:source.check()
        packet.require(identity.current_identity(self._python)==self._parent)

    def create(self):
        self._check();packet.require(self._receipt is None and self._controller.state(self._python)=='live')
        image=self._docker._call(['image','inspect','--format','{{.Id}}',container.IMAGE]).decode('ascii').strip()
        container.image_id(image)
        labels={'fleetory.public.guard.nonce':self._nonce,'fleetory.public.guard.profile':PURPOSE,
            'fleetory.public.guard.source':self._source_digest,'fleetory.public.guard.controller':H(C(self._controller.observed)),
            'fleetory.public.guard.supervisor':H(C(self._parent))}
        # A consumed start permits only this one call. Lost/partial create output is never adopted by name.
        self._receipt=False
        opened=time.time_ns()
        reply=self._docker._call(_arguments(_name(self._nonce),image,labels))
        finished=time.time_ns()
        identifier=_identifier(reply.decode('ascii').strip())
        packet.require(reply==identifier.encode('ascii')+b'\n' and opened<=finished)
        receipt=dict(schema='fleetory.fixed-public-guard-receipt.v1',nonce=self._nonce,containerId=identifier,
            name=_name(self._nonce),imageId=image,labels=labels,createReplySha256=H(reply),createStartedNs=opened,
            createFinishedNs=finished,controller=self._controller.observed,supervisor=self._parent,sourcePinsSha256=self._source_digest)
        self._check()
        _observation(self._docker._call(['container','inspect','--format',FORMAT,identifier]),receipt)
        self._wall=time.time_ns();self._mono=time.monotonic_ns()
        packet.require(self._wall>=finished and self._wall-opened<10_000_000_000)
        ready=dict(receipt,status='OWN_CREATE_RECEIPT_RECORDED',leaseExpiresNs=self._wall+LEASE_NS)
        self._ready=self._held.enter_context(attempts._claim_record(self._root,_ledger('ready',self._nonce),ready))
        self._receipt=C(receipt)
        return self.receipt()

    def receipt(self):
        self._check();packet.require(type(self._receipt) is bytes)
        self._ready.check()
        return packet.strict_json(self._receipt,8192)

    def _elapsed(self):
        mono=time.monotonic_ns()-self._mono;wall=time.time_ns()-self._wall
        packet.require(0<=mono<LEASE_NS+ACTION_NS and 0<=wall<LEASE_NS+ACTION_NS)
        return max(mono,wall)

    def cleanup(self):
        receipt=self.receipt()
        while True:
            elapsed=self._elapsed();state=self._controller.state(self._python)
            if state=='exited' or elapsed>=LEASE_NS:break
            time.sleep(0.01)
        reason='controller-exited' if state=='exited' else 'lease-expired'
        record=dict(schema='fleetory.fixed-public-guard-cleanup.v1',nonce=self._nonce,status='CLEANUP_ATTEMPT_CONSUMED',
            reason=reason,receiptSha256=H(self._receipt),containerId=receipt['containerId'],sourcePinsSha256=self._source_digest)
        with attempts._claim_record(self._root,_ledger('cleanup',self._nonce),record) as consumed:
            self._check();self._ready.check();self._elapsed();consumed.check()
            raw=self._docker._call(['container','inspect','--format',FORMAT,receipt['containerId']])
            _observation(raw,receipt)
            self._check();self._ready.check();self._elapsed();consumed.check()
            reply=self._docker._call(['container','rm','--force',receipt['containerId']])
            packet.require(reply==receipt['containerId'].encode('ascii')+b'\n')
            self._elapsed();consumed.check()
            absent=self._docker._call(['container','ls','-a','--no-trunc','--filter','id='+receipt['containerId'],'--format','{{.ID}}'])
            packet.require(absent==b'')
            self._check();self._elapsed();consumed.check()
        return dict(schema='fleetory.fixed-public-independent-cleanup.v1',nonce=self._nonce,reason=reason,
            receiptSha256=H(self._receipt),containerId=receipt['containerId'],sourcePinsSha256=self._source_digest,
            actualCleanupExecuted=True,ownCreatedContainerAbsent=True,actualControllerIdentityVerified=True,
            controllerExitedBeforeCleanup=state=='exited',independentExpiryEnforcementVerified=reason=='lease-expired',
            controllerDeathCleanupVerified=reason=='controller-exited',supervisorAliveDuringCleanup=True,
            localConsumedAttemptFlushed=True,restartReplayRefusedWhileRecordRetained=True,
            fixedWorkerPassiveAutoExpirySeconds=30,supervisorDeathCleanupVerified=False,
            dockerDaemonFailureCleanupVerified=False,preReceiptCrashCleanupVerified=False,
            dependenciesAuthenticated=False,externalRollbackResistanceVerified=False,windowsDirectoryAclAuthenticated=False,
            retainedPublicationIntegrationVerified=False,originalInputsRead=False,originalPrivatePkiUsed=False,
            sourceVpsAccessed=False,fullSystemRecoveryVerified=False,phase7Complete=False)

    def close(self):
        if self._closed:return
        self._closed=True
        try:
            if self._controller is not None:self._controller.close();self._controller=None
        finally:self._held.close()

    def __enter__(self):return self
    def __exit__(self,*_):self.close()


if __name__=='__main__':raise SystemExit('Fixed public guard library; no adopted ID, endpoint, command or secret CLI.')
