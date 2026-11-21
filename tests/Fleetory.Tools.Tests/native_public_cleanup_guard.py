"""Actual Docker expiry/death/foreign-ID/restart cases for fixed public workers only."""
from contextlib import ExitStack
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import time
from types import SimpleNamespace
import uuid
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'eng/pilot'))
import audit_public_cleanup_guard as guard

ROOT=Path(__file__).resolve().parents[2]


def absent(docker,identifier):
    return docker._call(['container','ls','-a','--no-trunc','--filter','id='+guard._identifier(identifier),'--format','{{.ID}}'])==b''


def await_absent(docker,identifier,deadline):
    while not absent(docker,identifier):
        guard.packet.require(time.monotonic()<deadline);time.sleep(0.1)


def guardian_death(docker,executable):
    nonce=str(uuid.uuid4())
    command=SimpleNamespace(executable=executable,arguments=('-I','-B',str(ROOT/'eng/pilot/Run-PublicCleanupGuard.py'),nonce),
        directory=ROOT,env=guard.process.environment(executable,(docker.pinned,)))
    child=fence=pumps=peer=None
    try:
        child=guard.process._spawn(command);fence=guard.process._create_fence(child)
        supervisor=guard._process_identity(fence.identity(child,executable))
        pumps=guard.process._Pumps(child,b'');pumps.start()
        deadline=time.monotonic()+15
        while b'\n' not in pumps.stdout:
            guard.packet.require(not pumps.errors and time.monotonic()<deadline);time.sleep(0.01)
        raw=bytes(pumps.stdout).split(b'\n',1)[0]
        receipt=guard.packet.strict_json(raw,8192)
        guard.packet.require(receipt['nonce']==nonce and receipt['supervisor']==supervisor)
        guard._observation(docker._call(['container','inspect','--format',guard.FORMAT,receipt['containerId']]),receipt)
        expected=receipt['controller']
        peer=(guard.identity._WindowsPeer if os.name=='nt' else guard.identity._LinuxPeer)(expected['pid'],executable)
        guard.packet.require(peer.live_identity()==expected)
        # Only the fixture's own unreaped process/job is killed, never a wire-selected PID.
        fence.terminate()
        deadline=time.monotonic()+5
        while not peer.exited():
            guard.packet.require(time.monotonic()<deadline);time.sleep(0.01)
        ended,failure=guard.process._finish_owned(child,fence,pumps);child=fence=None
        guard.packet.require(failure is None and ended['noRunningMembersVerified'] and not pumps.errors)
        guard.packet.require(len(bytes(pumps.stdout).splitlines())==1 and not pumps.stderr)
        await_absent(docker,receipt['containerId'],time.monotonic()+40)
        root=ROOT/'artifacts'/('public-cleanup-'+nonce)
        guard.packet.require((root/guard._ledger('start',nonce)).is_file() and (root/guard._ledger('ready',nonce)).is_file()
            and not (root/guard._ledger('cleanup',nonce)).exists())
        return dict(case='guardian-killed',containerId=receipt['containerId'],actualGuardianKilled=True,
            actualControllerExited=True,fixedWorkerPassiveAutoExpiryAfterGuardianDeathVerified=True,
            cleanupExecutorRan=False,consumedStartAndReceiptRetained=True)
    finally:
        if peer is not None:peer.close()
        if child is not None:guard.process._finish_owned(child,fence,pumps)


def run():
    outcomes=[]
    python=Path(sys.executable).resolve(strict=True);docker_path=Path(shutil.which('docker') or '').resolve(strict=True)
    pins={name:guard.H((ROOT/name).read_bytes()) for name in guard.SOURCES}
    with tempfile.TemporaryDirectory(prefix='fleetory-public-guard-') as temp,ExitStack() as held:
        executable=held.enter_context(guard.process.PinnedFile(python,guard.H(python.read_bytes()),True))
        docker_pin=held.enter_context(guard.process.PinnedFile(docker_path,guard.H(docker_path.read_bytes()),True))
        docker=guard.native._Docker(docker_pin)
        def owner():
            nonce=str(uuid.uuid4());root=Path(temp)/nonce;root.mkdir(mode=0o700)
            value=guard.PublicCleanupGuard(ROOT,root,nonce,python,executable.digest,docker_path,docker_pin.digest,pins)
            return value,root,nonce
        for case in ('lease-expired','controller-exited'):
            value,root,nonce=owner()
            with value:
                receipt=value.create()
                if case=='controller-exited':value._controller.fence.terminate()
                result=value.cleanup()
                guard.packet.require(result['reason']==case and result['actualCleanupExecuted'] and absent(docker,receipt['containerId']))
                try:value.cleanup()
                except OSError:pass
                else:raise ValueError('Cleanup replay unexpectedly accepted.')
            before={p.name:guard.H(p.read_bytes()) for p in root.iterdir()}
            try:guard.PublicCleanupGuard(ROOT,root,nonce,python,executable.digest,docker_path,docker_pin.digest,pins)
            except OSError:pass
            else:raise ValueError('Start replay unexpectedly accepted.')
            guard.packet.require(before=={p.name:guard.H(p.read_bytes()) for p in root.iterdir()})
            outcomes.append(dict(case=case,result=result,restartAndCleanupReplayRefused=True))
        victim,_,_=owner();sentinel,_,_=owner()
        with victim,sentinel:
            victim_receipt=victim.create();foreign=sentinel.create()
            foreign_raw=docker._call(['container','inspect','--format',guard.FORMAT,foreign['containerId']])
            call=victim._docker._call;removals=[]
            def substituted(args):
                if args[:2]==['container','inspect']:return foreign_raw
                if args[:2]==['container','rm']:removals.append(args)
                return call(args)
            with patch.object(victim._docker,'_call',side_effect=substituted):
                try:victim.cleanup()
                except ValueError:pass
                else:raise ValueError('Foreign observation accepted.')
            guard.packet.require(not removals)
            try:victim.cleanup()
            except OSError:pass
            else:raise ValueError('Failed cleanup retried.')
            after=docker._call(['container','inspect','--format',guard.FORMAT,foreign['containerId']])
            guard.packet.require(after==foreign_raw and not absent(docker,victim_receipt['containerId']))
            sentinel.cleanup()
            outcomes.append(dict(case='foreign-observation',foreignContainerUntouched=True,cleanupCalls=0,failedAttemptConsumed=True))
        outcomes.append(guardian_death(docker,executable))
        await_absent(docker,victim_receipt['containerId'],time.monotonic()+40)
        guard.packet.require(all((ROOT/name).is_file() and guard.H((ROOT/name).read_bytes())==digest for name,digest in pins.items()))
    return dict(schema='fleetory.actual-fixed-public-cleanup-proof.v1',verified=True,cases=outcomes,sourcePins=pins,
        sourcePinsSha256=guard.H(guard.C(pins)),allOwnedTestContainersAbsent=True,originalInputsRead=False,
        originalPrivatePkiUsed=False,sourceVpsAccessed=False,retainedPublicationIntegrationVerified=False,
        dockerDaemonFailureCleanupVerified=False,fullSystemRecoveryVerified=False,phase7Complete=False)


if __name__=='__main__':print('ACTUAL PUBLIC GUARD PASS: '+json.dumps(run(),sort_keys=True))
