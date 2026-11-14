"""Portable refusal, consumption and real owned-controller contracts; no Docker daemon."""
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
import uuid
from unittest.mock import Mock,patch

sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'eng/pilot'))
import audit_public_cleanup_guard as guard

ROOT=Path(__file__).resolve().parents[2]
REFUSALS=(OSError,ValueError,guard.attempts.files.archive.ArchiveError)


def fixture():
    receipt=dict(containerId='a'*64,name='fixture',imageId='sha256:'+'b'*64,labels={'fixed':'value'},
        createStartedNs=0,createFinishedNs=2_000_000_000)
    value=dict(schema=guard.OBSERVATION,id=receipt['containerId'],name='/fixture',imageId=receipt['imageId'],
        configImage=receipt['imageId'],labels=receipt['labels'],created='1970-01-01T00:00:01Z',user='65534:65534',
        entrypoint=['python'],command=guard.COMMAND,running=True,paused=False,restarting=False,dead=False,
        networkMode='none',networks={'none':{}},readonly=True,privileged=False,capDrop=['ALL'],capAdd=None,
        securityOpt=['no-new-privileges:true'],memory=67108864,nanoCpus=250000000,pidsLimit=32,mounts=[],ports={},
        portBindings={},binds=None,tmpfs=None,volumesFrom=None,devices=None,deviceRequests=None,pidMode='',
        ipcMode='private',utsMode='',usernsMode='',restart={'Name':'no','MaximumRetryCount':0},autoRemove=True,publishAllPorts=False)
    return receipt,value


class PublicGuardContracts(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)/'operator';self.root.mkdir(mode=0o700)
        self.nonce=str(uuid.uuid4())

    def claim(self,kind='cleanup'):
        return guard.attempts._claim_record(self.root,guard._ledger(kind,self.nonce),dict(status='CONSUMED',nonce=self.nonce))

    def test_exact_runtime_and_immutable_identity(self):
        receipt,value=fixture()
        self.assertEqual(guard._observation(guard.C(value),receipt),value)

    def test_every_observed_field_has_a_refusal_mutation(self):
        receipt,value=fixture()
        for key in value:
            with self.subTest(key=key):
                bad=copy.deepcopy(value);bad[key]={'18080/tcp':[]} if key in ('ports','portBindings') else (None if bad[key] is not None else ['foreign'])
                with self.assertRaises(REFUSALS):guard._observation(guard.C(bad),receipt)

    def test_unknown_observation_fields_and_duplicate_json_keys_refused(self):
        receipt,value=fixture()
        for raw in (guard.C(dict(value,extra=True)),guard.C(value)[:-1]+b',"id":"'+b'f'*64+b'"}'):
            with self.assertRaises(REFUSALS):guard._observation(raw,receipt)

    def test_limits_are_integers_and_exact(self):
        receipt,value=fixture()
        for key in ('memory','nanoCpus','pidsLimit'):
            for limit in (True,1.0,value[key]+1):
                bad=dict(value);bad[key]=limit
                with self.assertRaises(REFUSALS):guard._observation(guard.C(bad),receipt)

    def test_full_id_and_canonical_nonce_only(self):
        for bad in ('','a'*12,'A'*64,'--all',True):
            with self.assertRaises(REFUSALS):guard._identifier(bad)
        for bad in ('../x','--all',self.nonce.upper()):
            with self.assertRaises(REFUSALS):guard._ledger('start',bad)

    def test_unknown_record_prefix_cannot_write(self):
        with self.assertRaises(REFUSALS):
            with guard.attempts._claim_record(self.root,'foreign-'+self.nonce+'.json',{}):self.fail('Unexpected yield')
        self.assertEqual(list(self.root.iterdir()),[])

    def test_three_independent_record_stages_are_consumed(self):
        for kind in ('start','ready','cleanup'):
            with self.claim(kind) as record:self.assertTrue(record.report()['localConsumedRecordFlushed'])
            with self.assertRaises(OSError):
                with self.claim(kind):self.fail('Replayed attempt')
        self.assertEqual(len(list(self.root.iterdir())),3)

    def test_post_claim_failure_cannot_retry(self):
        with self.assertRaises(RuntimeError):
            with self.claim():raise RuntimeError('generated failure')
        with self.assertRaises(OSError):
            with self.claim():self.fail('Retried failed action')

    def test_fsync_failure_consumes_attempt_before_yield(self):
        with patch.object(guard.attempts.os,'fsync',side_effect=OSError('generated fsync failure')):
            with self.assertRaises(OSError):
                with self.claim():self.fail('Unflushed record yielded')
        with self.assertRaises(OSError):
            with self.claim():self.fail('Reopened unflushed attempt')

    def test_fixed_arguments_have_no_mount_port_endpoint_or_payload(self):
        args=guard._arguments('fixed','sha256:'+'a'*64,{'z':'generated'})
        self.assertEqual(args[-len(guard.COMMAND):],guard.COMMAND)
        for item in ('--network=none','--read-only','--rm','--pull=never','--restart=no'):self.assertIn(item,args)
        for item in ('--mount','--volume','--publish','--privileged','--env','--host'):self.assertNotIn(item,args)

    def test_wall_and_monotonic_expiry_and_clock_rollback(self):
        owner=guard.PublicCleanupGuard.__new__(guard.PublicCleanupGuard);owner._wall=100;owner._mono=100
        for wall,mono,expected in ((100,100,0),(101,105,5),(105,101,5)):
            with patch.object(guard.time,'time_ns',return_value=wall),patch.object(guard.time,'monotonic_ns',return_value=mono):
                self.assertEqual(owner._elapsed(),expected)
        for wall,mono in ((99,100),(100,99),(100+guard.LEASE_NS+guard.ACTION_NS,100),(100,100+guard.LEASE_NS+guard.ACTION_NS)):
            with patch.object(guard.time,'time_ns',return_value=wall),patch.object(guard.time,'monotonic_ns',return_value=mono):
                with self.assertRaises(REFUSALS):owner._elapsed()

    def test_complete_source_inventory_and_cli_entrypoint_are_fixed(self):
        actual={str(p.relative_to(ROOT)).replace('\\','/') for p in (ROOT/'eng/pilot').glob('*.py')}
        self.assertEqual(set(guard.SOURCES),actual|{'eng/pilot/probe-runtime-profile.json'})
        self.assertEqual(len(guard.SOURCES),len(set(guard.SOURCES)))
        self.assertIn('eng/pilot/PublicCleanupController.py',guard.SOURCES)

    def test_wrong_source_digest_refuses_before_docker_or_controller(self):
        pins={name:guard.H((ROOT/name).read_bytes()) for name in guard.SOURCES}
        pins[guard.SOURCES[0]]='f'*64
        path=Path(sys.executable).resolve();digest=guard.H(path.read_bytes())
        with patch.object(guard.native,'_Docker') as docker,patch.object(guard,'_Controller') as controller:
            with self.assertRaises(REFUSALS):guard.PublicCleanupGuard(ROOT,self.root,self.nonce,path,digest,path,digest,pins)
            docker.assert_not_called();controller.assert_not_called()

    def generated_action(self):
        receipt,value=fixture()
        owner=guard.PublicCleanupGuard.__new__(guard.PublicCleanupGuard)
        owner._root=self.root;owner._nonce=self.nonce;owner._receipt=guard.C(receipt);owner._source_digest='c'*64
        owner._python=None;owner._ready=Mock();owner._controller=Mock()
        owner._controller.state.return_value='exited'
        owner._check=Mock();owner._elapsed=Mock(return_value=0)
        owner._docker=Mock()
        return owner,receipt,value

    def test_cleanup_flush_failure_releases_no_docker_action(self):
        owner,_,_=self.generated_action()
        with patch.object(guard.attempts.os,'fsync',side_effect=OSError('generated flush refusal')):
            with self.assertRaises(OSError):owner.cleanup()
        owner._docker._call.assert_not_called()
        with self.assertRaises(OSError):owner.cleanup()
        owner._docker._call.assert_not_called()

    def test_lost_remove_reply_is_consumed_and_cannot_delete_twice(self):
        owner,receipt,value=self.generated_action()
        owner._docker._call.side_effect=[guard.C(value),OSError('generated lost remove reply')]
        with self.assertRaises(OSError):owner.cleanup()
        self.assertEqual(owner._docker._call.call_count,2)
        self.assertEqual(owner._docker._call.call_args.args[0],['container','rm','--force',receipt['containerId']])
        with self.assertRaises(OSError):owner.cleanup()
        self.assertEqual(owner._docker._call.call_count,2)

    def test_wrong_remove_reply_cannot_claim_success_or_retry(self):
        owner,_,value=self.generated_action()
        owner._docker._call.side_effect=[guard.C(value),b'foreign\n']
        with self.assertRaises(ValueError):owner.cleanup()
        with self.assertRaises(OSError):owner.cleanup()
        self.assertEqual(owner._docker._call.call_count,2)

    def test_actual_owned_controller_identity_and_pipe_eof(self):
        path=Path(sys.executable).resolve()
        with guard.process.PinnedFile(path,guard.H(path.read_bytes()),True) as executable:
            parent=guard.identity.current_identity(executable)
            controller=guard._Controller(ROOT,executable,self.nonce,parent)
            try:
                self.assertEqual(controller.state(executable),'live')
                self.assertNotEqual(controller.observed['pid'],parent['pid'])
                controller.child.stdin.close()
                deadline=time.monotonic()+5
                while not controller.exited():
                    self.assertLess(time.monotonic(),deadline);time.sleep(0.01)
                self.assertEqual(controller.state(executable),'exited')
            finally:controller.close()

    def test_controller_rejects_wrong_actual_parent(self):
        path=Path(sys.executable).resolve()
        with guard.process.PinnedFile(path,guard.H(path.read_bytes()),True) as executable:
            parent=guard.identity.current_identity(executable);parent['birthToken']='1'
            with self.assertRaises(REFUSALS):guard._Controller(ROOT,executable,self.nonce,parent)

    def test_start_replay_refuses_before_docker_or_controller(self):
        pins={name:guard.H((ROOT/name).read_bytes()) for name in guard.SOURCES}
        path=Path(sys.executable).resolve();digest=guard.H(path.read_bytes())
        with self.claim('start'):pass
        with patch.object(guard.native,'_Docker') as docker,patch.object(guard,'_Controller') as controller:
            with self.assertRaises(OSError):guard.PublicCleanupGuard(ROOT,self.root,self.nonce,path,digest,path,digest,pins)
            docker.assert_not_called();controller.assert_not_called()


if __name__=='__main__':
    result=unittest.TextTestRunner().run(unittest.defaultTestLoader.loadTestsFromTestCase(PublicGuardContracts))
    if not result.wasSuccessful() or result.skipped:raise SystemExit(1)
    print('PUBLIC GUARD CONTRACT PASS: '+json.dumps(dict(tests=result.testsRun,skipped=0,sourcePins=len(guard.SOURCES),
        actualOwnedControllerExercised=True,dockerOperationsPerformed=0,originalInputsRead=False,originalPrivatePkiUsed=False,phase7Complete=False),sort_keys=True))
