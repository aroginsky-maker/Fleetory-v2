"""Generated typed-source/retained-record contracts. No guardian process or Docker daemon."""
import copy
import json
import os
from pathlib import Path
import sys
import time
import unittest
from unittest.mock import patch

import retained_runtime_tests as vectors
import audit_public_cleanup_guard as guard

policy=vectors.policy
C,H=policy.container.canonical,policy.packet.digest
ROOT=Path(__file__).resolve().parents[2]
REFUSALS=(OSError,ValueError,guard.attempts.files.archive.ArchiveError)


class RetainedGuardPreparationContracts(unittest.TestCase):
    def setUp(self):
        self.fixture=vectors.RetainedRuntimeContracts();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.repo=self.fixture.fixture.repo
        for name in guard.SOURCES:
            path=self.repo/name;path.parent.mkdir(exist_ok=True,parents=True);path.write_bytes((ROOT/name).read_bytes())
        self.operator=self.fixture.fixture.root/'operator';self.operator.mkdir(mode=0o700)
        self.python=Path(sys.executable).resolve(strict=True)
        self.docker=self.fixture.fixture.root/('docker.exe' if os.name=='nt' else 'docker')
        self.docker.write_bytes(b'fixed public metadata-only executable canary');self.docker.chmod(0o700)
        self.pins={name:H((self.repo/name).read_bytes()) for name in guard.SOURCES}

    def source(self):
        retained,image=self.fixture.source();target=self.fixture.target(image)
        return retained,image,target

    def prepare(self,target,**changes):
        args=dict(python_path=self.python,python_sha256=H(self.python.read_bytes()),
            docker_path=self.docker,docker_sha256=H(self.docker.read_bytes()),source_pins=self.pins)
        args.update(changes)
        item=policy.RetainedGuardPreparation(target.session,target,self.operator,**args)
        self.addCleanup(item.close);return item

    def path(self,target,ready=False):return self.operator/policy.guardian_preparation_name(target.intent['nonce'],ready=ready)

    def assert_consumed(self,target):
        self.assertTrue(self.path(target).is_file())
        with self.assertRaises(OSError):self.prepare(target)

    def test_same_source_descriptor_lineage_and_actual_current_process(self):
        retained,image,target=self.source();before={name:pin.fd for name,pin in retained._bundle.pins.items()}
        item=self.prepare(target);report=item.report()
        self.assertEqual(report['controller']['pid'],os.getpid())
        self.assertEqual(report['controller']['executableSha256'],H(self.python.read_bytes()))
        self.assertEqual(report['sourcePinsSha256'],H(C(self.pins)))
        self.assertEqual(report['runtimeIntentSha256'],target._pin)
        self.assertEqual(report['lineage']['heldDescriptorsSha256'],retained.descriptor_pin)
        self.assertEqual(report['lineage']['publicationReadbackSha256'],H(target.session._records['publication-continuation-readback.json'][1]))
        self.assertEqual(report['publicationDescriptorsHeld'],4)
        self.assertEqual(before,{name:pin.fd for name,pin in retained._bundle.pins.items()})
        self.assertTrue(report['actualPreparingControllerIdentityVerified'])
        self.assertTrue(self.path(target,True).is_file())

    def test_preparation_never_dispatches_or_claims_execution(self):
        _,_,target=self.source()
        with patch.object(guard.process,'_spawn') as spawn,patch.object(guard.native,'_Docker') as docker:
            report=self.prepare(target).report();spawn.assert_not_called();docker.assert_not_called()
        self.assertEqual(report['dockerOperationsPerformed'],0)
        for key in ('guardianProcessStarted','ownDockerCreateReceiptAvailable','launchAuthorized','cleanupAuthorized',
                'retainedControllerDeathCleanupVerified','retainedExpiryCleanupVerified','publicationOriginAuthenticated',
                'dependenciesAuthenticated','independentRollbackResistanceVerified','originalInputsRead','originalPrivatePkiUsed',
                'sourceVpsAccessed','fullSystemRecoveryVerified','phase7Complete'):self.assertIs(report[key],False,key)

    def test_serialized_report_cannot_replace_exact_source_capability(self):
        _,_,target=self.source();value=json.loads(C(target.report()))
        args=dict(python_path=self.python,python_sha256=H(self.python.read_bytes()),docker_path=self.docker,
            docker_sha256=H(self.docker.read_bytes()),source_pins=self.pins)
        with self.assertRaises(ValueError):policy.RetainedGuardPreparation(target.session,value,self.operator,**args)
        self.assert_consumed(target);self.assertFalse(self.path(target,True).exists())

    def test_subclass_cannot_enter_preparation(self):
        _,_,target=self.source()
        class Foreign(policy.RetainedRuntimeBinding):pass
        altered=object.__new__(Foreign);altered.__dict__.update(target.__dict__)
        with self.assertRaises(ValueError):self.prepare(altered)
        self.assert_consumed(target)

    def test_foreign_session_is_refused_after_consumption(self):
        _,_,target=self.source();_,_,foreign=self.source()
        with patch.object(target,'session',foreign.session),self.assertRaises(ValueError):self.prepare(target)
        self.assertTrue((self.operator/policy.guardian_preparation_name(foreign.intent['nonce'])).exists())

    def test_bound_runtime_is_never_adopted(self):
        _,_,target=self.source();target.bind(C(self.fixture.observation(target)),'b'*64)
        with self.assertRaises(ValueError):self.prepare(target)
        self.assert_consumed(target)

    def test_failed_observation_cannot_be_promoted(self):
        _,_,target=self.source()
        with self.assertRaises(ValueError):target.bind(b'{}','b'*64)
        with self.assertRaises(ValueError):self.prepare(target)
        self.assert_consumed(target)

    def test_target_binding_after_preparation_invalidates_prepared_snapshot(self):
        _,_,target=self.source();item=self.prepare(target)
        target.bind(C(self.fixture.observation(target)),'b'*64)
        with self.assertRaises(ValueError):item.report()

    def test_all_lineage_metadata_is_frozen_and_returned_as_fresh_copy(self):
        _,_,target=self.source();item=self.prepare(target);before=item.report()
        returned=item.report();returned['lineage']['imageId']='sha256:'+'f'*64;returned['launchAuthorized']=True
        self.assertEqual(item.report(),before)

    def test_rewritten_inmemory_target_cannot_escape_persisted_intent(self):
        _,_,target=self.source();target.intent['name']='foreign-name'
        target._intent_bytes=C(target.intent);target._pin=H(target._intent_bytes)
        target.report() # The older metadata object's in-memory check alone is insufficient here.
        with self.assertRaises(ValueError):self.prepare(target)
        self.assert_consumed(target)

    def test_prepared_snapshot_detects_later_runtime_intent_change(self):
        _,_,target=self.source();item=self.prepare(target);target.intent['imageId']='sha256:'+'f'*64
        with self.assertRaises(ValueError):item.report()

    def test_close_preserves_existing_source_and_target_handles(self):
        retained,image,target=self.source();item=self.prepare(target);fds=[pin.fd for pin in item._sources]
        item.close();item.close()
        for fd in fds:
            with self.assertRaises(OSError):os.fstat(fd)
        retained.check();image.report();target.report()
        with self.assertRaises(ValueError):item.report()
        self.assert_consumed(target)

    def test_retained_or_target_closure_invalidates_preparation(self):
        for which in ('retained','target'):
            retained,_,target=self.source();item=self.prepare(target)
            (retained if which=='retained' else target).close()
            with self.assertRaises(ValueError):item.report()

    def test_image_and_retained_deadlines_remain_binding(self):
        retained,image,target=self.source();item=self.prepare(target);image._deadline=time.monotonic()-1
        with self.assertRaises(ValueError):item.report()
        retained,_,target=self.source();item=self.prepare(target)
        with patch.object(policy.publication.time,'monotonic_ns',return_value=retained._monotonic+policy.publication.WINDOW_NS):
            with self.assertRaises(ValueError):item.report()

    def test_wall_rollback_and_target_deadline_are_refused(self):
        retained,_,target=self.source();item=self.prepare(target)
        with patch.object(policy.time,'time_ns',return_value=retained.opened-1),self.assertRaises(ValueError):item.report()
        target._deadline=time.monotonic()-1
        with self.assertRaises(ValueError):item.report()

    def test_forked_or_foreign_caller_is_refused(self):
        _,_,target=self.source();item=self.prepare(target)
        with patch.object(policy.os,'getpid',return_value=os.getpid()+1),self.assertRaises(ValueError):item.report()

    def test_missing_extra_or_bad_source_pin_consumes_attempt(self):
        for change in ('missing','extra','bad'):
            _,_,target=self.source();pins=dict(self.pins)
            if change=='missing':pins.pop(next(iter(pins)))
            elif change=='extra':pins['foreign/file.py']='a'*64
            else:pins[next(iter(pins))]='f'*64
            with self.assertRaises(REFUSALS):self.prepare(target,source_pins=pins)
            self.assert_consumed(target)

    def test_wrong_executable_pin_or_docker_role_consumes_attempt(self):
        for key in ('python_sha256','docker_sha256','docker_path'):
            _,_,target=self.source()
            changed={key:self.python if key=='docker_path' else 'f'*64}
            if key=='docker_path':changed['docker_sha256']=H(self.python.read_bytes())
            with self.assertRaises(REFUSALS):self.prepare(target,**changed)
            self.assert_consumed(target)

    def test_source_mutation_is_denied_or_detected(self):
        _,_,target=self.source();item=self.prepare(target);path=self.repo/'eng/pilot/PublicCleanupController.py'
        try:path.write_bytes(b'changed public-only source')
        except PermissionError:item.report()
        else:
            with self.assertRaises(REFUSALS):item.report()

    def test_replay_refuses_before_opening_executables(self):
        _,_,target=self.source();item=self.prepare(target);item.close()
        before={p.name:H(p.read_bytes()) for p in self.operator.iterdir()}
        with patch.object(guard.process,'PinnedFile') as pinned:
            with self.assertRaises(OSError):self.prepare(target)
            pinned.assert_not_called()
        self.assertEqual(before,{p.name:H(p.read_bytes()) for p in self.operator.iterdir()})

    def test_attempt_fsync_failure_is_consumed_without_ready_record(self):
        _,_,target=self.source()
        with patch.object(guard.attempts.os,'fsync',side_effect=OSError('generated flush failure')):
            with self.assertRaises(OSError):self.prepare(target)
        self.assert_consumed(target);self.assertFalse(self.path(target,True).exists())

    def test_ready_flush_crossing_deadline_returns_no_preparation(self):
        _,_,target=self.source();original=guard.attempts.create_ledger
        def expire(directory,fd,name):
            result=original(directory,fd,name)
            if name==policy.guardian_preparation_name(target.intent['nonce'],ready=True):target._deadline=time.monotonic()-1
            return result
        with patch.object(guard.attempts,'create_ledger',side_effect=expire),self.assertRaises(ValueError):self.prepare(target)
        self.assertTrue(self.path(target,True).exists());self.assert_consumed(target)


if __name__=='__main__':
    result=unittest.TextTestRunner().run(unittest.defaultTestLoader.loadTestsFromTestCase(RetainedGuardPreparationContracts))
    if not result.wasSuccessful() or result.skipped:raise SystemExit(1)
    print('RETAINED GUARD PREPARATION PASS: '+json.dumps(dict(tests=result.testsRun,skipped=0,sourcePins=len(guard.SOURCES),
        actualPreparingControllerIdentityExercised=True,generatedLineageOnly=True,guardianProcessStarted=False,dockerOperationsPerformed=0,
        cleanupAuthorized=False,originalInputsRead=False,originalPrivatePkiUsed=False,phase7Complete=False),sort_keys=True))
