"""Real generated ledger/restart/failure contracts. No Docker or original input."""
from concurrent.futures import ThreadPoolExecutor
import base64
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'eng/pilot'))
import cleanup_protocol_tests as vectors
import audit_cleanup_attempt as policy

C,H=policy.C,policy.packet.digest
REFUSALS=(OSError,ValueError,policy.files.archive.ArchiveError)


class CleanupAttemptContracts(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='fleetory-public-attempt-');self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve()/'operator';self.root.mkdir(mode=0o700)
        generated=vectors.CleanupProtocolContracts();generated.setUp()
        self.value,self.receipt,self.resource=generated.value,generated.receipt,generated.resource

    def claim(self,**changes):
        values=dict(ticket=C(self.value),expected_ticket=H(C(self.value)),create_receipt=C(self.receipt),resource=C(self.resource))
        values.update(changes)
        return policy.claim(self.root,**values)

    def ledger(self):return self.root/policy.ledger_name(self.value['nonce'])

    def child(self,mode='--attempt'):
        frame=C(dict(ticket=base64.b64encode(C(self.value)).decode('ascii'),pin=H(C(self.value)),
            receipt=base64.b64encode(C(self.receipt)).decode('ascii'),resource=base64.b64encode(C(self.resource)).decode('ascii')))
        return subprocess.run([sys.executable,'-B',str(Path(__file__).resolve()),mode,str(self.root)],
            input=frame,capture_output=True,timeout=10)

    def test_exact_binding_is_flushed_and_never_grants_cleanup(self):
        with self.claim() as attempt:
            report=attempt.report()
            self.assertEqual(report['ticketSha256'],H(C(self.value)))
            self.assertEqual(report['createReceiptSha256'],H(C(self.receipt)))
            self.assertEqual(report['resourceAssertionSha256'],H(C(self.resource)))
            self.assertEqual(report['status'],'ATTEMPT_CONSUMED');self.assertTrue(report['localConsumedRecordFlushed'])
            self.assertFalse(os.get_inheritable(attempt._stream.fileno()))
            for key in ('actualProcessIdentityVerified','createReceiptOriginAuthenticated','cleanupAuthorized','actualCleanupExecuted',
                    'independentExpiryEnforcementVerified','controllerDeathCleanupVerified','supervisorDeathCleanupVerified',
                    'operationalLeaseAuthorized','externalRollbackResistanceVerified','fullSystemRecoveryVerified','phase7Complete'):
                self.assertIs(report[key],False)
        self.assertNotIn('localConsumedRecordFlushed',json.loads(self.ledger().read_bytes()))
        if os.name=='posix':self.assertEqual(self.ledger().stat().st_mode&0o777,0o600)

    def test_eight_concurrent_claims_have_one_winner(self):
        barrier=threading.Barrier(8)
        def claim(_):
            barrier.wait(timeout=5)
            try:
                with self.claim() as attempt:return attempt.report()['status']=='ATTEMPT_CONSUMED'
            except OSError:return False
        with ThreadPoolExecutor(max_workers=8) as pool:self.assertEqual(sum(pool.map(claim,range(8))),1)

    def test_fresh_python_process_refuses_consumed_nonce(self):
        with self.claim():pass
        original=self.ledger().read_bytes()
        for _ in range(2):
            run=self.child()
            self.assertEqual((run.returncode,run.stdout,run.stderr),(3,b'REFUSED\n',b''))
            self.assertEqual(self.ledger().read_bytes(),original)

    def test_abrupt_writer_exit_remains_consumed_in_another_process(self):
        crashed=self.child('--attempt-crash')
        self.assertEqual((crashed.returncode,crashed.stdout,crashed.stderr),(17,b'CLAIMED\n',b''))
        original=self.ledger().read_bytes();replay=self.child()
        self.assertEqual((replay.returncode,replay.stdout,replay.stderr),(3,b'REFUSED\n',b''))
        self.assertEqual(self.ledger().read_bytes(),original)

    def test_same_nonce_new_ticket_cannot_reset_history(self):
        with self.claim():pass
        original=self.ledger().read_bytes();self.value['controller']['birthToken']='999'
        with self.assertRaises(OSError):
            with self.claim():self.fail('New ticket reset a consumed nonce.')
        self.assertEqual(self.ledger().read_bytes(),original)

    def test_failure_after_claim_retains_record_without_exception_canary(self):
        with self.assertRaises(RuntimeError):
            with self.claim():raise RuntimeError('PRIVATE_FAILURE_CANARY')
        self.assertNotIn(b'PRIVATE_FAILURE_CANARY',self.ledger().read_bytes())
        with self.assertRaises(OSError):
            with self.claim():self.fail('Failed attempt was retried.')

    def test_short_write_is_a_consumed_failure_before_yield(self):
        original=policy.os.fdopen
        class ShortWrite:
            def __init__(self,stream):self.stream=stream
            def __getattr__(self,name):return getattr(self.stream,name)
            def __enter__(self):return self
            def __exit__(self,*args):self.stream.close()
            def write(self,data):return self.stream.write(data[:3])
        with patch.object(policy.os,'fdopen',side_effect=lambda *a,**kw:ShortWrite(original(*a,**kw))),self.assertRaises(ValueError):
            with self.claim():self.fail('Partial ledger yielded.')
        self.assertEqual(len(self.ledger().read_bytes()),3)
        with self.assertRaises(OSError):
            with self.claim():self.fail('Partial ledger retried.')

    def test_file_flush_failure_cannot_return_a_success_report(self):
        with patch.object(policy.os,'fsync',side_effect=OSError('PRIVATE_FLUSH_CANARY')),self.assertRaises(OSError):
            with self.claim():self.fail('Failed flush yielded.')
        record=self.ledger().read_bytes()
        self.assertNotIn(b'PRIVATE_FLUSH_CANARY',record);self.assertNotIn(b'localConsumedRecordFlushed',record)
        with self.assertRaises(OSError):
            with self.claim():self.fail('Unconfirmed flush was retried.')

    def test_changed_live_record_is_refused(self):
        with self.assertRaises(ValueError):
            with self.claim() as attempt:
                attempt._stream.seek(0);attempt._stream.write(b'!')
                attempt.report()
        with self.assertRaises(OSError):
            with self.claim():self.fail('Changed ledger was adopted.')

    def test_replaced_operator_directory_is_prevented_or_detected(self):
        moved=self.root.with_name('moved-operator')
        with self.assertRaises(REFUSALS):
            with self.claim() as attempt:
                try:self.root.rename(moved)
                except OSError:
                    self.assertEqual(os.name,'nt');raise
                self.root.mkdir(mode=0o700)
                attempt.report()

    def test_existing_malformed_record_is_never_overwritten(self):
        self.ledger().write_bytes(b'UNTRUSTED_EXISTING_RECORD')
        with self.assertRaises(OSError):
            with self.claim():self.fail('Existing ledger adopted.')
        self.assertEqual(self.ledger().read_bytes(),b'UNTRUSTED_EXISTING_RECORD')

    def test_existing_hardlink_is_refused_without_touching_target(self):
        target=self.root/'sentinel';target.write_bytes(b'UNRELATED_SENTINEL');os.link(target,self.ledger())
        with self.assertRaises(OSError):
            with self.claim():self.fail('Hardlink adopted.')
        self.assertEqual(target.read_bytes(),b'UNRELATED_SENTINEL')

    def test_inputs_are_all_frozen_before_ticket_validation(self):
        receipt,resource=bytearray(C(self.receipt)),bytearray(C(self.resource));original=policy.protocol._ticket
        def changed(*args):
            receipt[:]=b'CHANGED';resource[:]=b'CHANGED'
            return original(*args)
        with patch.object(policy.protocol,'_ticket',side_effect=changed):
            with self.claim(create_receipt=receipt,resource=resource) as attempt:
                self.assertEqual(attempt.report()['createReceiptSha256'],H(C(self.receipt)))
                self.assertEqual(attempt.report()['resourceAssertionSha256'],H(C(self.resource)))

    def test_wrong_pins_receipts_resources_and_unsafe_fields_create_no_record(self):
        extra=copy.deepcopy(self.value);extra['command']='DO_NOT_EXECUTE'
        for changes in (dict(expected_ticket='f'*64),dict(create_receipt=b'{}'),dict(resource=b'{}'),
                dict(ticket=C(extra),expected_ticket=H(C(extra))),dict(ticket=True),dict(resource=b'x'*8193)):
            with self.subTest(changes=tuple(changes)),self.assertRaises(REFUSALS):
                with self.claim(**changes):self.fail('Invalid packet accepted.')
            self.assertFalse(self.ledger().exists())

    def test_closed_observer_and_changed_caller_are_refused(self):
        with self.claim() as attempt:
            with patch.object(policy.os,'getpid',return_value=os.getpid()+1),self.assertRaises(ValueError):attempt.report()
        with self.assertRaises(ValueError):attempt.report()

    def test_close_during_namespace_recheck_refuses_without_none_attribute_access(self):
        with self.assertRaises(ValueError):
            with self.claim() as attempt:
                with patch.object(attempt._directory,'check',side_effect=attempt.close):attempt.report()

    def test_returned_record_cannot_rearm_or_change_the_binding(self):
        with self.claim() as attempt:
            changed=attempt.report();changed['controller']['pid']+=1;changed['status']='NEW'
            self.assertEqual(attempt.report()['controller'],self.value['controller'])
            self.assertEqual(attempt.report()['status'],'ATTEMPT_CONSUMED')
            with self.assertRaises(ValueError):attempt._seal()

    def test_posix_parent_and_file_modes_or_windows_exclusive_sharing_are_enforced(self):
        if os.name=='posix':
            self.root.chmod(0o755)
            with self.assertRaises(ValueError):
                with self.claim():self.fail('Public directory accepted.')
            self.root.chmod(0o700)
            with self.assertRaises(ValueError):
                with self.claim() as attempt:
                    self.ledger().chmod(0o644);attempt.check()
        else:
            with self.claim():
                with self.assertRaises(OSError):self.ledger().write_bytes(b'UNRELATED_WRITE')


if __name__=='__main__':
    if len(sys.argv)==3 and sys.argv[1] in ('--attempt','--attempt-crash'):
        try:
            frame=json.loads(sys.stdin.buffer.read(40001))
            with policy.claim(Path(sys.argv[2]),base64.b64decode(frame['ticket'],validate=True),frame['pin'],
                    base64.b64decode(frame['receipt'],validate=True),base64.b64decode(frame['resource'],validate=True)):
                if sys.argv[1]=='--attempt-crash':
                    sys.stdout.buffer.write(b'CLAIMED\n');sys.stdout.buffer.flush();os._exit(17)
        except Exception:sys.stdout.buffer.write(b'REFUSED\n');raise SystemExit(3)
        sys.stdout.buffer.write(b'CONSUMED\n')
    else:
        result=unittest.main(exit=False).result
        if not result.wasSuccessful():raise SystemExit(1)
        print('CLEANUP ATTEMPT CONTRACT PASS: '+json.dumps(dict(schema='fleetory.cleanup-attempt-contract-proof.v1',
            tests=result.testsRun,skipped=len(result.skipped),sourceSha256=H(Path(policy.__file__).read_bytes()),
            generatedOnly=True,dockerOperationsPerformed=0,actualCleanupExecuted=False,createReceiptOriginAuthenticated=False,
            externalRollbackResistanceVerified=False,independentExpiryEnforcementVerified=False,fullSystemRecoveryVerified=False,phase7Complete=False),sort_keys=True))
