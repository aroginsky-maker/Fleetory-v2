"""Actual disposable filesystem/race contracts; no original files or native service."""
from concurrent.futures import ThreadPoolExecutor
import dataclasses
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import audit_use_admission_tests as vectors
import audit_use_transaction as policy

REFUSALS=(ValueError,OSError,policy.files.archive.ArchiveError)


class AuditUseTransactionTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='fleetory-audit-use-')
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve()
        self.operator=self.root/'operator';self.operator.mkdir(mode=0o700)
        self.offline=self.root/'offline';self.offline.mkdir(mode=0o700)
        vector=vectors.AuditUseAdmissionTests();vector.setUp()
        self.accepted=vector.admit();self.data=vector.parts['archive']
        self.source=self.offline/self.accepted.archive_path
        self.source.parent.mkdir();self.source.write_bytes(self.data)

    def ledger(self):
        return self.operator/policy.ledger_name(self.accepted.nonce)

    def record(self):
        return json.loads(self.ledger().read_bytes())

    def transaction(self):
        return policy.transaction(self.operator,self.accepted)

    def held_record(self,session):
        os.lseek(session._fd,0,os.SEEK_SET)
        return json.loads(os.read(session._fd,policy.MAX_LEDGER+1))

    def junction(self,link,target):
        if os.name=='nt':
            result=subprocess.run(['cmd.exe','/d','/c','mklink','/J',str(link),str(target)],capture_output=True,timeout=5)
            self.assertEqual(result.returncode,0,'Generated junction could not be created.')
            self.addCleanup(lambda:os.rmdir(link) if link.exists() else None)
        else:
            link.symlink_to(target,target_is_directory=True)
            self.addCleanup(lambda:link.unlink() if link.is_symlink() else None)

    def test_claim_is_saved_before_exactly_one_audit_open(self):
        original=policy.archive.files.inspect_file
        with self.transaction() as session:
            def observed(*args,**kwargs):
                record=self.held_record(session)
                self.assertEqual((record['status'],record['archiveCaptureAttempts']),('CAPTURE_ATTEMPT_CONSUMED',1))
                return original(*args,**kwargs)
            with patch.object(policy.archive.files,'inspect_file',side_effect=observed) as opened, patch.object(policy.archive.files,'verify',side_effect=AssertionError('Broad verifier forbidden')):
                captured=session.capture(self.offline)
            self.assertEqual(opened.call_count,1)
            self.assertEqual(opened.call_args.args[2:],(self.accepted.archive_path,len(self.data)))
            self.assertEqual(captured.data,self.data)
        self.assertEqual(self.record()['status'],'CAPTURED_PRIVATE_NOT_DISPATCHED')

    def test_dispatch_slot_saved_before_callback_and_result_is_not_authenticated(self):
        with self.transaction() as session:
            session.capture(self.offline)
            def callback(value):
                record=self.held_record(session)
                self.assertEqual((record['dispatchAttempts'],record['status']),(1,'DISPATCH_ATTEMPT_CONSUMED'))
                self.assertEqual(value.data,self.data)
                return b'generated-result'
            self.assertEqual(session.dispatch(callback),b'generated-result')
        self.assertEqual(self.record()['status'],'DISPATCH_RETURNED_UNVERIFIED')
        self.assertFalse(self.record()['nativeResultAuthenticated'])
        self.assertFalse(self.record()['nativeLaunchAuthorized'])

    def test_capture_cannot_retry_or_reopen_after_success(self):
        with self.transaction() as session:
            session.capture(self.offline)
            with patch.object(policy.archive,'capture',side_effect=AssertionError('Second capture forbidden')):
                with self.assertRaises(ValueError):session.capture(self.offline)
        self.assertEqual(self.record()['archiveCaptureAttempts'],1)

    def test_dispatch_cannot_retry_even_after_lost_response(self):
        calls=[]
        def lost(value):
            calls.append(True)
            raise RuntimeError('PRIVATE_INPUT_CANARY')
        with self.assertRaises(RuntimeError):
            with self.transaction() as session:
                session.capture(self.offline)
                session.dispatch(lost)
        self.assertEqual(len(calls),1)
        self.assertEqual((self.record()['status'],self.record()['dispatchAttempts']),('FAILED_CONSUMED',1))
        self.assertNotIn('PRIVATE_INPUT_CANARY',self.ledger().read_text())
        with self.assertRaises(OSError):
            with self.transaction():self.fail('Consumed ledger reopened.')

    def test_same_nonce_replay_preserves_original_ledger_bytes(self):
        with self.transaction():pass
        original=self.ledger().read_bytes()
        with self.assertRaises(OSError):
            with self.transaction():self.fail('Replay admitted.')
        self.assertEqual(self.ledger().read_bytes(),original)

    def test_new_plan_digest_does_not_reset_a_consumed_nonce(self):
        with self.transaction():pass
        changed=dataclasses.replace(self.accepted,plan_sha256='f'*64)
        with self.assertRaises(OSError):
            with policy.transaction(self.operator,changed):self.fail('Nonce reset by plan replacement.')

    def test_concurrent_callers_get_one_capture_winner(self):
        def contender(_):
            try:
                with self.transaction() as session:session.capture(self.offline)
                return True
            except OSError:return False
        with ThreadPoolExecutor(max_workers=8) as pool:
            results=list(pool.map(contender,range(8)))
        self.assertEqual(results.count(True),1)
        self.assertEqual(self.record()['archiveCaptureAttempts'],1)

    def test_changed_source_fails_with_consumed_claim_and_no_dispatch(self):
        self.source.write_bytes(self.data+b'changed')
        with self.assertRaises(REFUSALS):
            with self.transaction() as session:session.capture(self.offline)
        self.assertEqual((self.record()['status'],self.record()['archiveCaptureAttempts'],self.record()['dispatchAttempts']),('FAILED_CONSUMED',1,0))
        self.assertEqual(self.source.read_bytes(),self.data+b'changed')

    def test_missing_source_also_consumes_attempt(self):
        self.source.unlink()
        with self.assertRaises(OSError):
            with self.transaction() as session:session.capture(self.offline)
        self.assertEqual(self.record()['archiveCaptureAttempts'],1)

    def test_captured_bytes_do_not_follow_later_source_changes(self):
        with self.transaction() as session:
            value=session.capture(self.offline)
            self.source.write_bytes(b'replaced')
            self.assertEqual(value.data,self.data)
            self.assertEqual(session.dispatch(lambda captured:captured.data),self.data)

    def test_dispatch_requires_successful_capture(self):
        with self.transaction() as session:
            with self.assertRaises(ValueError):session.dispatch(lambda _:self.fail('Premature callback.'))
        self.assertEqual(self.record()['dispatchAttempts'],0)

    def test_empty_and_oversized_callback_outputs_fail_consumed(self):
        for value in (b'',b'x'*(policy.MAX_RESULT+1)):
            nonce='00000000-0000-4000-8000-00000000000'+str(2 if value else 3)
            accepted=dataclasses.replace(self.accepted,nonce=nonce)
            with self.assertRaises(ValueError):
                with policy.transaction(self.operator,accepted) as session:
                    session.capture(self.offline);session.dispatch(lambda _,data=value:data)
            record=json.loads((self.operator/policy.ledger_name(nonce)).read_bytes())
            self.assertEqual((record['status'],record['dispatchAttempts']),('FAILED_CONSUMED',1))

    def test_preexisting_hardlinked_ledger_is_never_overwritten(self):
        victim=self.root/'victim';victim.write_bytes(b'untouched')
        os.link(victim,self.ledger())
        with self.assertRaises(OSError):
            with self.transaction():self.fail('Hardlinked ledger admitted.')
        self.assertEqual(victim.read_bytes(),b'untouched')

    def test_preexisting_ledger_junction_or_symlink_is_not_followed(self):
        victim=self.root/'victim';victim.mkdir();(victim/'keep').write_bytes(b'untouched')
        self.junction(self.ledger(),victim)
        with self.assertRaises(OSError):
            with self.transaction():self.fail('Linked ledger admitted.')
        self.assertEqual((victim/'keep').read_bytes(),b'untouched')

    def test_hardlinked_archive_refused_after_claim(self):
        os.link(self.source,self.root/'archive-alias')
        with self.assertRaises(REFUSALS):
            with self.transaction() as session:session.capture(self.offline)
        self.assertEqual(self.record()['status'],'FAILED_CONSUMED')

    def test_archive_parent_junction_refused_after_claim(self):
        self.source.unlink();self.source.parent.rmdir()
        victim=self.root/'outside';victim.mkdir();(victim/'backup.bin').write_bytes(self.data)
        self.junction(self.source.parent,victim)
        with self.assertRaises(REFUSALS):
            with self.transaction() as session:session.capture(self.offline)
        self.assertEqual(self.record()['archiveCaptureAttempts'],1)

    def test_live_ledger_cannot_be_replaced_silently(self):
        if os.name=='nt':
            with self.transaction() as session:
                with self.assertRaises(OSError):self.ledger().unlink()
                session.capture(self.offline)
        else:
            with self.assertRaises(ValueError):
                with self.transaction() as session:
                    self.ledger().rename(self.operator/'moved-ledger')
                    self.ledger().write_bytes(b'{}')
                    session.capture(self.offline)
            self.assertEqual(self.ledger().read_bytes(),b'{}')

    def test_linked_operator_root_refused_before_claim(self):
        linked=self.root/'operator-link';self.junction(linked,self.operator)
        with self.assertRaises(REFUSALS):
            with policy.transaction(linked,self.accepted):self.fail('Linked root admitted.')
        self.assertFalse(self.ledger().exists())

    def test_private_mode_or_exclusive_windows_sharing(self):
        with self.transaction() as session:
            if os.name=='posix':self.assertEqual(os.fstat(session._fd).st_mode & 0o777,0o600)
            else:
                with self.assertRaises(OSError):self.ledger().write_bytes(b'overwrite')
        self.assertEqual(self.record()['status'],'CLAIMED_CONSUMED')

    def test_held_ledger_descriptor_is_not_inheritable(self):
        with self.transaction() as session:
            self.assertFalse(os.get_inheritable(session._fd))
            self.assertFalse(session.report()['processSupervisionVerified'])
            self.assertFalse(session.report()['ownerCleanupVerified'])
            self.assertFalse(session.report()['rollbackResistanceVerified'])

    def test_report_detached_and_closed_session_cannot_dispatch(self):
        with self.transaction() as session:
            view=session.report();view['nativeLaunchAuthorized']=True
            self.assertFalse(session.report()['nativeLaunchAuthorized'])
            session.capture(self.offline)
        with self.assertRaises(ValueError):session.dispatch(lambda _:b'bad')

    def test_unknown_admission_or_forged_reference_refused_before_filesystem(self):
        for value in (object(),dataclasses.replace(self.accepted,archive_path='../wrong')):
            with patch.object(policy.files,'rooted',side_effect=AssertionError('Filesystem forbidden')):
                with self.assertRaises(ValueError):
                    with policy.transaction(self.operator,value):self.fail('Forged admission admitted.')

    def test_flush_failure_never_opens_source_or_removes_claim(self):
        with patch.object(policy.os,'fsync',side_effect=OSError('Generated flush failure')),patch.object(policy.archive,'capture',side_effect=AssertionError('Data forbidden')):
            with self.assertRaises(OSError):
                with self.transaction():self.fail('Unflushed claim admitted.')
        self.assertTrue(self.ledger().exists())
        with self.assertRaises(OSError):
            with self.transaction():self.fail('Failed claim silently reset.')

    def test_partial_writes_are_completed_and_zero_write_is_not_success(self):
        original=policy.os.write
        with patch.object(policy.os,'write',side_effect=lambda fd,data:original(fd,data[:max(1,len(data)//2)])):
            with self.transaction():pass
        self.assertEqual(self.record()['nonce'],self.accepted.nonce)
        changed=dataclasses.replace(self.accepted,nonce='00000000-0000-4000-8000-000000000004')
        with patch.object(policy.os,'write',return_value=0):
            with self.assertRaises(ValueError):
                with policy.transaction(self.operator,changed):self.fail('Zero write accepted.')


if __name__=='__main__':
    unittest.main()
