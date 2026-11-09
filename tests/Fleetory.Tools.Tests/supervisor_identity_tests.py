"""Actual self process-object contracts; no Docker, parent selection or cleanup operation."""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'eng/pilot'))
import audit_supervisor_identity as policy


class SupervisorIdentityContracts(unittest.TestCase):
    def setUp(self):
        path=Path(sys.executable).resolve();digest=policy.packet.digest(path.read_bytes())
        self.pin=self.enterContext(policy.process.PinnedFile(path,digest,True))
        self.identity=policy.current_identity(self.pin)

    def test_actual_self_birth_and_entry_image_are_bound_to_held_object(self):
        with policy.HeldLocalPeer('self',self.pin,self.identity) as peer:
            report=peer.snapshot();self.assertEqual(report['identity'],self.identity);self.assertEqual(report['state'],'live')
            self.assertTrue(report['heldOsProcessObject']);self.assertTrue(report['nonInheritable']);self.assertTrue(report['actualEntryImageAndBirthMatched'])
            for key in ('processSignalAuthorized','cleanupAuthorized','supervisorIndependenceVerified','controllerDeathCleanupVerified'):self.assertIs(report[key],False)

    def test_wrong_pid_is_rejected_before_any_process_open(self):
        bad=dict(self.identity,pid=self.identity['pid']+1)
        with patch.object(policy,'_WindowsPeer') as windows,patch.object(policy,'_LinuxPeer') as linux:
            with self.assertRaises(ValueError):policy.HeldLocalPeer('self',self.pin,bad)
            windows.assert_not_called();linux.assert_not_called()

    def test_changed_birth_or_image_cannot_match_the_same_scalar_pid(self):
        for key,value in (('birthToken','1' if self.identity['birthToken']!='1' else '2'),('executableSha256','f'*64)):
            with self.subTest(key=key),self.assertRaises(ValueError):policy.HeldLocalPeer('self',self.pin,dict(self.identity,**{key:value}))

    def test_roles_identity_aliases_and_unknown_fields_are_closed(self):
        with self.assertRaises(ValueError):policy.HeldLocalPeer('arbitrary',self.pin,self.identity)
        for key,value in (('pid',True),('birthToken',True),('verified',True)):
            with self.subTest(key=key),self.assertRaises(ValueError):policy.HeldLocalPeer('self',self.pin,dict(self.identity,**{key:value}))

    def test_close_invalidates_observer_without_closing_the_executable_pin(self):
        peer=policy.HeldLocalPeer('self',self.pin,self.identity);peer.close();peer.close()
        with self.assertRaises(ValueError):peer.snapshot()
        self.pin.check()

    def test_returned_identity_mutation_does_not_modify_held_expectation(self):
        with policy.HeldLocalPeer('self',self.pin,self.identity) as peer:
            first=peer.snapshot();first['identity']['pid']+=1
            self.assertEqual(peer.snapshot()['identity'],self.identity)

    def test_wrong_birth_kind_and_untyped_pin_are_not_accepted(self):
        other='windows-filetime' if self.identity['birthKind']=='linux-proc-start-ticks' else 'linux-proc-start-ticks'
        with self.assertRaises(ValueError):policy.HeldLocalPeer('self',self.pin,dict(self.identity,birthKind=other))
        with self.assertRaises(ValueError):policy.HeldLocalPeer('self',object(),self.identity)

    def test_fork_or_reused_caller_cannot_use_existing_observer(self):
        with policy.HeldLocalPeer('self',self.pin,self.identity) as peer:
            with patch.object(policy.os,'getpid',return_value=self.identity['pid']+1),self.assertRaises(ValueError):peer.snapshot()


if __name__=='__main__':unittest.main()
