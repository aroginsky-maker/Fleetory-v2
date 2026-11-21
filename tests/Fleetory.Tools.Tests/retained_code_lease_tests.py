"""Held public code identities/bytes and pre-open boundaries; no original data or native work."""
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

sys.path.insert(0, str(Path(__file__).resolve().parents[2]/'eng/pilot'))
from historical import retained_code_lease as policy

H, C = policy.packet.digest, policy.prep.canonical
REFUSALS = (ValueError, OSError, TypeError, KeyError, policy.files.archive.ArchiveError)


class CodeLeaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='fleetory-held-code-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.names = ('eng/pilot/public.py', 'src/Product/Service.cs', '.editorconfig')
        for name in self.names:
            p = self.root/name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(('public source '+name).encode('ascii'))
        self.plan = dict(schema=policy.SCHEMA, revision='1'*40,
                         nonce='12345678-1234-4123-8123-123456789abc', sourcePins={})
        for name in self.names:
            data = (self.root/name).read_bytes()
            self.plan['sourcePins'][name] = dict(bytes=len(data), sha256=H(data))

    def opened(self, plan=None, names=None, raw=None, pin=None):
        raw = C(self.plan if plan is None else plan) if raw is None else raw
        return policy.hold(self.root, raw, H(raw) if pin is None else pin,
                           self.names if names is None else names)

    def no_open(self, plan, names=None, pin=None):
        with patch.object(policy.control, 'DirectoryLease') as opened:
            with self.assertRaises(REFUSALS), self.opened(plan, names, pin=pin):
                self.fail('invalid plan yielded a lease')
            opened.assert_not_called()

    def test_live_set_reports_only_actual_held_source_observations(self):
        with self.opened() as lease:
            value = lease.report()
            self.assertEqual(3, value['files'])
            self.assertEqual(sum(v['bytes'] for v in self.plan['sourcePins'].values()), value['bytes'])
            self.assertTrue(value['listedSourceIdentitiesAndBytesStable'])
            for name in ('metadataControlsRoot', 'sourceContentsReturned', 'sourceOriginAuthenticated',
                         'fullTransitiveInventoryVerified', 'nativeLaunchAuthorized', 'originalDataUseAuthorized',
                         'fullSystemRecoveryVerified', 'phase7Complete'):
                self.assertIs(False, value[name])
        with self.assertRaises(REFUSALS):
            lease.check()

    def test_copied_or_foreign_lease_cannot_recreate_the_live_owner(self):
        with self.opened() as lease:
            for foreign in (copy.copy(lease), policy.CodeLease()):
                with self.assertRaises(REFUSALS):
                    foreign.report()
            result = []
            def other_thread():
                try:
                    lease.check()
                except ValueError:
                    result.append('refused')
            thread = threading.Thread(target=other_thread)
            thread.start();thread.join(3)
            self.assertFalse(thread.is_alive())
            self.assertEqual(['refused'], result)
            lease.check()

    def test_metadata_root_command_callback_and_permission_fields_are_pre_open_refusals(self):
        for key in ('root', 'command', 'callback', 'permission', 'provider', 'pki', 'reset'):
            value = copy.deepcopy(self.plan);value[key] = 'not-authority'
            self.no_open(value)

    def test_untrusted_name_set_cannot_add_or_alias_public_source_names(self):
        for names in ([*self.names], (*self.names, self.names[0]),
                      (*self.names, self.names[0].upper()), (*self.names, 'provider/root.key'),
                      (*self.names, 'eng/pilot/../../provider.py'), (*self.names, '/src/code.cs')):
            self.no_open(self.plan, names)
        value = copy.deepcopy(self.plan);value['sourcePins']['eng/pilot/extra.py'] = dict(bytes=1, sha256='a'*64)
        self.no_open(value)

    def test_pin_revision_nonce_size_and_entry_shapes_refuse_before_root_open(self):
        self.no_open(self.plan, pin='a'*64)
        for name, wrong in (('revision', 'bad'), ('nonce', '00000000-0000-0000-0000-000000000000'), ('schema', 'other')):
            value=copy.deepcopy(self.plan);value[name]=wrong;self.no_open(value)
        for wrong in (True, 0, -1, policy.MAX_FILE+1):
            value=copy.deepcopy(self.plan);value['sourcePins'][self.names[0]]['bytes']=wrong;self.no_open(value)
        value=copy.deepcopy(self.plan);value['sourcePins'][self.names[0]]['executable']=True;self.no_open(value)

    def test_mutable_plan_buffer_is_frozen_before_yield(self):
        raw=bytearray(C(self.plan))
        with self.opened(raw=raw) as lease:
            original=lease.report()['planSha256']
            raw[:]=b'changed after opening'
            self.plan['sourcePins'].clear()
            self.assertEqual(original, lease.report()['planSha256'])

    def test_wrong_hash_closes_all_partial_source_descriptors(self):
        value=copy.deepcopy(self.plan);value['sourcePins']['src/Product/Service.cs']['sha256']='a'*64
        descriptors=[];original=policy.files.relative_open
        def opened(*args, **kwargs):
            fd=original(*args, **kwargs);descriptors.append(fd);return fd
        with patch.object(policy.files, 'relative_open', opened), self.assertRaises(REFUSALS), self.opened(value):
            self.fail('wrong hash yielded')
        self.assertTrue(descriptors)
        for descriptor in descriptors:
            with self.assertRaises(OSError):
                os.fstat(descriptor)

    def test_wrong_actual_length_refuses_before_content_read(self):
        (self.root/self.names[0]).write_bytes(b'larger file than declared')
        with patch.object(policy.os, 'fdopen', wraps=policy.os.fdopen) as read:
            with self.assertRaises(REFUSALS), self.opened():
                self.fail('wrong actual length yielded')
            # Sorted .editorconfig is read first; the changed file must not be read.
            self.assertLessEqual(read.call_count, 1)

    def test_hardlink_alias_is_not_read_as_public_code(self):
        source=self.root/self.names[0]
        os.link(source,self.root/'alias')
        with self.assertRaises(REFUSALS), self.opened():
            self.fail('hardlinked source yielded')

    def test_linked_source_parent_refuses_before_opening_target_file(self):
        original=self.root/'eng/pilot';moved=self.root/'outside-code'
        original.rename(moved)
        if os.name=='nt':
            result=subprocess.run(['cmd','/c','mklink','/J',str(original),str(moved)],capture_output=True,timeout=10)
            self.assertEqual(0,result.returncode)
        else:
            original.symlink_to(moved,target_is_directory=True)
        with self.assertRaises(REFUSALS), self.opened():
            self.fail('linked ancestor yielded')

    def test_same_bytes_replacement_is_prevented_or_refused_by_identity(self):
        source=self.root/self.names[0];replacement=self.root/'replacement'
        replacement.write_bytes(source.read_bytes())
        mutated=False
        try:
            with self.opened() as lease:
                try:
                    os.replace(replacement,source)
                except PermissionError:
                    self.assertEqual('nt',os.name)
                    lease.check()
                else:
                    mutated=True
                    with self.assertRaises(REFUSALS):
                        lease.check()
        except REFUSALS:
            self.assertTrue(mutated)

    def test_source_write_is_prevented_or_refused_before_reuse(self):
        source=self.root/self.names[0]
        mutated=False
        try:
            with self.opened() as lease:
                try:
                    source.write_bytes(b'mutated public code')
                except PermissionError:
                    self.assertEqual('nt',os.name)
                    lease.check()
                else:
                    mutated=True
                    with self.assertRaises(REFUSALS):
                        lease.check()
        except REFUSALS:
            self.assertTrue(mutated)
            self.assertNotEqual(self.plan['sourcePins'][self.names[0]]['sha256'],H(source.read_bytes()))

    def test_body_exception_releases_file_sharing_and_live_registration(self):
        with self.assertRaisesRegex(RuntimeError,'generated-body-failure'):
            with self.opened() as lease:
                raise RuntimeError('generated-body-failure')
        with self.assertRaises(REFUSALS):
            lease.report()
        for name in self.names:
            (self.root/name).write_bytes(b'write after closed lease')

    def test_distinct_ctime_views_are_each_bound_without_tolerance(self):
        source=self.root/self.names[0];original=Path.lstat;offset=[1000];changed=False
        class View:
            def __init__(self,value):self.value=value
            def __getattr__(self,name):return getattr(self.value,name)
            @property
            def st_ctime_ns(self):return self.value.st_ctime_ns+offset[0]
        def lstat(path,*args,**kwargs):
            value=original(path,*args,**kwargs)
            return View(value) if path==source else value
        try:
            with patch.object(Path,'lstat',lstat),self.opened() as lease:
                lease.check()
                offset[0]+=1;changed=True
                with self.assertRaises(REFUSALS):
                    lease.check()
        except REFUSALS:
            self.assertTrue(changed)


if __name__=='__main__':
    unittest.main()
