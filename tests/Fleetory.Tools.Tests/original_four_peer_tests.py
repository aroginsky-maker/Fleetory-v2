"""Generated original binding and fixed source entry; no native/original material."""
import base64
import copy
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

import original_four_use_tests as models
import retained_source_bootstrap_tests as bootstrap
from historical import original_four_peer as entry

C,H=entry.C,entry.H


class OriginalPeerTests(unittest.TestCase):
    def setUp(self):
        self.model=models.OriginalFourTests('runTest');self.model.setUp();self.addCleanup(self.model.doCleanups)
        m=self.model;f=m.fixture;v=m.expected
        self.wanted=dict(root=v.root,artifacts=entry.policy._expected(v),revision=v.revision,imageId=v.image_id,
            probeSha256=v.probe_sha256,configurationSha256=v.configuration_sha256,
            executionInventorySha256=v.execution_inventory_sha256,policySha256=v.policy_sha256)
        self.header=dict(plan=base64.b64encode(f.raw).decode('ascii'),planSha256=f.digest,
                         parent=m.parent.snapshot()['identity'],codePlanSha256='7'*64)
        self.raw=C(self.header)
        self.legacy=dict(header=base64.b64encode(self.raw).decode('ascii'),sha256=H(self.raw),
                         nonce=f.plan['nonce'],parent=self.header['parent'])

    def prepared(self,wanted=None):
        with patch.object(entry.peer,'prepare',return_value=self.legacy),patch.object(entry.Path,'cwd',return_value=self.model.fixture.root):
            return entry.prepare(C(dict(request={},expected=self.wanted if wanted is None else wanted)))

    def run_binding(self,value,callback=None,binding_pin=None,header_pin=None):
        frozen=base64.b64decode(value['binding'],validate=True)
        with patch.object(entry.peer,'_receive',side_effect=[frozen,self.raw]),patch.object(entry.peer,'_serve_header',side_effect=callback) as serve:
            entry.run(value['sha256'] if header_pin is None else header_pin,
                      value['bindingSha256'] if binding_pin is None else binding_pin)
            return serve

    def factory_callback(self,parent=None,code_pin='7'*64,consume=False):
        def callback(raw,builder):
            self.assertEqual(self.raw,raw)
            m=self.model;f=m.fixture;checks=[]
            factory,pin=builder(m.parent if parent is None else parent,f.raw,f.digest,f.metadata,
                                lambda:checks.append('source'),code_pin,f.operator)
            if consume:self.assertEqual(self.prepared()['originalPlanSha256'],pin)
            with factory(f.consumer) as context:
                self.assertFalse(context.report()['existingDataConsentAuthenticated'])
                if consume:context.capture();self.assertEqual(b'generated-result',context.dispatch())
            self.assertTrue(checks)
        return callback

    def test_separate_pinned_binding_reaches_actual_generated_use_factory(self):
        value=self.prepared();self.run_binding(value,self.factory_callback(consume=True))
        self.assertEqual(1,len(self.model.fixture.calls))
        packet=entry.packet.strict_json(self.model.fixture.calls[0],entry.policy.legacy.private.MAX_INPUT*2)
        self.assertEqual(entry.policy.KINDS,set(packet['packets']))

    def test_modified_frame_pins_refused_before_shared_entry(self):
        value=self.prepared()
        for pins in (dict(binding_pin='a'*64),dict(header_pin='a'*64)):
            with self.subTest(pins=pins),patch.object(entry.policy.legacy.attempts,'_claim_record') as claim:
                with self.assertRaises(ValueError):self.run_binding(value,**pins)
                claim.assert_not_called()

    def test_extra_permission_or_category_and_wrong_policy_refused(self):
        cases=[]
        for key,value in (('permissionGranted',True),('factory','legacy')):
            v=copy.deepcopy(self.wanted);v[key]=value;cases.append(v)
        v=copy.deepcopy(self.wanted);v['artifacts']['provider-raft']=v['artifacts']['audit-immudb'];cases.append(v)
        v=copy.deepcopy(self.wanted);v['policySha256']='a'*64;cases.append(v)
        for v in cases:
            with self.subTest(keys=list(v)),patch.object(entry.peer,'prepare') as prepare:
                with self.assertRaises(ValueError):self.prepared(v)
                prepare.assert_not_called()

    def test_foreign_root_or_runtime_bindings_refused_in_preparation(self):
        for key,value in (('root',str(self.model.fixture.root/'foreign')),('revision','a'*40),('imageId','sha256:'+'a'*64),('probeSha256','a'*64),('configurationSha256','a'*64)):
            v=copy.deepcopy(self.wanted);v[key]=value
            with self.subTest(key=key),patch.object(entry.policy.legacy.attempts,'_claim_record') as claim:
                with self.assertRaises(ValueError):self.prepared(v)
                claim.assert_not_called()

    def test_metadata_artifact_mismatch_refused_before_attempt_or_raw(self):
        v=copy.deepcopy(self.wanted);v['artifacts']['audit-immudb']['sha256']='a'*64
        value=self.prepared(v)
        with patch.object(entry.policy.legacy.attempts,'_claim_record') as claim,self.model.no_raw() as raw:
            with self.assertRaises(ValueError):self.run_binding(value,self.factory_callback())
            claim.assert_not_called();raw.assert_not_called()

    def test_wrong_code_inventory_or_report_parent_refused_before_attempt(self):
        value=self.prepared()
        for options in (dict(code_pin='a'*64),dict(parent=self.model.parent.snapshot())):
            with self.subTest(options=options.keys()),patch.object(entry.policy.legacy.attempts,'_claim_record') as claim:
                with self.assertRaises(ValueError):self.run_binding(value,self.factory_callback(**options))
                claim.assert_not_called()


class OriginalBootstrapTests(unittest.TestCase):
    def setUp(self):
        self.model=bootstrap.SourceBootstrapTests('runTest');self.model.setUp();self.addCleanup(self.model.doCleanups)
        self.wrapper=self.model.wrapper.with_name('original_four_source_bootstrap.py')
        self.wrapper.write_bytes((bootstrap.PILOT/'historical/original_four_source_bootstrap.py').read_bytes())
        (self.model.pilot/'historical/original_four_peer.py').write_text('from public_cache_probe import VALUE\nprint(VALUE)\n')

    def invoke(self,*args,isolated=True):
        return subprocess.run([sys.executable,*(['-I','-S','-B'] if isolated else ['-B']),str(self.wrapper),*args],
                              cwd=self.model.root,capture_output=True,timeout=15)

    def test_new_fixed_entry_uses_source_despite_unchecked_cache(self):
        self.model.cached(kind='UNCHECKED_HASH');v=self.invoke()
        self.assertEqual(0,v.returncode,v.stderr);self.assertEqual(b'sourcex',v.stdout.strip())

    def test_isolation_required_and_legacy_five_entries_stay_closed(self):
        self.model.cached();self.assertNotEqual(0,self.invoke(isolated=False).returncode)
        v=self.model.run_entry('original-peer');self.assertNotEqual(0,v.returncode)


if __name__=='__main__':
    from held_parent_test_runner import main
    main()
