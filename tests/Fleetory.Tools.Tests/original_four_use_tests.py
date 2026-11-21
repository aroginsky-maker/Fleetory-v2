"""Distinct admission rehearsal: generated files, actual held parent, no originals/native."""
from dataclasses import replace
from pathlib import Path
import copy
import base64
import os
import sys
import threading
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'eng/pilot'))
from historical import original_four_use as policy
from historical import retained_service_peer as peer
import retained_service_use_tests as model

H,C=policy.H,policy.C


class OriginalFourTests(unittest.TestCase):
    def setUp(self):
        self.fixture=model.ServiceUseTests('runTest');self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        f=self.fixture
        parent_path=peer._parent_path()
        self.pinned=policy.legacy.identity.process.PinnedFile(parent_path,H(parent_path.read_bytes()),True)
        self.addCleanup(self.pinned.close)
        self.parent=policy.legacy.identity.HeldLocalPeer('parent',self.pinned,peer._parent_identity(self.pinned))
        self.addCleanup(self.parent.close)
        selected,_=policy.legacy.inputs.selection.decode_report(f.metadata['selection'],f.plan['pins']['selection'])
        exported=policy.legacy.inputs.expectations.source_plan({n:f.metadata[n] for n in ('manifest','checkpoint')},
                                                             {n:f.plan['pins'][n] for n in ('manifest','checkpoint')})
        artifacts=tuple((v.kind,v.path,v.bytes,v.sha256) for v in (*selected.artifacts,exported.artifact))
        self.expected=policy.ExpectedOriginalFour(str(f.root),artifacts,f.plan['revision'],f.plan['imageId'],
            f.plan['probeSha256'],f.plan['configurationSha256'],'7'*64,H(Path(policy.__file__).read_bytes()))
        self.plan=dict(schema=policy.SCHEMA,purpose=policy.PURPOSE,nonce=f.plan['nonce'],root=str(f.root),
            artifacts={k:dict(path=p,bytes=n,sha256=h) for k,p,n,h in artifacts},servicePlanSha256=f.digest,
            executionInventorySha256=self.expected.execution_inventory_sha256,
            consumerIdentitySha256=H(C(self.parent.snapshot()['identity'])))
        self.inventory={'live':True};self.freeze()

    def freeze(self):self.raw=C(self.plan);self.pin=H(self.raw)

    def use(self):
        f=self.fixture
        return policy.use(f.operator,f.repo,self.expected,self.parent,lambda:self.inventory['live'],
                          self.raw,self.pin,f.raw,f.digest,f.metadata,f.consumer)

    def no_raw(self):return patch.object(policy.legacy.inputs,'capture',side_effect=AssertionError('Raw capture reached'))

    def test_exact_generated_four_capture_and_distinct_attempt_before_io(self):
        original=policy.legacy.inputs.capture
        original_file=policy.legacy.inputs.files.inspect_file
        def checked(*args,**kwargs):
            path=self.fixture.operator/('original-four-use-'+self.plan['nonce']+'.json')
            self.assertTrue(path.is_file())
            attempt=policy._LIVE[value]['attempt'];attempt.check()
            self.assertTrue(attempt._sealed)
            self.assertEqual('ATTEMPT_CONSUMED',policy.packet.strict_json(attempt._bytes,8192)['status'])
            return original(*args,**kwargs)
        def checked_file(*args,**kwargs):
            attempt=policy._LIVE[value]['attempt'];attempt.check();self.assertTrue(attempt._sealed)
            return original_file(*args,**kwargs)
        with patch.object(policy.legacy.inputs,'capture',side_effect=checked) as captured, \
             patch.object(policy.legacy.inputs.files,'inspect_file',side_effect=checked_file) as opened:
            with self.use() as value:
                self.assertEqual('ready',value.report()['stage'])
                value.capture()
                for _,relative,_,_ in self.expected.artifacts:
                    target=self.fixture.root/relative
                    self.assertIn(self.fixture.root,target.parents);target.write_bytes(b'replaced after frozen capture')
                self.assertEqual(b'generated-result',value.dispatch())
                self.assertEqual(1,captured.call_count);self.assertEqual(1,len(self.fixture.calls))
                self.assertEqual(4,opened.call_count)
                self.assertEqual([entry[1] for entry in self.expected.artifacts],[call.args[2] for call in opened.call_args_list])
                received=policy.packet.strict_json(self.fixture.calls[0],policy.legacy.private.MAX_INPUT*2)
                self.assertEqual(policy.KINDS,set(received['packets']))
                expected_packets=dict(self.fixture.fixture.data,**{'audit-export':policy.legacy.inputs.expectations.archive.canonical(self.fixture.fixture.source.snapshot)})
                for kind,data in expected_packets.items():
                    self.assertEqual(data,base64.b64decode(received['packets'][kind],validate=True))
                    self.assertEqual(H(data),received['packetSha256'][kind])
                for name in ('executionAuthorized','existingDataConsentAuthenticated','nativeResultAuthenticated','phase7Complete'):
                    self.assertIs(value.report()[name],False)
                with self.assertRaises(ValueError):value.capture()
                with self.assertRaises(ValueError):value.dispatch()
        with self.assertRaises((ValueError,OSError)):
            with self.use():pass

    def test_wrong_purpose_refused_before_records_or_capture(self):
        self.plan['purpose']=policy.legacy.PURPOSE;self.freeze()
        with patch.object(policy.legacy.attempts,'_claim_record') as claim,self.no_raw() as raw:
            with self.assertRaises(ValueError):
                with self.use():pass
            claim.assert_not_called();raw.assert_not_called()

    def test_missing_or_extra_category_and_changed_artifact_refused_preopen(self):
        original=self.expected
        altered=list(original.artifacts);entry=altered[0];altered[0]=(entry[0],entry[1],entry[2],'a'*64)
        cases=(replace(original,artifacts=original.artifacts[:3]),replace(original,artifacts=original.artifacts+(('provider-raft','foreign.bin',1,'b'*64),)),replace(original,artifacts=tuple(altered)))
        for expected in cases:
            with self.subTest(count=len(expected.artifacts)),self.no_raw() as raw:
                self.expected=expected
                with self.assertRaises(ValueError):
                    with self.use():pass
                raw.assert_not_called()
        self.expected=original

    def test_foreign_root_runtime_bindings_and_consumer_identity_refused_preopen(self):
        for field,value in (('root',str(self.fixture.root/'foreign')),('executionInventorySha256','8'*64),('consumerIdentitySha256','9'*64),('servicePlanSha256','a'*64)):
            old=self.plan[field];self.plan[field]=value;self.freeze()
            with self.subTest(field=field),self.no_raw() as raw:
                with self.assertRaises(ValueError):
                    with self.use():pass
                raw.assert_not_called()
            self.plan[field]=old
        self.freeze()
        for field,value in (('revision','9'*40),('image_id','sha256:'+'9'*64),('probe_sha256','9'*64),('configuration_sha256','9'*64)):
            old=self.expected;self.expected=replace(old,**{field:value})
            with self.subTest(field=field),self.no_raw() as raw:
                with self.assertRaises(ValueError):
                    with self.use():pass
                raw.assert_not_called()
            self.expected=old

    def test_failed_inventory_capture_attempt_cannot_be_repaired_or_replayed(self):
        with self.use() as value,self.no_raw() as raw:
            self.inventory['live']=False
            with self.assertRaises(ValueError):value.capture()
            self.inventory['live']=True
            with self.assertRaises(ValueError):value.capture()
            with self.assertRaises(ValueError):value.dispatch()
            raw.assert_not_called()

    def test_original_integer_expiry_refuses_capture(self):
        with self.use() as value,self.no_raw() as raw:
            started=policy._LIVE[value]['mono']
            with patch.object(policy.time,'monotonic_ns',return_value=started+policy.legacy.LIFETIME_NS):
                with self.assertRaises(ValueError):value.capture()
            with self.assertRaises(ValueError):value.capture()
            raw.assert_not_called()

    def test_backwards_clock_refuses_and_consumes_capture_before_raw_io(self):
        with self.use() as value,self.no_raw() as raw:
            started=policy._LIVE[value]['mono']
            with patch.object(policy.time,'monotonic_ns',return_value=started-1):
                with self.assertRaises(ValueError):value.capture()
            with self.assertRaises(ValueError):value.capture()
            raw.assert_not_called()

    def test_observation_report_cannot_substitute_actual_held_parent(self):
        original=self.parent;self.parent=original.snapshot()
        with patch.object(policy.legacy.attempts,'_claim_record') as claim,self.no_raw() as raw:
            with self.assertRaises(ValueError):
                with self.use():pass
            claim.assert_not_called();raw.assert_not_called()
        self.parent=original

    def test_copied_fabricated_and_cross_thread_contexts_do_not_open_inputs(self):
        with self.use() as value,self.no_raw() as raw:
            for other in (copy.copy(value),policy.LiveOriginalFour()):
                with self.assertRaises(ValueError):other.capture()
            errors=[]
            def consume():
                try:value.capture()
                except ValueError:errors.append('refused')
            thread=threading.Thread(target=consume);thread.start();thread.join(5)
            self.assertFalse(thread.is_alive());self.assertEqual(['refused'],errors);raw.assert_not_called()
        with self.assertRaises(ValueError):value.capture()

    def test_parent_loss_refuses_and_burns_attempt_before_raw_io(self):
        with self.use() as value,self.no_raw() as raw:
            self.parent.close()
            with self.assertRaises(ValueError):value.capture()
            with self.assertRaises(ValueError):value.capture()
            raw.assert_not_called()


if __name__=='__main__':unittest.main()
