"""Fixed exchange with real generated admission/parent; private packets stay in memory."""
from pathlib import Path
import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'eng/pilot'))
from historical import retained_private_session as session
import original_four_use_tests as models

C,H=session.C,session.H


class SessionTests(unittest.TestCase):
    def setUp(self):
        self.model=models.OriginalFourTests('runTest');self.model.setUp();self.addCleanup(self.model.doCleanups)
        self.sent=[];self.result=b'generated native result';self.nonce=self.model.plan['nonce']

    def run_session(self,steps,legacy=False):
        owner=self
        class Reader:
            def next(self,check):
                check()
                if not steps:raise ValueError('Unexpected input read')
                value=steps.pop(0)
                return value() if callable(value) else value
        def factory(consumer):
            f=owner.model.fixture
            if legacy:return models.policy.legacy.use(f.operator,f.root,f.repo,f.raw,f.digest,f.metadata,consumer)
            return models.policy.use(f.operator,f.repo,owner.model.expected,owner.model.parent,lambda:True,
                owner.model.raw,owner.model.pin,f.raw,f.digest,f.metadata,consumer)
        return session.serve(Reader(),self.sent.append,lambda:None,factory,self.model.parent,self.nonce,
                             '1'*64,'2'*64,'3'*64,430,'normal')

    def steps(self):
        return [C(dict(kind='capture',nonce=self.nonce)),
                lambda:C(dict(kind='status',nonce=self.nonce,sequence=1,payloadSha256=H(self.sent[2]))),
                C(dict(kind='result',nonce=self.nonce,resultSha256=H(self.result))),self.result,
                C(dict(kind='close',nonce=self.nonce))]

    def assert_exchange(self):
        self.assertEqual(6,len(self.sent))
        bound,envelope,payload,live,receipt,closed=self.sent
        values=[session.packet.strict_json(v,262144) for v in (bound,envelope,live,receipt,closed)]
        self.assertEqual(['bound','payload','live','receipt','closed'],[v['kind'] for v in values])
        self.assertEqual([8,6,4,11,3],list(map(len,values)))
        self.assertEqual(os.getpid(),values[0]['owner']['pid'])
        self.assertEqual(self.model.parent.snapshot()['identity'],values[0]['consumer'])
        self.assertEqual(H(payload),values[1]['payloadSha256'])
        self.assertEqual(1,values[3]['statusChecks']);self.assertFalse(values[3]['executionAuthorized'])
        self.assertEqual(H(self.result),values[3]['resultSha256'])
        captured=session.packet.strict_json(payload,models.policy.legacy.private.MAX_INPUT*2)
        self.assertEqual(models.policy.KINDS,set(captured['packets']))

    def test_distinct_purpose_uses_fixed_private_exchange(self):
        self.run_session(self.steps());self.assert_exchange()

    def test_legacy_purpose_keeps_identical_exchange(self):
        self.run_session(self.steps(),legacy=True);self.assert_exchange()

    def test_foreign_nonce_refused_before_any_raw_capture(self):
        steps=self.steps();steps[0]=C(dict(kind='capture',nonce='00000000-0000-4000-8000-000000000099'))
        with patch.object(models.policy.legacy.inputs,'capture',side_effect=AssertionError('Raw input reached')) as raw:
            with self.assertRaises(ValueError):self.run_session(steps)
            raw.assert_not_called()
        self.assertEqual(1,len(self.sent))

    def test_wire_cannot_select_factory_before_capture(self):
        steps=self.steps();steps[0]=C(dict(kind='capture',nonce=self.nonce,factory='original-four'))
        with patch.object(models.policy.legacy.inputs,'capture',side_effect=AssertionError('Raw input reached')) as raw:
            with self.assertRaises(ValueError):self.run_session(steps)
            raw.assert_not_called()
        self.assertEqual(1,len(self.sent))

    def test_replayed_status_refused_without_completion_receipt(self):
        steps=self.steps();steps.insert(2,lambda:C(dict(kind='status',nonce=self.nonce,sequence=1,payloadSha256=H(self.sent[2]))))
        with self.assertRaises(ValueError):self.run_session(steps)
        self.assertEqual(4,len(self.sent))

    def test_result_hash_mismatch_refused_without_completion_receipt(self):
        steps=self.steps();steps[3]=b'changed generated result'
        with self.assertRaises(ValueError):self.run_session(steps)
        self.assertEqual(4,len(self.sent))


if __name__=='__main__':unittest.main()
