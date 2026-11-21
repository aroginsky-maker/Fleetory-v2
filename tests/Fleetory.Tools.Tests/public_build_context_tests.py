import copy
import datetime as dt
import io
import tarfile
import unittest

from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'eng/pilot'))
import public_build_context as policy


def pin(raw):
    return {'bytes':len(raw), 'sha256':policy.digest(raw)}


class ContextTests(unittest.TestCase):
    def setUp(self):
        self.now=dt.datetime(2026,11,21,tzinfo=dt.timezone.utc)
        self.sources={n:('generated '+n).encode() for n in (*policy.ROOTS,policy.PROJECT)}
        self.packages={'generated.1.0.nupkg':b'generated unsigned package model'}
        self.crls={'12345678.abcdef01.crl':b'generated CRL model, not a signature proof'}
        self.sp={n:pin(v) for n,v in self.sources.items()}
        self.pp={n:pin(v) for n,v in self.packages.items()}
        self.cp={n:dict(pin(v),thisUpdate=self.now-dt.timedelta(days=1),nextUpdate=self.now+dt.timedelta(days=1)) for n,v in self.crls.items()}
        self.args=[self.sources,self.sp,self.packages,self.pp,self.crls,self.cp,self.now]

    def test_canonical_public_context_is_deterministic_and_has_no_execution_grant(self):
        raw=policy.prepare(*self.args)
        self.assertEqual(raw,policy.prepare(*self.args))
        result=policy.validate(raw,*self.args)
        self.assertFalse(result['executionAuthorized'])
        self.assertFalse(result['signatureVerificationPerformed'])
        with tarfile.open(fileobj=io.BytesIO(raw)) as t:
            self.assertEqual(policy.SCRIPT,t.extractfile('control/build.sh').read())
            self.assertNotIn(b'RUN ',t.extractfile('Dockerfile').read())
            self.assertEqual(policy.trust.render(),t.extractfile('control/NuGet.Config').read())

    def test_reviewed_trust_bytes_are_identical_across_platforms(self):
        self.assertEqual('d990096e64e0c5ce6e1f146469fcd81791ac10e0aacc4ef5c50d896caf8b0a42',
                         policy.digest(policy.trust.render()))
        with self.assertRaises(ValueError):
            policy.trust.validate(policy.trust.render().replace(b'allowUntrustedRoot="false"', b'allowUntrustedRoot="true"'))

    def test_unbounded_or_ambiguous_input_sets_are_refused(self):
        changes = []
        changed = copy.deepcopy(self.args);changed[1][policy.PROJECT]['bytes'] = True;changes.append(changed)
        changed = copy.deepcopy(self.args);changed[1][policy.PROJECT]['extra'] = 1;changes.append(changed)
        changed = copy.deepcopy(self.args);changed[2] = {};changed[3] = {};changes.append(changed)
        changed = copy.deepcopy(self.args);changed[4] = {};changed[5] = {};changes.append(changed)
        changed = copy.deepcopy(self.args);changed[0]['src/../escape.cs'] = b'a';changed[1]['src/../escape.cs'] = pin(b'a');changes.append(changed)
        changed = copy.deepcopy(self.args);changed[2]['../foreign.nupkg'] = b'a';changed[3]['../foreign.nupkg'] = pin(b'a');changes.append(changed)
        changed = copy.deepcopy(self.args);changed[0][policy.PROJECT] = b'x' * 1048577;changed[1][policy.PROJECT] = pin(changed[0][policy.PROJECT]);changes.append(changed)
        changed = copy.deepcopy(self.args);changed[2] = {f'p{i}.nupkg':b'a' for i in range(65)};changed[3] = {n:pin(v) for n,v in changed[2].items()};changes.append(changed)
        for index, changed in enumerate(changes):
            with self.subTest(case=index):
                with self.assertRaises(ValueError):policy.prepare(*changed)

    def test_changed_controls_headers_tail_and_cross_pin_are_refused(self):
        raw=policy.prepare(*self.args)
        mutations=[raw+b'\0',raw[:-512],raw.replace(b'FROM ',b'RUN  ',1),
                   raw.replace(b'allowUntrustedRoot="false"',b'allowUntrustedRoot="true" ',1),
                   raw.replace(b'signatureValidationMode',b'signatureValidationMods',1),
                   raw.replace(b'--disable-parallel',b'--disable-paralleL',1)]
        for changed in mutations:
            with self.subTest(bytes=len(changed)):
                with self.assertRaises(ValueError):policy.validate(changed,*self.args)
        args=copy.deepcopy(self.args);args[0][policy.PROJECT]+=b'changed'
        with self.assertRaises(ValueError):policy.prepare(*args)

    def test_expiry_future_naive_timestamp_and_case_alias_are_refused(self):
        for field,value in [('nextUpdate',self.now+dt.timedelta(seconds=420)),
                            ('nextUpdate',self.now-dt.timedelta(seconds=1)),
                            ('thisUpdate',self.now+dt.timedelta(seconds=1)),
                            ('thisUpdate',self.now.replace(tzinfo=None))]:
            args=copy.deepcopy(self.args);args[5]['12345678.abcdef01.crl'][field]=value
            with self.subTest(field=field,value=str(value)):
                with self.assertRaises(ValueError):policy.prepare(*args)
        args=copy.deepcopy(self.args);args[0]['src/A.cs']=b'a';args[0]['src/a.cs']=b'a'
        args[1].update({n:pin(b'a') for n in ('src/A.cs','src/a.cs')})
        with self.assertRaises(ValueError):policy.prepare(*args)


if __name__=='__main__':unittest.main()
