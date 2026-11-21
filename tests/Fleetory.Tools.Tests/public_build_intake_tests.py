from pathlib import Path
import copy
import datetime as dt
import os
import sys
import tempfile
import threading
import types
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'eng/pilot'))
from public_build import context as policy
from public_build import intake


def pin(data):return {'bytes':len(data),'sha256':policy.digest(data)}


class IntakeTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='fleetory-public-intake-model-')
        self.addCleanup(self.temp.cleanup)
        self.roots=tuple(Path(self.temp.name)/n for n in ('source','packages','crls'))
        for root in self.roots:root.mkdir()
        self.sources={n:('generated '+n).encode() for n in (*policy.ROOTS,policy.PROJECT)}
        self.sources['global.json']=intake.SDK_BYTES
        for name,data in self.sources.items():
            if name=='global.json':continue
            p=self.roots[0]/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data)
        self.sp={n:pin(v) for n,v in self.sources.items()}
        self.package=b'generated unsigned package model'
        p=self.roots[1]/'p/1/p.1.nupkg';p.parent.mkdir(parents=True);p.write_bytes(self.package)
        self.pp={'p.1.nupkg':dict(pin(self.package),path='p/1/p.1.nupkg')}
        self.crl=b'generated CRL model, no cryptographic signature proof'
        (self.roots[2]/'12345678.abcdef01.crl').write_bytes(self.crl)
        now=dt.datetime.now(dt.timezone.utc)
        self.cp={'12345678.abcdef01.crl':dict(pin(self.crl),thisUpdate=now-dt.timedelta(days=1),nextUpdate=now+dt.timedelta(days=1))}

    def capture(self):return intake.capture(self.roots,self.sp,self.pp,self.cp)

    def test_generated_sdk_bytes_match_the_pinned_native_context(self):
        self.assertEqual(55,len(intake.SDK_BYTES))
        self.assertEqual('d1bb820bf074027be921b263729d1fba343d34328f0c4b7484d10162287c059e',policy.digest(intake.SDK_BYTES))

    def test_actual_frozen_capture_remains_original_after_paths_and_metadata_change(self):
        value=self.capture()
        self.assertFalse((self.roots[0]/'global.json').exists())
        for p in (self.roots[0]/policy.PROJECT,self.roots[1]/'p/1/p.1.nupkg',self.roots[2]/'12345678.abcdef01.crl'):
            p.write_bytes(b'replaced after capture')
        self.sp[policy.PROJECT]['sha256']='0'*64
        raw=value.take()
        expected=policy.prepare(self.sources,{n:pin(v) for n,v in self.sources.items()},
            {'p.1.nupkg':self.package},{'p.1.nupkg':pin(self.package)},
            {'12345678.abcdef01.crl':self.crl},self.cp,dt.datetime.now(dt.timezone.utc))
        self.assertEqual(expected,raw)
        value.check_before_sdk()
        self.assertTrue(value.report()['sdkAdmitted'])
        with self.assertRaises(ValueError):value.take()
        with self.assertRaises(ValueError):value.check_before_sdk()
        self.assertFalse(value.report()['nativeExecutionAuthorized'])

    def test_unsupported_source_name_is_refused_before_any_directory_open(self):
        self.sp['eng/pilot/public_build/__init__.py']=pin(b'generated marker')
        with patch.object(intake.control,'DirectoryLease') as opened:
            with self.assertRaises((ValueError,intake.files.archive.ArchiveError)):self.capture()
            opened.assert_not_called()

    def test_bad_metadata_is_refused_before_any_directory_open(self):
        self.pp['p.1.nupkg']['path']='../foreign/p.1.nupkg'
        with patch.object(intake.control,'DirectoryLease') as opened:
            with self.assertRaises((ValueError,intake.files.archive.ArchiveError)):self.capture()
            opened.assert_not_called()

    def test_source_replacement_or_package_hardlink_is_refused(self):
        p=self.roots[0]/policy.PROJECT;p.write_bytes(b'changed')
        with self.assertRaises((ValueError,intake.files.archive.ArchiveError)):self.capture()
        p.write_bytes(self.sources[policy.PROJECT])
        os.link(self.roots[1]/'p/1/p.1.nupkg',Path(self.temp.name)/'package-alias')
        with self.assertRaises((ValueError,intake.files.archive.ArchiveError)):self.capture()

    def test_copied_fabricated_and_cross_thread_capsules_are_refused(self):
        value=self.capture()
        for other in (copy.copy(value),intake.CapturedPublicInputs()):
            with self.assertRaises(ValueError):other.take()
        errors=[]
        def read():
            try:value.report()
            except ValueError:errors.append('refused')
        thread=threading.Thread(target=read);thread.start();thread.join(5)
        self.assertFalse(thread.is_alive());self.assertEqual(['refused'],errors)

    def test_original_expiry_and_sdk_budget_are_not_renewed(self):
        value=self.capture();started=intake._LIVE[value]['startedNs'];value.take()
        with patch.object(intake.time,'monotonic_ns',return_value=started+115_000_000_000):
            with self.assertRaises(ValueError):value.check_before_sdk()
        self.assertTrue(value.report()['sdkAttempted']);self.assertFalse(value.report()['sdkAdmitted'])
        with self.assertRaises(ValueError):value.check_before_sdk()
        with patch.object(intake.time,'monotonic_ns',return_value=started+420_000_000_000):
            with self.assertRaises(ValueError):value.report()

    def test_integer_nanosecond_deadline_boundaries_and_backwards_clock(self):
        for boundary,action in ((420_000_000_000,'report'),(115_000_000_000,'check_before_sdk')):
            for delta in (-1,0,1):
                with self.subTest(boundary=boundary,delta=delta):
                    value=self.capture();value.take();started=intake._LIVE[value]['startedNs']
                    self.assertIs(type(started),int)
                    with patch.object(intake.time,'monotonic_ns',return_value=started+boundary+delta):
                        if delta<0:getattr(value,action)()
                        else:
                            with self.assertRaises(ValueError):getattr(value,action)()
                    self.assertEqual(started,intake._LIVE[value]['startedNs'])
        value=self.capture();started=intake._LIVE[value]['startedNs']
        with patch.object(intake.time,'monotonic_ns',return_value=started-1):
            with self.assertRaises(ValueError):value.report()

    def test_crl_freshness_is_rechecked_immediately_before_sdk(self):
        value=self.capture();value.take();limit=self.cp['12345678.abcdef01.crl']['nextUpdate']
        class Clock:
            @staticmethod
            def now(_zone):return limit-dt.timedelta(seconds=305)
        clock=types.SimpleNamespace(datetime=Clock,timezone=dt.timezone,timedelta=dt.timedelta)
        with patch.object(intake,'dt',clock):
            with self.assertRaises(ValueError):value.check_before_sdk()
        with self.assertRaises(ValueError):value.check_before_sdk()
        self.assertFalse(value.report()['sdkAdmitted'])


if __name__=='__main__':unittest.main()
