"""Contracts for the fixed public publisher; generated files only."""
import base64
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
import uuid
from unittest.mock import patch

from audit_probe_image_tests import public_files,measure
from historical_audit_restore_tests import fixture
from native_audit_preparation import claim_plan
import audit_native_publication as policy

B=lambda b:base64.b64encode(b).decode('ascii')
C=policy.prep.canonical
H=policy.packet.digest


class NativePublicationContracts(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='fleetory-native-publication-contract-')
        self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name).resolve()
        self.repo=self.root/'repository';self.repo.mkdir();(self.repo/'artifacts').mkdir()
        source=self.root/'public';public_files(source);self.manifest=C(measure(source))
        measured,entries=policy.ns.bundle.manifest(self.manifest,H(self.manifest))
        plan,_=fixture();plan.update(nonce=str(uuid.uuid4()),probeBundleSha256=measured['sha256'],
            probeSha256=entries['ServerBackendProbe.dll']['sha256'])
        self.plan=plan;self.raw,claimed=claim_plan(self.root,plan,Path(sys.executable),Path(sys.executable))
        self.session=self.enterContext(claimed)
        self.value=policy._NativePublicationPumps.make_header(self.raw,self.session.report(),self.session,
            {n:'e'*64 for n in policy.SOURCES},'a'*64,dotnet_sha256='d'*64,manifest=self.manifest)
        self.pin=H(self.raw)

    def header(self,**updates):
        return C({**self.value,**updates})

    def test_header_matches_plan_manifest_and_selected_intent(self):
        value,info,intent,manifest=policy.inputs(self.header(),self.pin)
        self.assertEqual(info['headerSha256'],H(self.header()))
        self.assertEqual(manifest,self.manifest);self.assertEqual(value['sdkVersion'],'10.0.402')
        self.assertEqual(policy.ns.admit(intent,H(intent))['manifestSha256'],H(manifest))

    def test_header_schema_and_field_set_closed(self):
        for updates in ({'schema':policy.prep.SCHEMA},{'root':'/host'},{'command':'restore'},{'archiveBase64':'CANARY'}):
            with self.subTest(updates=updates),self.assertRaises(ValueError):policy.header(self.header(**updates),self.pin)

    def test_sdk_and_tool_pin_closed(self):
        for updates in ({'sdkVersion':'10.0.401'},{'dotnetSha256':True},{'gitSha256':'A'*64}):
            with self.subTest(updates=updates),self.assertRaises(ValueError):policy.header(self.header(**updates),self.pin)

    def test_manifest_pin_and_bound_enforced(self):
        for raw in (self.manifest+b' ',b'x'*(policy.MAX_MANIFEST+1)):
            with self.assertRaises(ValueError):policy.header(self.header(manifestBase64=B(raw)),self.pin)

    def test_manifest_bundle_and_primary_assembly_must_match_plan(self):
        for key in ('probeBundleSha256','probeSha256'):
            plan={**self.plan,key:'f'*64};raw=C(plan)
            with self.subTest(key=key),self.assertRaises(ValueError):
                policy.header(self.header(planBase64=B(raw)),H(raw))

    def test_namespace_nonce_and_control_identity_closed(self):
        value,_,intent,_=policy.inputs(self.header(),self.pin);declared=json.loads(intent)
        for key,bad in (('nonce',str(uuid.uuid4())),('controlSha256','0'*64),('path','/host')):
            with self.subTest(key=key),self.assertRaises(ValueError):
                policy.header(self.header(namespaceBase64=B(C({**declared,key:bad}))),self.pin)

    def test_delegation_only_current_direct_parent(self):
        intent=policy.inputs(self.header(),self.pin)[2]
        for pid in (True,0,os.getppid()+1,os.getpid()):
            with self.subTest(pid=pid),self.assertRaises(ValueError):
                policy.ns.OwnedPublication(self.repo,intent,H(intent),native_owner_pid=pid)
        self.assertEqual(list((self.repo/'artifacts').iterdir()),[])

    def test_delegated_marker_and_ready_identify_native_parent(self):
        intent=policy.inputs(self.header(),self.pin)[2]
        with policy.ns.OwnedPublication(self.repo,intent,H(intent),native_owner_pid=os.getppid()) as owned:
            self.assertEqual(owned.ready()['pid'],os.getppid())
            marker=json.loads((owned.directory.path/policy.ns.MARKER).read_bytes())
            self.assertEqual(marker['ownerPid'],os.getppid())
            with policy._RecordedPublication(self.repo,intent,owned.ready(),os.getppid()) as reopened:
                self.assertEqual(owned.ready(),reopened.ready())

    def test_recorded_namespace_rejects_replaced_ready_owner(self):
        intent=policy.inputs(self.header(),self.pin)[2]
        with policy.ns.OwnedPublication(self.repo,intent,H(intent),native_owner_pid=os.getppid()) as owned:
            for key,bad in (('pid',os.getpid()),('ownerSha256','0'*64),('outputDirectorySha256','0'*64),('privateInputsAccepted',0)):
                with self.subTest(key=key),self.assertRaises(ValueError):
                    policy._RecordedPublication(self.repo,intent,{**owned.ready(),key:bad},os.getppid())

    def test_authorization_closed_to_three_fixed_decisions(self):
        info=policy.header(self.header(),self.pin);ready={'pinned':'public'}
        self.assertIsNone(policy.authorize(info,'a'*64,'reserve')['namespaceReadySha256'])
        for args in (('restore',None,None),('publish',None,None),('close',ready,None),('reserve',ready,None),('publish',ready,'f'*64)):
            with self.subTest(args=args),self.assertRaises(ValueError):
                policy.authorize(info,'a'*64,*args)

    def test_reopen_never_adopts_wrong_marker(self):
        intent=policy.inputs(self.header(),self.pin)[2]
        with policy.ns.OwnedPublication(self.repo,intent,H(intent),native_owner_pid=os.getppid()) as owned:
            bad={**owned.ready(),'namespaceDirectorySha256':'f'*64}
            with self.assertRaises(ValueError):policy._RecordedPublication(self.repo,intent,bad,os.getppid())
            self.assertTrue((owned.directory.path/policy.ns.MARKER).is_file())

    def test_fixed_source_inventory_preserves_old_profiles_and_limits(self):
        import audit_native_probe_create as creator
        self.assertEqual(len(policy.SOURCES),36);self.assertEqual(len(set(policy.SOURCES)),36)
        self.assertEqual((len(policy.prep.SOURCES),len(creator.SOURCES)),(32,46))
        self.assertNotIn('eng/pilot/audit_native_publication.py',creator.SOURCES)
        source=(Path(policy.__file__).parent/'HistoricalPublicPublication.ps1').read_text()
        self.assertIn("'--no-restore','--disable-build-servers','-p:UseAppHost=false'",source)
        self.assertIn("$null 20",source)
        self.assertNotIn('Start-Process',source);self.assertNotIn('docker',source.lower())


if __name__=='__main__':unittest.main()
