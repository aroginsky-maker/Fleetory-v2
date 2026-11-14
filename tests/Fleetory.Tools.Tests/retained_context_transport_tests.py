"""Generated parent-reference/codec/consumption contracts; no native compiler or Docker."""
from contextlib import ExitStack
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import audit_probe_image_tests as vectors
from historical_audit_restore_tests import fixture as native_plan
from native_audit_preparation import active_sdk_input
import audit_retained_context_transport as policy

C,H=policy.C,policy.H
ROOT=Path(__file__).resolve().parents[2]
REFUSALS=(OSError,ValueError,policy.guard.attempts.files.archive.ArchiveError)


class RetainedContextContracts(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.held=ExitStack();self.addCleanup(self.held.close)
        self.held.enter_context(active_sdk_input(ROOT))
        self.root=Path(self.temp.name).resolve();self.public=self.root/'public';vectors.public_files(self.public)
        self.manifest=C(vectors.measure(self.public))
        self.reference=self.held.enter_context(policy.bundle.HeldProbeBundle(self.public,self.manifest,H(self.manifest)))
        self.operator=self.root/'operator';self.operator.mkdir(mode=0o700)
        self.opened=time.time_ns()
        control=vectors.control_plan('12345678-1234-4123-8123-123456789abc')
        control['probeSha256']=self.reference.entries['ServerBackendProbe.dll']['sha256']
        self.control=self.held.enter_context(policy.process.control.claim(self.operator,C(control),H(C(control))))
        self.plan,_=native_plan();self.plan.update(nonce=control['nonce'],revision=control['revision'],codeSha256=control['codeSha256'],
            probeSha256=control['probeSha256'],probeBundleSha256=self.reference.value['sha256'])
        self.bases=copy.deepcopy(vectors.BASE_VALUES)
        self.intent=json.loads(policy.probe.prepare(self.control,self.reference,self.bases))
        self.context=self.reference.context(policy.probe.definition(self.intent))
        self.identity=dict(pid=42,birthKind='linux-proc-start-ticks',birthToken='100',executableSha256='a'*64)
        self.header=dict(schema='fleetory.retained-context-header.v1',parent=self.identity,controller=dict(self.identity,pid=43),
            runtimes={name:'a'*64 for name in ('python','powershell','git','dotnet')},sourcePins={name:'b'*64 for name in policy.SOURCES},
            nativePlanBase64=policy.encode(C(self.plan)),nativePlanSha256=H(C(self.plan)),manifestBase64=policy.encode(self.manifest),
            manifestSha256=H(self.manifest),bases=self.bases)
        now=time.time_ns()
        self.offer=dict(schema=policy.SCHEMA,headerSha256=H(C(self.header)),controller=self.header['controller'],nonce=self.plan['nonce'],
            reservationSha256=self.intent['controlSha256'],imageIntentBase64=policy.encode(C(self.intent)),contextBytes=len(self.context),
            contextSha256=H(self.context),publicationDescriptorsHeld=len(self.reference.pins),heldDescriptorsSha256='c'*64,
            publicationBindingSha256='d'*64,nativeOwnerExited=True,nativeOwnedMembersAbsent=True,
            retainedOpenedNs=now,retainedExpiresNs=now+policy.publication.WINDOW_NS)

    def admit(self,**changes):
        args=dict(raw=C(self.offer),context=self.context,header=C(self.header),reference=self.reference,opened=self.opened,now=time.time_ns())
        args.update(changes);return policy.admit_offer(**args)

    def test_exact_context_is_checked_against_independent_held_bytes(self):self.assertEqual(self.admit(),self.offer)

    def test_frozen_buffers_return_fresh_metadata(self):
        raw,context,header=(bytearray(data) for data in (C(self.offer),self.context,C(self.header)))
        result=self.admit(raw=raw,context=context,header=header);raw[:]=b'x';context[:]=b'y';header[:]=b'z'
        self.assertEqual(result,self.offer)

    def test_each_offer_field_has_a_rejection_mutation(self):
        for key in self.offer:
            changed=dict(self.offer);changed[key]=None
            with self.subTest(key=key),self.assertRaises(REFUSALS):self.admit(raw=C(changed))

    def test_no_wire_image_or_container_id_is_accepted(self):
        for key in ('imageId','containerId','command','path','cleanupAuthorized'):
            with self.assertRaises(REFUSALS):self.admit(raw=C(dict(self.offer,**{key:'foreign'})))

    def test_context_size_hash_and_bytes_cannot_be_forged_together(self):
        changed=bytearray(self.context);changed[1024]^=1
        offer=dict(self.offer,contextSha256=H(changed),contextBytes=len(changed))
        with self.assertRaises(REFUSALS):self.admit(raw=C(offer),context=bytes(changed))

    def test_truncated_extended_and_unknown_context_types_refused(self):
        for changed in (self.context[:-1],self.context+b'x',b'',None,'text'):
            with self.assertRaises(REFUSALS):self.admit(context=changed)

    def test_all_public_image_intent_fields_are_checked(self):
        for key in self.intent:
            intent=dict(self.intent);intent[key]=None
            changed=dict(self.offer,imageIntentBase64=policy.encode(C(intent)))
            with self.subTest(key=key),self.assertRaises(REFUSALS):self.admit(raw=C(changed))

    def test_arbitrary_dockerfile_or_runtime_tuple_cannot_enter_intent(self):
        for key in ('Dockerfile','command','entrypoint','mounts','ports','imageId'):
            changed=dict(self.offer,imageIntentBase64=policy.encode(C(dict(self.intent,**{key:'foreign'}))))
            with self.assertRaises(REFUSALS):self.admit(raw=C(changed))

    def test_wrong_manifest_or_probe_cannot_replace_parent_reference(self):
        for key in ('manifestSha256','manifestBase64','nativePlanSha256'):
            header=dict(self.header);header[key]='f'*64
            changed=dict(self.offer,headerSha256=H(C(header)))
            with self.assertRaises(REFUSALS):self.admit(raw=C(changed),header=C(header))

    def test_header_unknown_fields_and_runtime_roles_refused(self):
        for header in (dict(self.header,extra=True),dict(self.header,runtimes={'python':'a'*64})):
            with self.assertRaises(REFUSALS):policy._header(C(header))

    def test_duplicate_json_keys_refused(self):
        raw=C(self.offer)[:-1]+b',"contextBytes":1}'
        with self.assertRaises(REFUSALS):self.admit(raw=raw)

    def test_descriptor_count_context_size_and_times_are_integers(self):
        for key in ('publicationDescriptorsHeld','contextBytes','retainedOpenedNs','retainedExpiresNs'):
            for value in (True,1.0):
                with self.assertRaises(REFUSALS):self.admit(raw=C(dict(self.offer,**{key:value})))

    def test_native_exit_flags_are_exact_booleans(self):
        for key in ('nativeOwnerExited','nativeOwnedMembersAbsent'):
            for value in (1,False,'true'):
                with self.assertRaises(REFUSALS):self.admit(raw=C(dict(self.offer,**{key:value})))

    def test_retained_and_image_deadlines_and_clock_rollback(self):
        for now in (self.opened-1,self.offer['retainedExpiresNs'],self.intent['expiresNs']):
            with self.assertRaises(REFUSALS):self.admit(now=now)

    def test_closed_or_untyped_parent_reference_is_refused(self):
        with self.assertRaises(REFUSALS):self.admit(reference=object())
        self.reference.close()
        with self.assertRaises(REFUSALS):self.admit()

    def test_all_frame_lengths_are_bounded_before_payload(self):
        raw=policy.frame({'fixed':'public'},100);self.assertEqual(policy.frame_size(raw[:4],100),len(raw)-4)
        for prefix in (b'',b'abc',b'abcde',b'\0'*4,(101).to_bytes(4,'big')):
            with self.assertRaises(REFUSALS):policy.frame_size(prefix,100)

    def test_close_frame_is_fixed_and_does_not_dispatch(self):
        value=policy.close_request(self.plan['nonce'],'a'*64)
        self.assertEqual(value['decision'],'close-without-docker')
        self.assertEqual(set(value),{'schema','nonce','contextSha256','decision'})

    def test_source_inventory_includes_both_fixed_controller_and_transport(self):
        self.assertIn('eng/pilot/RetainedContextController.py',policy.SOURCES)
        self.assertIn('eng/pilot/audit_retained_context_transport.py',policy.SOURCES)
        self.assertEqual(len(policy.SOURCES),len(set(policy.SOURCES)))
        self.assertEqual(len(policy.guard.SOURCES),61)

    def test_source_pin_or_input_failure_consumes_start_before_spawn(self):
        paths={'python':Path(sys.executable).resolve()}
        for role,name in (('powershell','pwsh'),('git','git'),('dotnet','dotnet')):
            path=self.root/(name+('.exe' if os.name=='nt' else ''));path.write_bytes(b'public fake runtime');path.chmod(0o700);paths[role]=path
        pins={name:H(path.read_bytes()) for name,path in paths.items()}
        sources=policy.source_measurement(ROOT);sources[next(iter(sources))]='f'*64
        with patch.object(policy.process,'_spawn') as spawn:
            with self.assertRaises(REFUSALS):policy.RetainedContextTransport(ROOT,self.operator,C(self.plan),self.reference,self.bases,
                runtime_paths=paths,runtime_pins=pins,source_pins=sources)
            spawn.assert_not_called()
        self.assertTrue((self.operator/policy.ledger_name(self.plan['nonce'])).is_file())
        with patch.object(policy.process,'_spawn') as spawn:
            with self.assertRaises(OSError):policy.RetainedContextTransport(ROOT,self.operator,C(self.plan),self.reference,self.bases,
                runtime_paths=paths,runtime_pins=pins,source_pins=policy.source_measurement(ROOT))
            spawn.assert_not_called()

    def test_ledger_nonce_and_ready_selector_are_canonical(self):
        for nonce in ('../x','AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA'):
            with self.assertRaises(REFUSALS):policy.ledger_name(nonce)
        with self.assertRaises(REFUSALS):policy.ledger_name(self.plan['nonce'],ready=1)


if __name__=='__main__':
    result=unittest.TextTestRunner().run(unittest.defaultTestLoader.loadTestsFromTestCase(RetainedContextContracts))
    if not result.wasSuccessful() or result.skipped:raise SystemExit(1)
    print('RETAINED CONTEXT CONTRACT PASS: '+json.dumps(dict(tests=result.testsRun,skipped=0,sourceFiles=len(policy.SOURCES),
        generatedReferenceOnly=True,dockerOperationsPerformed=0,controllerProcessStarted=False,cleanupAuthorized=False,
        originalInputsRead=False,originalPrivatePkiUsed=False,phase7Complete=False),sort_keys=True))
