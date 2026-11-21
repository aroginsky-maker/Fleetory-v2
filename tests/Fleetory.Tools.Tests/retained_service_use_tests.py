"""Actual held local process/records, generated four files; no native dispatch or originals."""
import copy
import json
import os
from pathlib import Path
import shutil
import sys
import threading
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'eng/pilot'))
from historical import retained_service_use as policy
import retained_service_inputs_tests as fixture

H, C = policy.H, policy.C


class ServiceUseTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixture.RetainedServiceInputsTests('runTest')
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root = self.fixture.root
        self.operator = self.root / 'operator'
        self.operator.mkdir(mode=0o700)
        self.repo = self.root / 'code'
        source = Path(__file__).resolve().parents[2]
        for name in policy.SOURCES:
            target = self.repo / 'eng/pilot' / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source / 'eng/pilot' / name, target)
        revision = '1' * 40
        self.metadata = dict(selection=self.fixture.raw, **self.fixture.source.metadata)
        self.metadata['ci'] = C(dict(schema='fleetory.retained-inflight-native-acceptance.v1',
            revision=revision, codeCi='PASS', localSonar='PASS', overallCi='failure',
            officialSonar='COMPUTE_FAILED_DETAIL_UNAVAILABLE', nativeCiCoverage='93.66',
            fullSystemRecoveryVerified=False, phase7Complete=False))
        measures = [dict(metric=k, value=v) for k, v in dict(coverage='92.1', alert_status='OK',
            duplicated_lines_density='0.0', violations='0', new_violations='0', security_hotspots='0').items()]
        self.metadata['local'] = C(dict(revision=revision, analysisRevision=revision, status='PASS',
            analysisId='12345678-1234-4123-8123-123456789abc', source='local SonarQube fixture',
            coverageReportSha256='2' * 64, coverageSourceRevision=revision, measures=measures))
        self.plan = dict(schema=policy.SCHEMA, purpose=policy.PURPOSE, nonce=fixture.source_tests.NONCE,
            revision=revision, root=str(self.root),
            pins={n:H(v) for n, v in self.metadata.items()},
            sourcePins={n:H((self.repo/'eng/pilot'/n).read_bytes()) for n in policy.SOURCES},
            pythonSha256=H(Path(sys.executable).resolve().read_bytes()), imageId='sha256:'+'3'*64,
            probeSha256='4'*64, configurationSha256='5'*64)
        self.calls = []
        self.consumer = lambda raw: self.calls.append(raw) or b'generated-result'
        self.pin()

    def pin(self):
        self.raw = bytearray(C(self.plan))
        self.digest = H(self.raw)

    def use(self):
        return policy.use(self.operator, self.root, self.repo, self.raw, self.digest, self.metadata, self.consumer)

    def test_real_owner_record_capture_and_one_consumption(self):
        with self.use() as use:
            initial = use.report()
            self.assertEqual(initial['heldProcessIdentity']['pid'], os.getpid())
            self.assertTrue(initial['heldProcessIdentity']['birthToken'])
            self.assertEqual(initial['stage'], 'ready')
            use.capture()
            self.assertEqual(use.dispatch(), b'generated-result')
            self.assertEqual(len(self.calls), 1)
            value = json.loads(self.calls[0])
            self.assertEqual(value['capture']['verifiedArtifacts'], 4)
            for key in ('executionAuthorized', 'nativeResultAuthenticated', 'existingDataConsentAuthenticated',
                        'nativeConsumerProcessAuthenticated', 'gateOriginAuthenticated', 'fullSystemRecoveryVerified', 'phase7Complete'):
                self.assertIs(use.report()[key], False)
            with self.assertRaises(ValueError): use.dispatch()
            with self.assertRaises(ValueError): use.capture()

    def test_flushed_record_precedes_first_artifact_open(self):
        original = policy.inputs.files.inspect_file
        def check(*args, **kwargs):
            record = policy._LIVE[use]['attempt'].report()
            self.assertEqual(record['status'], 'ATTEMPT_CONSUMED')
            self.assertEqual(record['planSha256'], self.digest)
            return original(*args, **kwargs)
        with self.use() as use, patch.object(policy.inputs.files, 'inspect_file', side_effect=check) as seen:
            use.capture()
            self.assertEqual(seen.call_count, 4)

    def test_record_replay_and_closed_or_copied_context_refused(self):
        with self.use() as use:
            copied = copy.copy(use)
            with self.assertRaises(ValueError): copied.capture()
        with self.assertRaises(ValueError): use.report()
        with self.assertRaises(OSError):
            with self.use(): self.fail('Retained nonce restarted')

    def test_capture_failure_remains_consumed(self):
        with self.use() as use, patch.object(policy.inputs, 'capture', side_effect=OSError('generated fault')) as seen:
            with self.assertRaises(OSError): use.capture()
            with self.assertRaises(ValueError): use.capture()
            self.assertEqual(seen.call_count, 1)
            with self.assertRaises(ValueError): use.dispatch()

    def test_lost_dispatch_response_is_not_retried(self):
        def lost(_): raise OSError('generated lost reply')
        self.consumer = lost
        with self.use() as use:
            use.capture()
            with self.assertRaises(OSError): use.dispatch()
            with self.assertRaises(ValueError): use.dispatch()

    def test_payload_stays_frozen_after_source_paths_change(self):
        with self.use() as use:
            use.capture()
            for entry in self.fixture.record['selected']:
                (self.root/entry['path']).write_bytes(b'changed')
            self.fixture.source.path.write_bytes(b'changed')
            use.dispatch()
            value = json.loads(self.calls[0])
            self.assertEqual(value['packetSha256']['application-postgres'], H(self.fixture.data['application-postgres']))

    def test_foreign_caller_refused_before_read(self):
        with self.use() as use, patch.object(policy.os, 'getpid', return_value=os.getpid()+1), \
                patch.object(policy.inputs, 'capture', side_effect=AssertionError('Opened')) as seen:
            with self.assertRaises(ValueError): use.capture()
            self.assertFalse(seen.called)

    def test_competing_thread_cannot_capture_or_reuse_the_creators_handles(self):
        failures = []
        with self.use() as use, patch.object(policy.inputs, 'capture', side_effect=AssertionError('Opened')) as seen:
            def other():
                try: use.capture()
                except ValueError: failures.append(True)
            worker = threading.Thread(target=other)
            worker.start();worker.join(timeout=5)
            self.assertFalse(worker.is_alive())
            self.assertEqual(failures, [True])
            self.assertFalse(seen.called)

    def test_expiry_before_capture_does_not_open(self):
        with self.use() as use:
            state = policy._LIVE[use]
            with patch.object(policy.time, 'monotonic_ns', return_value=state['mono']+policy.LIFETIME_NS), \
                    patch.object(policy.inputs, 'capture', side_effect=AssertionError('Opened')) as seen:
                with self.assertRaises(ValueError): use.capture()
                self.assertFalse(seen.called)

    def test_wall_rollback_refused(self):
        with self.use() as use:
            with patch.object(policy.time, 'time_ns', return_value=policy._LIVE[use]['wall']-1):
                with self.assertRaises(ValueError): use.report()

    def test_expired_dispatch_result_is_refused_without_renewing_clock(self):
        def late(_):
            policy._LIVE[current]['mono'] -= policy.LIFETIME_NS
            return b'result'
        self.consumer = late
        with self.use() as current:
            current.capture()
            with self.assertRaises(ValueError): current.dispatch()

    def test_oversized_result_is_consumed(self):
        self.consumer = lambda _: b'x'*(policy.MAX_RESULT+1)
        with self.use() as use:
            use.capture()
            with self.assertRaises(ValueError): use.dispatch()
            with self.assertRaises(ValueError): use.dispatch()

    def test_held_record_corruption_refused(self):
        with self.assertRaises(ValueError), self.use() as use:
            stream = policy._LIVE[use]['attempt']._stream
            stream.seek(0);stream.write(b'changed')
            use.capture()

    def test_closed_source_handle_refused_before_capture(self):
        with self.use() as use:
            policy._LIVE[use]['sources'][0].close()
            with self.assertRaises(ValueError): use.capture()

    def test_changed_source_refuses_before_any_raw_open(self):
        (self.repo/'eng/pilot'/policy.SOURCES[0]).write_bytes(b'changed')
        with patch.object(policy.inputs, 'capture', side_effect=AssertionError('Opened')) as seen:
            with self.assertRaises(ValueError):
                with self.use(): self.fail('Changed source admitted')
            self.assertFalse(seen.called)

    def test_flush_failure_consumes_record_without_capture(self):
        with patch.object(policy.attempts.os, 'fsync', side_effect=OSError('generated flush failure')):
            with self.assertRaises(OSError):
                with self.use(): self.fail('Unflushed attempt admitted')
        self.assertEqual(len(list(self.operator.iterdir())), 1)
        with self.assertRaises(OSError):
            with self.use(): self.fail('Failed attempt replayed')

    def test_plan_pin_and_purpose_mismatch_prevent_open(self):
        for mutation in ('pin', 'purpose', 'root'):
            with self.subTest(mutation=mutation):
                original = copy.deepcopy(self.plan)
                if mutation == 'purpose': self.plan['purpose'] = 'provider-recovery'
                if mutation == 'root': self.plan['root'] = str(self.root.parent)
                self.pin()
                if mutation == 'pin': self.digest = 'f'*64
                with patch.object(policy.inputs, 'capture', side_effect=AssertionError('Opened')):
                    with self.assertRaises(ValueError):
                        with self.use(): self.fail('Mismatched admission')
                self.plan = original

    def test_failed_code_ci_is_not_a_sonar_exception(self):
        ci = json.loads(self.metadata['ci']);ci['codeCi'] = 'FAIL'
        self.metadata['ci'] = C(ci);self.plan['pins']['ci'] = H(self.metadata['ci']);self.pin()
        with self.assertRaises(ValueError):
            with self.use(): self.fail('Code failure admitted')

    def test_local_issue_or_coverage_failure_refuses(self):
        local = json.loads(self.metadata['local']);local['measures'][0]['value'] = '89.99'
        self.metadata['local'] = C(local);self.plan['pins']['local'] = H(self.metadata['local']);self.pin()
        with self.assertRaises(ValueError):
            with self.use(): self.fail('Insufficient local coverage admitted')

    def test_caller_buffers_are_frozen(self):
        with self.use() as use:
            self.raw[:] = b'changed'
            for key in list(self.metadata): self.metadata[key] = b'changed'
            self.plan.clear()
            use.capture()
            self.assertEqual(use.dispatch(), b'generated-result')

    def test_capture_finishing_after_expiry_cannot_dispatch(self):
        original = policy.inputs.capture
        with self.use() as use:
            def late(*args, **kwargs):
                result = original(*args, **kwargs)
                policy._LIVE[use]['mono'] -= policy.LIFETIME_NS
                return result
            with patch.object(policy.inputs, 'capture', side_effect=late):
                with self.assertRaises(ValueError): use.capture()
            with self.assertRaises(ValueError): use.dispatch()
            self.assertFalse(self.calls)

    def test_held_owner_closed_during_consumer_refuses_returned_result(self):
        def ended(_):
            policy._LIVE[current]['peer'].close()
            return b'not-accepted'
        self.consumer = ended
        with self.use() as current:
            current.capture()
            with self.assertRaises(ValueError): current.dispatch()


if __name__ == '__main__':
    unittest.main()
