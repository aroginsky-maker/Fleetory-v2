"""Synthetic gate records; successful JSON is explicitly not an authenticated approval."""
import copy
import json
from pathlib import Path
import sys
import subprocess
import unittest
from unittest.mock import patch

import historical_audit_restore_tests as native_vectors

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'eng/pilot'))
import audit_use_admission as policy

C = policy.native.history.core.canonical
H = policy.packet.digest


def fixture():
    declared, parts = native_vectors.fixture()
    revision = declared['revision']
    jobs = [dict(id=100 + i, name=name, status='completed', conclusion='success') for i, name in enumerate(sorted(policy.JOBS))]
    checks = [dict(row, head=revision) for row in jobs] + [dict(id=105, name='SonarCloud Code Analysis', status='completed', conclusion='success', head=revision)]
    ci = dict(schema='fleetory.owned-historical-controller-ci.v1', status='PASS', revision=revision, number=317, runId=1234567, attempt=1,
        repositoryPrivate=False, pr=dict(head=revision, state='open', draft=True, merged=False), jobs=jobs, checks=checks,
        officialSonar=dict(status='PASS', checkId=105, strictIssueGate=dict(revision=revision, check=105), newIssues=0, acceptedIssues=0, newHotspots=0,
            metrics=[dict(name=name, value=value) for name, value in (('COVERAGE','91.9'),('NEW COVERAGE','92.2180607573866'),('DUPLICATION','0.0'),('NEW DUPLICATION','0.0'))]),
        nativeDotnetCoverage='93.66', secretScan=dict(findings=0), dependencyAudit=dict(projects=31, skipped=0))
    local = dict(revision=revision, analysisRevision=revision, status='PASS', analysisId=declared['nonce'], source='local SonarQube synthetic',
        coverageReportSha256='f' * 64, coverageSourceRevision='c' * 40,
        measures=[dict(metric=name, value=value) for name, value in (('coverage','92.1'),('alert_status','OK'),('duplicated_lines_density','0.0'),('violations','0'),('new_violations','0'),('security_hotspots','0'))])
    selection = policy.archive.selection
    relative = 'immudb-restore-' + '2' * 32 + '/backup.bin'
    refs = (selection.ArtifactReference('application-postgres', 'coherent-postgres-' + '1' * 32 + '/fleetory.dump', 100, '1' * 64),
        selection.ArtifactReference('signer-postgres', 'coherent-postgres-' + '1' * 32 + '/fleetory_signer.dump', 100, '2' * 64),
        selection.ArtifactReference('audit-immudb', relative, len(parts['archive']), H(parts['archive'])))
    selected = selection.Selection(refs, tuple((name, char * 64) for name, char in (('audit','3'),('database','4'),('manifest','5')))).report()
    plan = dict(schema=policy.SCHEMA, purpose=policy.PURPOSE, nonce=declared['nonce'], revision=revision, pins={},
        scope=dict(historicalComparisonOnly=True, **{name:False for name in policy.FALSE_FLAGS}))
    return plan, declared, selected, ci, local, parts


class AuditUseAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.plan, self.native, self.selection, self.ci, self.local, self.parts = fixture()

    def bundle(self):
        ci, local = C(self.ci), C(self.local)
        self.native.update(ciEvidenceSha256=H(ci), localEvidenceSha256=H(local))
        metadata = dict(native=C(self.native), selection=C(self.selection), ci=ci, local=local)
        self.plan['pins'] = {name:H(value) for name, value in metadata.items()}
        raw = C(self.plan)
        return raw, H(raw), metadata

    def admit(self):
        return policy.admit(*self.bundle())

    def refused(self):
        with self.assertRaises((ValueError, TypeError, KeyError)):
            self.admit()

    def test_valid_pins_and_records_never_become_external_authority(self):
        value = self.admit()
        self.assertEqual((value.archive_bytes, value.archive_sha256), (64, H(self.parts['archive'])))
        self.assertTrue(value.report()['gateRecordSemanticsMatched'])
        for name in ('gateOriginAuthenticated','existingDataConsentAuthenticated','newPermissionGranted','nativeLaunchAuthorized','executionAuthorized','fullSystemRecoveryVerified'):
            self.assertIs(value.report()[name], False)

    def test_coverage_floors_apply_to_official_new_native_and_local(self):
        for target in ('official', 'new', 'native', 'local'):
            self.setUp()
            if target in ('official','new'):
                self.ci['officialSonar']['metrics'][0 if target=='official' else 1]['value']='89.999'
            elif target=='native': self.ci['nativeDotnetCoverage']='89.9'
            else: self.local['measures'][0]['value']='89.9'
            self.refused()

    def test_duplication_and_nonfinite_or_boolean_percentages_refused(self):
        for value in ('0.001','NaN','Infinity','1e-8',True):
            self.setUp();self.ci['officialSonar']['metrics'][2]['value']=value;self.refused()
        for value in ('0.1','NaN',True):
            self.setUp();self.local['measures'][2]['value']=value;self.refused()

    def test_official_issue_and_hotspot_counters_are_typed_zero(self):
        for name in ('newIssues','acceptedIssues','newHotspots'):
            for value in (1,False):
                self.setUp();self.ci['officialSonar'][name]=value;self.refused()

    def test_identifiers_cannot_alias_booleans_or_duplicate_jobs(self):
        for name in ('number','runId','attempt'):
            self.setUp();self.ci[name]=True;self.refused()
        self.setUp();self.ci['jobs'][1]['id']=self.ci['jobs'][0]['id'];self.refused()
        self.setUp();self.ci['officialSonar']['checkId']=True;self.refused()

    def test_each_execution_or_aggregate_job_is_required_success(self):
        for index in range(5):
            for state in ('failure','cancelled','skipped',None):
                self.setUp();self.ci['jobs'][index]['conclusion']=state;self.refused()
        self.setUp();self.ci['jobs'].pop();self.refused()
        self.setUp();self.ci['jobs'][1]=copy.deepcopy(self.ci['jobs'][0]);self.refused()

    def test_all_six_checks_bind_the_exact_revision(self):
        for index in range(6):
            self.setUp();self.ci['checks'][index]['head']='b'*40;self.refused()
        self.setUp();self.ci['checks'][-1]['conclusion']='neutral';self.refused()
        self.setUp();self.ci['checks'].pop();self.refused()

    def test_sonar_check_and_strict_gate_cannot_be_mixed(self):
        self.ci['officialSonar']['checkId']=99;self.refused()
        self.setUp();self.ci['officialSonar']['strictIssueGate']['revision']='b'*40;self.refused()
        self.setUp();self.ci['officialSonar']['strictIssueGate']['check']=True;self.refused()

    def test_pr_visibility_head_and_unmerged_draft_state_preserved(self):
        for name, value in (('head','b'*40),('state','closed'),('draft',False),('merged',True)):
            self.setUp();self.ci['pr'][name]=value;self.refused()
        self.setUp();self.ci['repositoryPrivate']=True;self.refused()

    def test_local_analysis_revision_identity_and_source_required(self):
        for name,value in (('analysisRevision','b'*40),('revision','b'*40),('analysisId','wrong'),('source','official cloud'),('status','PENDING')):
            self.setUp();self.local[name]=value;self.refused()

    def test_local_issues_hotspots_and_missing_metrics_refused(self):
        for index in (3,4,5):
            self.setUp();self.local['measures'][index]['value']='1';self.refused()
        self.setUp();self.local['measures'].pop();self.refused()
        self.setUp();self.local['measures'][1]['value']='ERROR';self.refused()

    def test_dependency_omission_and_secret_findings_refused(self):
        self.ci['dependencyAudit']['skipped']=1;self.refused()
        self.setUp();self.ci['secretScan']['findings']=1;self.refused()
        self.setUp();self.ci['dependencyAudit']['projects']=0;self.refused()

    def test_external_pin_and_each_metadata_pin_are_checked(self):
        raw,pin,metadata=self.bundle()
        with self.assertRaises(ValueError): policy.admit(raw,'0'*64,metadata)
        for name in metadata:
            changed=dict(metadata);changed[name]=changed[name]+b' '
            with self.assertRaises(ValueError): policy.admit(raw,pin,changed)

    def test_outer_scope_and_native_nonce_are_not_interchangeable(self):
        self.native['nonce']='00000000-0000-4000-8000-000000000002';self.refused()
        self.setUp();self.plan['root']='PRIVATE_INPUT_CANARY';self.refused()
        self.setUp();self.native['revision']='b'*40;self.refused()

    def test_no_scope_boolean_or_authority_promotion(self):
        for name in policy.FALSE_FLAGS:
            for value in (True,0):
                self.setUp();self.plan['scope'][name]=value;self.refused()
        self.setUp();self.plan['scope']['historicalComparisonOnly']=1;self.refused()

    def test_metadata_keys_bounds_and_duplicate_json_are_closed(self):
        raw,pin,metadata=self.bundle()
        for altered in ({**metadata,'extra':b'x'}, {**metadata,'ci':b'x'*(policy.METADATA['ci']+1)}):
            with self.assertRaises(ValueError):policy.admit(raw,pin,altered)
        raw=raw.replace(b'"schema":',b'"schema":"duplicate","schema":',1)
        with self.assertRaises(ValueError):policy.admit(raw,H(raw),metadata)

    def test_archive_reference_must_match_native_bytes_and_digest(self):
        self.native['inputs']['archiveBytes']+=1;self.refused()
        self.setUp();self.native['inputs']['archiveSha256']='0'*64;self.refused()
        self.setUp();self.selection['selected'][2]['kind']='provider-raft';self.refused()

    def test_all_mutable_inputs_frozen_before_any_parser_callback(self):
        raw,pin,metadata=self.bundle();raw=bytearray(raw);metadata={name:bytearray(data) for name,data in metadata.items()}
        parser=policy.packet.strict_json
        def mutate(data,bound):
            raw[:]=b'changed'
            for value in metadata.values():value[:]=b'changed'
            return parser(data,bound)
        with patch.object(policy.packet,'strict_json',side_effect=mutate):
            self.assertTrue(policy.admit(raw,pin,metadata).report()['gateEvidencePinsMatched'])

    def test_gate_decoder_uses_no_file_process_or_socket_api(self):
        with patch('builtins.open',side_effect=AssertionError('File forbidden')),patch('subprocess.Popen',side_effect=AssertionError('Process forbidden')),patch('socket.socket',side_effect=AssertionError('Socket forbidden')):
            self.assertTrue(self.admit().report()['auditOnlyReferenceMatched'])

    def test_native_profile_and_limits_stay_closed(self):
        self.native['limits']['nativeSeconds']=601;self.refused()
        self.setUp();self.native['scope']['writerAdmissionVerified']=True;self.refused()
        self.setUp();self.plan['purpose']='restore-and-start';self.refused()

    def test_library_modules_refuse_cli_arguments_without_echoing_input(self):
        for name in ('audit_use_admission.py','audit_use_transaction.py'):
            path=Path(policy.__file__).with_name(name)
            result=subprocess.run([sys.executable,'-B',str(path),'--root','PRIVATE_INPUT_CANARY'],input=b'PRIVATE_INPUT_CANARY',capture_output=True,timeout=10)
            self.assertEqual(result.returncode,1)
            self.assertNotIn(b'PRIVATE_INPUT_CANARY',result.stdout+result.stderr)


if __name__=='__main__':
    unittest.main()
