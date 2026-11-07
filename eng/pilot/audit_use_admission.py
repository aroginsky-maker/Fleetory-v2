"""Pinned gate and audit-only transaction admission. Pins do not authenticate their origin."""
from dataclasses import dataclass
from decimal import Decimal
import re

import audit_archive_input as archive
import fresh_server_pair as packet
import historical_audit_restore as native

SCHEMA = 'fleetory.audit-use-plan.v1'
PURPOSE = 'historical-known-events-sandbox-observation.v1'
JOBS = {'Windows root-only TLS chain', 'Native database and audit recovery',
        'Native provider and identity recovery', 'Strict build, tests, coverage and Sonar execution',
        'Strict build, tests, coverage and Sonar'}
FALSE_FLAGS = ('existingConsentExpanded newPermissionGranted originalPrivatePkiUseAuthorized providerRootOrIssuerUseAuthorized '
               'writerAdmissionVerified executionAuthorized fullSystemRecoveryVerified phase7Complete').split()
METADATA = dict(native=16384, selection=16384, ci=131072, local=16384)


def identity_number(value):
    packet.require(type(value) is int and 0 < value < 2 ** 63)
    return value


def percentage(value, minimum):
    packet.require(type(value) is str and re.fullmatch(r'\d{1,3}(?:\.\d{1,16})?', value) is not None)
    packet.require(Decimal(minimum) <= Decimal(value) <= Decimal(100))


def zero(value):
    packet.require(type(value) is int and value == 0)


def successful_rows(rows, names, revision=None):
    packet.require(type(rows) is list and len(rows) == len(names))
    packet.require({row['name'] for row in rows} == names)
    packet.require(len({row['id'] for row in rows}) == len(rows))
    for row in rows:
        identity_number(row['id'])
        packet.require(row['status'] == 'completed' and row['conclusion'] == 'success')
        if revision is not None:
            packet.require(row['head'] == revision)


def official_gate(sonar, check, revision):
    identity_number(sonar['checkId'])
    packet.require(sonar['status'] == 'PASS' and sonar['checkId'] == check['id'])
    packet.keys(sonar['strictIssueGate'], 'revision check')
    identity_number(sonar['strictIssueGate']['check'])
    packet.require(sonar['strictIssueGate'] == dict(revision=revision, check=check['id']))
    for name in ('newIssues', 'acceptedIssues', 'newHotspots'):
        zero(sonar[name])
    metrics = sonar['metrics']
    packet.require(type(metrics) is list and len(metrics) == 4)
    measured = {row['name']: row['value'] for row in metrics}
    packet.require(set(measured) == {'COVERAGE', 'NEW COVERAGE', 'DUPLICATION', 'NEW DUPLICATION'})
    for name in ('COVERAGE', 'NEW COVERAGE'):
        percentage(measured[name], 90)
    for name in ('DUPLICATION', 'NEW DUPLICATION'):
        percentage(measured[name], 0)
        packet.require(Decimal(measured[name]) == 0)


def ci_gate(value, revision):
    packet.require(type(value) is dict and value['schema'] in ('fleetory.owned-historical-controller-ci.v1', 'fleetory.audit-use-ci.v1'))
    packet.require(value['status'] == 'PASS' and value['revision'] == revision and value['repositoryPrivate'] is False)
    identity_number(value['number']); identity_number(value['runId'])
    packet.require(type(value['attempt']) is int and value['attempt'] == 1)
    pr = value['pr']
    packet.require(pr['head'] == revision and pr['state'] == 'open' and pr['draft'] is True and pr['merged'] is False)
    successful_rows(value['jobs'], JOBS)
    successful_rows(value['checks'], JOBS | {'SonarCloud Code Analysis'}, revision)
    check = next(row for row in value['checks'] if row['name'] == 'SonarCloud Code Analysis')
    official_gate(value['officialSonar'], check, revision)
    percentage(value['nativeDotnetCoverage'], 90)
    zero(value['secretScan']['findings']); zero(value['dependencyAudit']['skipped'])
    identity_number(value['dependencyAudit']['projects'])


def local_gate(value, revision):
    packet.require(value['revision'] == value['analysisRevision'] == revision and value['status'] == 'PASS')
    packet.identity(value['analysisId'])
    packet.require(type(value['source']) is str and value['source'].startswith('local SonarQube '))
    packet.hex_value(value['coverageReportSha256'])
    packet.require(re.fullmatch('[a-f0-9]{40}', value['coverageSourceRevision']) is not None)
    rows = value['measures']
    packet.require(type(rows) is list and len(rows) == 6)
    measured = {row['metric']: row.get('value', row.get('period', {}).get('value')) for row in rows}
    packet.require(set(measured) == {'coverage', 'alert_status', 'duplicated_lines_density', 'violations', 'new_violations', 'security_hotspots'})
    percentage(measured['coverage'], 90)
    packet.require(measured['alert_status'] == 'OK')
    for name in ('duplicated_lines_density', 'violations', 'new_violations', 'security_hotspots'):
        packet.require(type(measured[name]) is str and re.fullmatch(r'0(?:\.0+)?', measured[name]) is not None)


@dataclass(frozen=True)
class AdmittedUse:
    nonce: str
    revision: str
    plan_sha256: str
    native_sha256: str
    selection_sha256: str
    ci_sha256: str
    local_sha256: str
    selection_bytes: bytes
    archive_path: str
    archive_bytes: int
    archive_sha256: str

    def report(self):
        return dict(schema='fleetory.audit-use-admission.v1', nonce=self.nonce, revision=self.revision,
            planSha256=self.plan_sha256, gateEvidencePinsMatched=True, gateRecordSemanticsMatched=True,
            nativePlanPinMatched=True, auditOnlyReferenceMatched=True, historicalComparisonOnly=True,
            gateOriginAuthenticated=False, existingDataConsentAuthenticated=False, newPermissionGranted=False,
            originalPrivatePkiUseAuthorized=False, nativeLaunchAuthorized=False, executionAuthorized=False,
            fullSystemRecoveryVerified=False, phase7Complete=False)


def admit(plan_bytes, plan_pin, metadata):
    packet.require(type(plan_bytes) in (bytes, bytearray) and 0 < len(plan_bytes) <= 16384)
    packet.keys(metadata, 'native selection ci local')
    frozen = {}
    # Copy all externally mutable byte buffers before the first parser callback.
    for name, bound in METADATA.items():
        data = metadata[name]
        packet.require(type(data) in (bytes, bytearray) and 0 < len(data) <= bound)
        frozen[name] = bytes(data)
    root = bytes(plan_bytes)
    pin = packet.hex_value(plan_pin)
    packet.require(packet.digest(root) == pin)
    value = packet.strict_json(root, 16384)
    packet.keys(value, 'schema purpose nonce revision pins scope')
    packet.require(value['schema'] == SCHEMA and value['purpose'] == PURPOSE)
    packet.identity(value['nonce'])
    packet.require(type(value['revision']) is str and re.fullmatch('[a-f0-9]{40}', value['revision']) is not None)
    packet.keys(value['pins'], 'native selection ci local')
    for name, data in frozen.items():
        packet.require(packet.digest(data) == packet.hex_value(value['pins'][name]))
    packet.keys(value['scope'], 'historicalComparisonOnly ' + ' '.join(FALSE_FLAGS))
    packet.require(value['scope']['historicalComparisonOnly'] is True)
    packet.require(all(value['scope'][name] is False for name in FALSE_FLAGS))
    declared = native.plan(frozen['native'], value['pins']['native'])
    packet.require(declared['nonce'] == value['nonce'] and declared['revision'] == value['revision'])
    packet.require(declared['ciEvidenceSha256'] == value['pins']['ci'] and declared['localEvidenceSha256'] == value['pins']['local'])
    reference, selection_pin = archive.audit_reference(frozen['selection'], value['pins']['selection'])
    packet.require(reference.bytes == declared['inputs']['archiveBytes'] and reference.sha256 == declared['inputs']['archiveSha256'])
    ci_gate(packet.strict_json(frozen['ci'], METADATA['ci']), value['revision'])
    local_gate(packet.strict_json(frozen['local'], METADATA['local']), value['revision'])
    return AdmittedUse(value['nonce'], value['revision'], pin, value['pins']['native'], selection_pin,
        value['pins']['ci'], value['pins']['local'], frozen['selection'], reference.path, reference.bytes, reference.sha256)


if __name__ == '__main__':
    raise SystemExit('Audit-use admission is a library; no CLI or data authority is provided.')
