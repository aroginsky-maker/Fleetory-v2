#!/usr/bin/env python3
"""Closed two-input Server data admission; no restore, process, credentials or authority."""
import argparse
from dataclasses import dataclass, field
import json
from pathlib import Path
import re
import sys

import audit_archive as archive
import recovery_composition as composition
import recovery_files as files

SCHEMA = 'fleetory.server-data-manifest.v1'
MANIFEST = 'server-data-manifest.json'
INPUTS = {'application-postgres': 'application.dump', 'audit-immudb': 'audit.backup'}
MAX_MANIFEST = 64 * 1024
MAX_INPUT = 32 * 1024 * 1024
MAX_TOTAL = 48 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class VerifiedServerData:
    """Immutable captured bytes, not a permission token or a validated restore format."""
    application: bytes = field(repr=False)
    audit: bytes = field(repr=False)
    summary: bytes = field(repr=False)

    def packet(self, kind):
        archive.require(type(kind) is str and kind in INPUTS)
        return self.application if kind == 'application-postgres' else self.audit

    def result(self):
        return json.loads(self.summary)


def validate_manifest(record):
    archive.fields(record, ('schema', 'componentManifestSha256', 'candidateCommit',
                            'candidateBuildSha256', 'artifacts'))
    composition.expect(record, {'schema': SCHEMA})
    archive.require(type(record['candidateCommit']) is str
                    and re.fullmatch(r'[0-9a-f]{40}', record['candidateCommit'])
                    and record['candidateCommit'] != '0' * 40)
    for key in ('componentManifestSha256', 'candidateBuildSha256'):
        archive.require(type(record[key]) is str and archive.HEX.fullmatch(record[key]))
    archive.fields(record['artifacts'], INPUTS)
    total = 0
    for entry in record['artifacts'].values():
        archive.fields(entry, ('bytes', 'sha256'))
        archive.require(type(entry['bytes']) is int and 0 < entry['bytes'] <= MAX_INPUT)
        archive.require(type(entry['sha256']) is str and archive.HEX.fullmatch(entry['sha256']))
        total += entry['bytes']
    archive.require(total <= MAX_TOTAL)
    archive.require(len({entry['sha256'] for entry in record['artifacts'].values()}) == 2)


def load(root, expected):
    """Admit all or return nothing; future consumers use these bytes, never reopen paths."""
    expected = composition.digest(expected)
    with files.rooted(root) as (directory, descriptor):
        pin, _, packet = files.inspect_file(directory, descriptor, MANIFEST, MAX_MANIFEST, retain=True)
        archive.require(pin == expected)
        manifest = archive.parse(packet, MAX_MANIFEST)
        validate_manifest(manifest)
        component_pin, component_manifest, reports, _ = composition.read_reports(
            directory, manifest['componentManifestSha256'])
        matrix = composition.compose(reports, component_manifest)
        database = reports['database']
        audit = reports['audit']
        artifacts = manifest['artifacts']
        archive.require(artifacts['application-postgres']['sha256'] ==
                        composition.digest(database['dumpSha256']['fleetory']))
        archive.require(artifacts['audit-immudb']['sha256'] == composition.digest(audit['backupSha256']))
        archive.require(type(audit['backupBytes']) is int and
                        artifacts['audit-immudb']['bytes'] == audit['backupBytes'])
        captured = {}
        for kind, name in INPUTS.items():
            entry = artifacts[kind]
            actual, size, packet = files.inspect_file(directory, descriptor, name, entry['bytes'], retain=True)
            archive.require(actual == entry['sha256'] and size == entry['bytes'])
            captured[kind] = packet
    inventory = database['databaseInventories']['fleetory']
    result = {
        'schema': 'fleetory.server-data-admission.v1', 'status': 'PASS_TWO_INPUT_BYTE_ADMISSION_ONLY',
        'manifestSha256': pin, 'componentManifestSha256': component_pin,
        'candidateCommit': manifest['candidateCommit'], 'candidateBuildSha256': manifest['candidateBuildSha256'],
        'reportedSourceApplicationCommit': component_manifest['sourceApplicationCommit'],
        'reportedSourceConfigurationCommit': component_manifest['sourceConfigurationCommit'],
        'verifiedInputs': 2, 'verifiedInputBytes': sum(len(value) for value in captured.values()),
        'artifacts': artifacts, 'applicationInventorySha256': composition.digest(inventory['inventorySha256']),
        'applicationSecuritySha256': composition.digest(inventory['securitySha256']),
        'auditSnapshotSha256': composition.digest(inventory['audit']['snapshotSha256']),
        'expectedApplicationTables': matrix['database']['databases']['fleetory']['tables'],
        'expectedApplicationRows': matrix['database']['databases']['fleetory']['rows'],
        'expectedAuditEvents': matrix['audit']['events'], 'expectedAuditTransactions': matrix['audit']['transactions'],
        'payloadReferencesOpened': False, 'bytesCapturedBeforeReturn': True,
        'nativeBackupFormatsValidated': False, 'databaseSchemaCompatibilityVerified': False,
        'candidateBuildAuthenticated': False, 'sourceRevisionAuthenticated': False,
        'restoredDataContentsVerified': False, 'originalSigningKeyContinuityVerified': False,
        'servicesStarted': False, 'newOperationsAuthorized': False, 'standingAuthorizationRemaining': False,
        'postRestoreHumanLoginVerified': False, 'fullSystemRecoveryVerified': False, 'phase7Complete': False,
    }
    return VerifiedServerData(captured['application-postgres'], captured['audit-immudb'], archive.canonical(result))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected-sha256', required=True)
    args = parser.parse_args()
    try:
        result = load(Path.cwd(), args.expected_sha256).result()
    except Exception:
        print('Server data admission failed; no input contents logged.', file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
