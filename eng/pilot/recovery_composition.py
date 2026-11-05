#!/usr/bin/env python3
"""Read-only composition of eight pinned pilot metadata reports; never a restore grant."""
import argparse
import json
from pathlib import Path
import re
import sys
import uuid

import audit_archive as archive
import recovery_files as files

SCHEMA = 'fleetory.recovery-component-manifest.v1'
MANIFEST = 'recovery-component-manifest.json'
MAX_REPORT = 64 * 1024
MAX_TOTAL = 512 * 1024
REPORTS = {
    'database': 'coherent-postgres-restore.json',
    'audit': 'immudb-actual-restore.json',
    'identity': 'keycloak-restore-20261101T174928Z.json',
    'provider': 'provider-original-acceptance-7b72988.json',
    'login': 'runtime-login-actual.json',
    'configuration': 'native-configuration-original-proof.json',
    'release': 'release-input-review.json',
    'images': 'recovery-code-images.json',
}
DATABASES = {'fleetory', 'fleetory_signer'}
ROLES = {'server', 'signer', 'keycloak'}


def expect(record, expected):
    archive.require(type(record) is dict)
    for key, value in expected.items():
        archive.require(key in record and type(record[key]) is type(value) and record[key] == value)


def digest(value):
    archive.require(type(value) is str and re.fullmatch(r'[0-9A-Fa-f]{64}', value))
    return value.lower()


def integer(value, minimum=0):
    archive.require(type(value) is int and minimum <= value <= 1000000)
    return value


def partial(record):
    archive.require(type(record) is dict)
    for key in ('fullSystemRecoveryVerified', 'phase7Complete', 'independentCustodyVerified',
                'globalAtomicSnapshotClaimed', 'standingAuthorizationRemaining'):
        if key in record:
            expect(record, {key: False})


def inventory(record, name):
    expect(record, {'algorithm': 'fleetory.application-signer-recovery.v2', 'database': name,
                    'rolePasswordsAndLoginRecoveryVerified': False, 'globalAtomicSnapshotClaimed': False})
    digest(record['inventorySha256'])
    digest(record['securitySha256'])
    count = integer(record['tableCount'], 1)
    rows = integer(record['totalRows'])
    tables = record['tableCounts']
    archive.require(type(tables) is dict and len(tables) == count)
    archive.require(sum(integer(value) for value in tables.values()) == rows)
    return {'tables': count, 'rows': rows}


def database(record, manifest):
    expect(record, {'status': 'PASS_CURRENT_APPLICATION_SIGNER_DB_RECOVERY_SET',
                    'singleMvccSnapshotPerDatabase': True, 'observedStableCaptureWindow': True,
                    'ownersAndAclsMatched': True, 'roleCapabilitiesAndMembershipsMatched': True,
                    'restartPreservedBothDatabases': True, 'immudbSignedCaptureBoundaryVerified': True,
                    'olderThreeEventApplicationSnapshotRejected': True, 'roleLoginOrPasswordsRecovered': False,
                    'ownedTargetAndVolumeRemoved': True, 'sourceRootRecoveryRepeated': False,
                    'sourceApplicationCommit': manifest['sourceApplicationCommit'],
                    'sourceConfigurationCommit': manifest['sourceConfigurationCommit']})
    archive.fields(record['databaseInventories'], DATABASES)
    archive.fields(record['dumpSha256'], DATABASES)
    matrix = {name: inventory(record['databaseInventories'][name], name) for name in sorted(DATABASES)}
    for value in record['dumpSha256'].values():
        digest(value)
    audit = record['databaseInventories']['fleetory']['audit']
    expect(audit, {'pendingExportCount': 0, 'events': integer(record['currentAuditEvents'], 1)})
    archive.require(record['databaseInventories']['fleetory_signer']['audit'] is None)
    digest(audit['snapshotSha256'])
    integer(record['immudbCheckpointTransactions'], 1)
    return {'scope': 'original-database-state-and-permissions', 'databases': matrix,
            'auditEvents': audit['events'], 'sourcePasswordsRecovered': False}


def login(record, db, database_digest):
    expect(record, {'schema': 'fleetory.target-login-acceptance.v1',
                    'status': 'PASS_TARGET_ONLY_LOGIN_SCRAM_ON_RETAINED_ACTUAL_DB_PAIR',
                    'runtimeRoles': 2, 'transport': 'private Unix socket SCRAM-SHA-256',
                    'sourcePasswordsRead': False, 'sourcePasswordRecoveryVerified': False,
                    'remoteTlsVerified': False, 'issuerOrSigningServicesStarted': False,
                    'explicitLoginCapabilitiesVerified': True, 'generatedTargetOwnerPasswordsRemainNoLogin': True,
                    'dataSchemaOwnersGrantsMembershipsUnchanged': True, 'targetPasswordRotationVerified': True,
                    'restartAuthenticationVerified': True, 'originalDumpFilesUnmodified': True,
                    'ownedResourcesRemoved': True, 'ephemeralPasswordFilesRemoved': True})
    archive.require(digest(record['sourceRestoreProofSha256']) == database_digest)
    for key, expected in (('sourceDumpSha256', db['dumpSha256']),
                          ('databaseInventoriesBefore', db['databaseInventories']),
                          ('databaseInventoriesAfter', db['databaseInventories'])):
        archive.require(archive.canonical(record[key]) == archive.canonical(expected))
    for key, minimum in {'successfulReadbackSessions': 8, 'privilegeDenials': 21, 'permittedZeroRowInserts': 4,
                         'wrongPasswordDenials': 2, 'oldPasswordDenials': 2, 'noLoginOwnerDenials': 2,
                         'crossDatabaseDenials': 2}.items():
        integer(record[key], minimum)
    return {'scope': 'regenerated-target-credentials', 'runtimeRoles': 2,
            'sourcePasswordsRecovered': False, 'remoteTlsVerified': False}


def audit(record, db, manifest):
    expect(record, {'schema': 'fleetory.pilot-immudb-restore.v1',
                    'status': 'PASS_ACTUAL_AUDIT_DB_OFFHOST_RESTORE_LIMITED_SCOPE',
                    'database': 'fleetoryaudit', 'transactions': db['immudbCheckpointTransactions'],
                    'verifiedAuditEvents': db['currentAuditEvents'], 'sourceStateUnchanged': True,
                    'restoredEventHashesAndRevisionsVerified': True, 'readOnlyPrincipalWriteDenied': True,
                    'restartPreservedStateAndReader': True, 'locallyRetainedCheckpointVerified': True,
                    'corruptedBackupRestoreRejected': True, 'ownedTargetAndVolumeRemoved': True,
                    'signedStateCryptographicVerification': 'PASS_EXISTING_OFFLINE_VERIFIER',
                    'checkpointIndependentApprovalClaimed': False, 'sourcePrivateSigningKeyTransferred': False,
                    'sourceRootRecoveryRepeated': False, 'sourceApplicationCommit': manifest['sourceApplicationCommit'],
                    'sourceConfigurationCommit': manifest['sourceConfigurationCommit']})
    digest(record['checkpointSha256'])
    return {'scope': 'original-audit-state-and-signed-checkpoint', 'events': record['verifiedAuditEvents'],
            'transactions': record['transactions'], 'independentCustodyVerified': False}


def identity(record):
    expect(record, {'schema': 'fleetory.keycloak-restore-evidence.v1', 'sourceTemporaryFilesRemoved': True})
    restored = record['restore']
    expect(restored, {'schema': 'fleetory.keycloak-restore-verification.v1', 'verified': True,
                      'postRestoreHumanLoginVerified': False, 'independentCustodyVerified': False})
    digest(restored['dumpSha256'])
    return {'scope': 'historical-logical-identity-database', 'tables': integer(restored['tableCount'], 1),
            'rows': integer(restored['totalRows']), 'postRestoreHumanLoginVerified': False}


def provider(record):
    expect(record, {'schema': 'fleetory.retained-provider-acceptance.v1',
                    'status': 'PASS_SINGLE_APPROVED_OPERATION_CONSUMED', 'verified': True,
                    'permissionConsumed': True, 'standingAuthorizationRemaining': False,
                    'actualSignerServerAuthenticated': False, 'naturalExpiryWaited': False,
                    'sourceProviderApiCalls': 0, 'sourceRootRecoveryRepeated': False,
                    'productionTokensIssued': False, 'originalPkiUsed': False})
    operation = record['operationId']
    archive.require(type(operation) is str)
    parsed = uuid.UUID(operation)
    archive.require(parsed.int != 0 and str(parsed) == operation)
    result = record['controllerResult']
    expect(result, {'operationId': record['operationId'], 'scope': 'retained-provider', 'verified': True,
                    'cleanupVerified': True, 'snapshotReads': 1, 'shareReads': 1, 'shareSubmissions': 4,
                    'sourceProviderApiCalls': 0, 'productionTokensIssued': False})
    partial(result)
    archive.require(digest(record['planSha256']) == digest(result['planSha256']))
    expect(record['codeBoundAssertions'], {'targetRootRevoked403BeforeSignature': True,
                                         'probeRevoked403': True, 'nonCommandSignatureVerified': True,
                                         'targetRemovalAndAbsenceVerified': True})
    return {'scope': 'consumed-isolated-provider-operation', 'permissionConsumed': True,
            'standingAuthorizationRemaining': False, 'actualSignerServerAuthenticated': False,
            'naturalExpiryVerified': False}


def configuration(record):
    expect(record, {'schema': 'fleetory.original-native-configuration.v1', 'provider': 'File',
                    'originalFilesLoaded': 13, 'originalPublicFilesValidated': 10, 'originalPrivateLeafKeysUsed': 3,
                    'regeneratedCredentialSlots': 4, 'nativeBuildersAccepted': 2,
                    'publicPinsMatchedBeforePrivateKeyReads': True, 'originalFilesUnchanged': True,
                    'ownedResourcesRemoved': True, 'secretCanariesAbsent': True, 'tcpListenersObserved': 0,
                    'servicesStarted': False, 'databaseOpened': False, 'providerBackendAuthenticationVerified': False,
                    'currentCallerAdmissionVerified': False, 'transitKeyContinuityVerified': False,
                    'restoredIssuerActivated': False, 'policyGrantRenewed': False, 'sourcePasswordsRead': False,
                    'sourceRootRecoveryRepeated': False, 'productionTokensIssued': False})
    return {'scope': 'original-files-build-dispose-only', 'originalFiles': 13, 'nativeBuilders': 2,
            'servicesStarted': False, 'providerBackendAuthenticationVerified': False,
            'newUseOfOriginalMaterialAuthorized': False}


def release(record):
    expect(record, {'schema': 'fleetory.release-input-review.v1', 'newSecretOrPkiCopy': False,
                    'newTokensIssued': False, 'sourceRestarted': False})
    continuity = record['continuity']
    expect(continuity, {'schema': 'fleetory.release-payload-continuity.v1', 'codePayloadContinuityVerified': True,
                        'imageConfigurationVerified': False, 'releaseSignatureVerified': False,
                        'sourceRevisionAuthenticated': False})
    expect(record['archiveInventory'], {'releaseSignatureVerified': False, 'sourceRevisionAuthenticated': False})
    archive.require(digest(continuity['archiveSha256']) == digest(record['archiveInventory']['archiveSha256']))
    return {'scope': 'payload-continuity-only', 'matchedFiles': integer(continuity['matchedFiles'], 1),
            'sourceRevisionAuthenticated': False, 'releaseSignatureVerified': False}


def images(record, release_record):
    expect(record, {'schema': 'fleetory.recovery-code-images.v1', 'applicationOrIssuerStarted': False,
                    'historicalSourceImageReproduced': False, 'releaseSignatureVerified': False,
                    'codeArchiveReloadExactImageIdsVerified': True, 'newSecretOrPkiCopied': False,
                    'sourceVpsAccessed': False, 'additionalCost': 0})
    archive.fields(record['images'], ROLES)
    archive.require(digest(record['contexts']['archiveSha256']) == digest(release_record['continuity']['archiveSha256']))
    payload = sum(integer(record['images'][name]['payloadFilesMatched'], 1) for name in ('server', 'signer'))
    archive.require(payload == release_record['continuity']['matchedFiles'])
    for entry in record['images'].values():
        expect(entry, {'baseRootfsPrefixMatches': True})
        expect(entry['metadata'], {'os': 'linux', 'arch': 'amd64'})
        value = entry['metadata']['id']
        archive.require(type(value) is str and value.startswith('sha256:'))
        digest(value[7:])
    return {'scope': 'reconstructed-code-only-images', 'images': len(ROLES), 'payloadFiles': payload,
            'historicalSourceImageReproduced': False, 'servicesStarted': False}


def compose(reports, manifest):
    for record in reports.values():
        partial(record)
    db = reports['database']
    return {
        'database': database(db, manifest),
        'audit': audit(reports['audit'], db, manifest),
        'identity': identity(reports['identity']),
        'provider': provider(reports['provider']),
        'login': login(reports['login'], db, manifest['reports']['database']['sha256']),
        'configuration': configuration(reports['configuration']),
        'release': release(reports['release']),
        'images': images(reports['images'], reports['release']),
    }


def verify(root, expected):
    expected = digest(expected)
    with files.rooted(root) as (directory, descriptor):
        pin, _, packet = files.inspect_file(directory, descriptor, MANIFEST, MAX_REPORT, retain=True)
        archive.require(pin == expected)
        manifest = archive.parse(packet, MAX_REPORT)
        archive.fields(manifest, ('schema', 'sourceApplicationCommit', 'sourceConfigurationCommit', 'operatorRevision', 'reports'))
        expect(manifest, {'schema': SCHEMA})
        for key in ('sourceApplicationCommit', 'sourceConfigurationCommit', 'operatorRevision'):
            archive.require(type(manifest[key]) is str and re.fullmatch(r'[0-9a-f]{40}', manifest[key]))
        archive.fields(manifest['reports'], REPORTS)
        total = 0
        for entry in manifest['reports'].values():
            archive.fields(entry, ('bytes', 'sha256'))
            archive.require(0 < integer(entry['bytes']) <= MAX_REPORT)
            archive.require(type(entry['sha256']) is str and archive.HEX.fullmatch(entry['sha256']))
            total += entry['bytes']
        archive.require(total <= MAX_TOTAL)
        reports = {}
        for kind, name in REPORTS.items():
            entry = manifest['reports'][kind]
            actual, size, packet = files.inspect_file(directory, descriptor, name, entry['bytes'], retain=True)
            archive.require(actual == entry['sha256'] and size == entry['bytes'])
            reports[kind] = archive.parse(packet, MAX_REPORT)
        matrix = compose(reports, manifest)
    return {'schema': 'fleetory.recovery-component-composition.v1', 'status': 'PASS_PARTIAL_COMPONENT_COMPOSITION',
            'manifestSha256': pin, 'verifiedReports': len(REPORTS), 'verifiedReportBytes': total, 'components': matrix,
            'reportedSourceApplicationCommit': manifest['sourceApplicationCommit'],
            'reportedSourceConfigurationCommit': manifest['sourceConfigurationCommit'],
            'operatorRevision': manifest['operatorRevision'], 'referencesOpened': False,
            'sourcePasswordsRecovered': False, 'postRestoreHumanLoginVerified': False,
            'sourceRevisionAuthenticated': False, 'coordinatedCaptureWindowVerified': False,
            'originalServiceStartupVerified': False, 'newOperationsAuthorized': False,
            'standingAuthorizationRemaining': False, 'independentCustodyVerified': False,
            'fullSystemRecoveryVerified': False, 'phase7Complete': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected-sha256', required=True)
    args = parser.parse_args()
    try:
        result = verify(Path.cwd(), args.expected_sha256)
    except Exception:
        print('Recovery component composition failed; no report contents logged.', file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
