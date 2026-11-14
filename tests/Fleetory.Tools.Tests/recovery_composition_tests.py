"""Synthetic report composition and refusal tests; no backup/PKI/credentials or services."""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'eng' / 'pilot'))
import recovery_composition as policy

H = 'a' * 64
APP = 'a' * 40
CONFIG = 'b' * 40


def flags(true=(), false=(), **values):
    return {**dict.fromkeys(true, True), **dict.fromkeys(false, False), **values}


def inventory(name, audit):
    tables = {'platform.audit_events': 4, 'platform.audit_export_queue': 0} if name == 'fleetory' else {'fixture.table': 4}
    return dict(algorithm='fleetory.application-signer-recovery.v2', database=name,
                inventorySha256=H, securitySha256=H, tableCount=len(tables), totalRows=4,
                tableCounts=tables, audit=audit,
                rolePasswordsAndLoginRecoveryVerified=False, globalAtomicSnapshotClaimed=False)


def synthetic_reports():
    inv = {'fleetory': inventory('fleetory', dict(events=4, pendingExportCount=0, snapshotSha256=H)),
           'fleetory_signer': inventory('fleetory_signer', None)}
    db = flags(true=('singleMvccSnapshotPerDatabase', 'observedStableCaptureWindow', 'ownersAndAclsMatched',
                     'roleCapabilitiesAndMembershipsMatched', 'restartPreservedBothDatabases',
                     'immudbSignedCaptureBoundaryVerified', 'olderThreeEventApplicationSnapshotRejected', 'ownedTargetAndVolumeRemoved'),
               false=('roleLoginOrPasswordsRecovered', 'sourceRootRecoveryRepeated', 'fullSystemRecoveryVerified', 'globalAtomicSnapshotClaimed'),
               status='PASS_CURRENT_APPLICATION_SIGNER_DB_RECOVERY_SET', sourceApplicationCommit=APP,
               sourceConfigurationCommit=CONFIG, databaseInventories=inv,
               dumpSha256=dict(fleetory=H, fleetory_signer=H), currentAuditEvents=4, immudbCheckpointTransactions=5)
    login = flags(true=('targetPasswordRotationVerified', 'restartAuthenticationVerified', 'originalDumpFilesUnmodified',
                        'explicitLoginCapabilitiesVerified', 'generatedTargetOwnerPasswordsRemainNoLogin',
                        'dataSchemaOwnersGrantsMembershipsUnchanged', 'ownedResourcesRemoved', 'ephemeralPasswordFilesRemoved'),
                  false=('sourcePasswordsRead', 'sourcePasswordRecoveryVerified', 'remoteTlsVerified', 'issuerOrSigningServicesStarted'),
                  schema='fleetory.target-login-acceptance.v1', status='PASS_TARGET_ONLY_LOGIN_SCRAM_ON_RETAINED_ACTUAL_DB_PAIR',
                  runtimeRoles=2, transport='private Unix socket SCRAM-SHA-256', sourceRestoreProofSha256=H,
                  sourceDumpSha256=copy.deepcopy(db['dumpSha256']), databaseInventoriesBefore=copy.deepcopy(inv),
                  databaseInventoriesAfter=copy.deepcopy(inv), successfulReadbackSessions=8, privilegeDenials=21,
                  permittedZeroRowInserts=4, wrongPasswordDenials=2, oldPasswordDenials=2, noLoginOwnerDenials=2, crossDatabaseDenials=2)
    audit = flags(true=('sourceStateUnchanged', 'restoredEventHashesAndRevisionsVerified', 'readOnlyPrincipalWriteDenied',
                        'restartPreservedStateAndReader', 'locallyRetainedCheckpointVerified',
                        'corruptedBackupRestoreRejected', 'ownedTargetAndVolumeRemoved'),
                  false=('checkpointIndependentApprovalClaimed', 'sourcePrivateSigningKeyTransferred', 'sourceRootRecoveryRepeated'),
                  schema='fleetory.pilot-immudb-restore.v1', status='PASS_ACTUAL_AUDIT_DB_OFFHOST_RESTORE_LIMITED_SCOPE',
                  database='fleetoryaudit', transactions=5, verifiedAuditEvents=4,
                  signedStateCryptographicVerification='PASS_EXISTING_OFFLINE_VERIFIER', checkpointSha256=H,
                  sourceApplicationCommit=APP, sourceConfigurationCommit=CONFIG)
    provider = flags(true=('verified', 'permissionConsumed'),
                     false=('standingAuthorizationRemaining', 'actualSignerServerAuthenticated', 'naturalExpiryWaited',
                            'sourceRootRecoveryRepeated', 'productionTokensIssued', 'originalPkiUsed'),
                     schema='fleetory.retained-provider-acceptance.v1', status='PASS_SINGLE_APPROVED_OPERATION_CONSUMED',
                     sourceProviderApiCalls=0, operationId='00000000-0000-4000-8000-000000000001', planSha256=H,
                     controllerResult=dict(operationId='00000000-0000-4000-8000-000000000001', scope='retained-provider', verified=True,
                                           cleanupVerified=True, snapshotReads=1, shareReads=1, shareSubmissions=4,
                                           sourceProviderApiCalls=0, productionTokensIssued=False, planSha256=H),
                     codeBoundAssertions=flags(true=('targetRootRevoked403BeforeSignature', 'probeRevoked403',
                                                     'nonCommandSignatureVerified', 'targetRemovalAndAbsenceVerified')))
    configuration = flags(true=('publicPinsMatchedBeforePrivateKeyReads', 'originalFilesUnchanged', 'ownedResourcesRemoved', 'secretCanariesAbsent'),
                          false=('servicesStarted', 'databaseOpened', 'providerBackendAuthenticationVerified', 'currentCallerAdmissionVerified',
                                 'transitKeyContinuityVerified', 'restoredIssuerActivated', 'policyGrantRenewed', 'sourcePasswordsRead',
                                 'sourceRootRecoveryRepeated', 'productionTokensIssued'),
                          schema='fleetory.original-native-configuration.v1', provider='File', originalFilesLoaded=13,
                          originalPublicFilesValidated=10, originalPrivateLeafKeysUsed=3, regeneratedCredentialSlots=4,
                          nativeBuildersAccepted=2, tcpListenersObserved=0)
    release = flags(false=('newSecretOrPkiCopy', 'newTokensIssued', 'sourceRestarted'),
                    schema='fleetory.release-input-review.v1',
                    archiveInventory=dict(archiveSha256=H, releaseSignatureVerified=False, sourceRevisionAuthenticated=False),
                    continuity=dict(schema='fleetory.release-payload-continuity.v1', archiveSha256=H, matchedFiles=67,
                                    codePayloadContinuityVerified=True, imageConfigurationVerified=False,
                                    releaseSignatureVerified=False, sourceRevisionAuthenticated=False))
    images = flags(true=('codeArchiveReloadExactImageIdsVerified',),
                   false=('applicationOrIssuerStarted', 'historicalSourceImageReproduced', 'releaseSignatureVerified',
                          'newSecretOrPkiCopied', 'sourceVpsAccessed'), schema='fleetory.recovery-code-images.v1',
                   additionalCost=0, contexts=dict(archiveSha256=H), images={})
    for role in sorted(policy.ROLES):
        identity = {'server': 'a', 'signer': 'b', 'keycloak': 'c'}[role] * 64
        entry = dict(baseRootfsPrefixMatches=True, metadata=dict(os='linux', arch='amd64', id='sha256:' + identity))
        if role != 'keycloak':
            entry['payloadFilesMatched'] = 56 if role == 'server' else 11
        images['images'][role] = entry
    identity = dict(schema='fleetory.keycloak-restore-evidence.v1', sourceTemporaryFilesRemoved=True,
                    restore=dict(schema='fleetory.keycloak-restore-verification.v1', verified=True,
                                 postRestoreHumanLoginVerified=False, independentCustodyVerified=False,
                                 dumpSha256=H, tableCount=101, totalRows=1645))
    return dict(database=db, login=login, audit=audit, identity=identity, provider=provider,
                configuration=configuration, release=release, images=images)


def pin_reports(root, reports, record):
    db = json.dumps(reports['database']).encode()
    reports['login']['sourceRestoreProofSha256'] = hashlib.sha256(db).hexdigest()
    for kind, name in policy.REPORTS.items():
        packet = json.dumps(reports[kind]).encode()
        (root / name).write_bytes(packet)
        record['reports'][kind] = dict(bytes=len(packet), sha256=hashlib.sha256(packet).hexdigest())
    packet = json.dumps(record).encode()
    (root / policy.MANIFEST).write_bytes(packet)
    return hashlib.sha256(packet).hexdigest()


class RecoveryCompositionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='fleetory-recovery-components-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.reports = synthetic_reports()
        self.record = dict(schema=policy.SCHEMA, sourceApplicationCommit=APP,
                           sourceConfigurationCommit=CONFIG, operatorRevision='c' * 40, reports={})
        self.pin()

    def pin(self):
        self.expected = pin_reports(self.root, self.reports, self.record)

    def verify(self):
        return policy.verify(self.root, self.expected)

    def cli(self, *extra):
        return subprocess.run([sys.executable, '-B', str(Path(policy.__file__)), '--expected-sha256', self.expected, *extra],
                              capture_output=True, timeout=5, cwd=self.root)

    def refused(self):
        with self.assertRaises(Exception):
            self.verify()

    def test_complete_matrix_preserves_partial_scopes_without_writes(self):
        before = {p.name: p.read_bytes() for p in self.root.iterdir()}
        result = self.cli()
        self.assertEqual(result.returncode, 0, result.stderr)
        value = json.loads(result.stdout)
        self.assertEqual(value['verifiedReports'], 8)
        self.assertEqual(value['components']['database']['auditEvents'], 4)
        self.assertEqual(value['components']['images']['payloadFiles'], 67)
        for key in ('newOperationsAuthorized', 'standingAuthorizationRemaining', 'fullSystemRecoveryVerified',
                    'phase7Complete', 'coordinatedCaptureWindowVerified', 'sourcePasswordsRecovered',
                    'sourceRevisionAuthenticated', 'postRestoreHumanLoginVerified', 'originalServiceStartupVerified',
                    'originalEventContentsReverified'):
            self.assertIs(value[key], False)
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.root.iterdir()})

    def test_metadata_references_are_never_followed(self):
        canary = self.root / 'unapproved-secret.json'
        canary.write_text('DO_NOT_OPEN_SYNTHETIC_PRIVATE_CANARY')
        for report in self.reports.values():
            report['backupPath'] = str(canary)
            report['proofPath'] = str(canary)
        self.pin()
        original = policy.files.inspect_file
        names = []

        def observed(root, descriptor, name, *args, **kwargs):
            names.append(name)
            return original(root, descriptor, name, *args, **kwargs)

        with patch.object(policy.files, 'inspect_file', side_effect=observed):
            result = self.verify()
        self.assertEqual(set(names), {policy.MANIFEST, *policy.REPORTS.values()})
        self.assertIs(result['referencesOpened'], False)

    def test_missing_or_renamed_report_refused(self):
        for name in policy.REPORTS.values():
            with self.subTest(name=name):
                path = self.root / name
                packet = path.read_bytes()
                path.unlink()
                self.refused()
                path.write_bytes(packet)

    def test_changed_bytes_and_stale_manifest_refused(self):
        path = self.root / policy.REPORTS['database']
        path.write_bytes(path.read_bytes().replace(b'"currentAuditEvents": 4', b'"currentAuditEvents": 3'))
        self.refused()

    def test_manifest_cannot_add_path_authority(self):
        for key, value in (('path', '../private.json'), ('root', '/'), ('sourceRootRecoveryAllowed', True)):
            with self.subTest(key=key):
                self.record['reports']['database'][key] = value
                packet = json.dumps(self.record).encode()
                (self.root / policy.MANIFEST).write_bytes(packet)
                self.expected = hashlib.sha256(packet).hexdigest()
                self.refused()
                del self.record['reports']['database'][key]

    def test_scope_and_cross_component_mutations_refused_even_with_new_pins(self):
        mutations = [
            ('database', ('currentAuditEvents',), 3), ('audit', ('verifiedAuditEvents',), 3),
            ('audit', ('transactions',), 6), ('audit', ('sourceApplicationCommit',), 'd' * 40),
            ('database', ('sourceConfigurationCommit',), 'd' * 40),
            ('database', ('roleLoginOrPasswordsRecovered',), True), ('database', ('globalAtomicSnapshotClaimed',), True),
            ('database', ('databaseInventories', 'fleetory', 'tableCount'), 3),
            ('login', ('sourcePasswordRecoveryVerified',), True), ('login', ('remoteTlsVerified',), True),
            ('login', ('databaseInventoriesAfter', 'fleetory', 'totalRows'), 3),
            ('login', ('sourceDumpSha256', 'fleetory'), 'd' * 64), ('login', ('privilegeDenials',), 20),
            ('identity', ('restore', 'postRestoreHumanLoginVerified'), True),
            ('identity', ('restore', 'verified'), 1),
            ('provider', ('permissionConsumed',), False), ('provider', ('standingAuthorizationRemaining',), True),
            ('provider', ('actualSignerServerAuthenticated',), True), ('provider', ('naturalExpiryWaited',), True),
            ('provider', ('controllerResult', 'operationId'), 'different-operation'),
            ('provider', ('controllerResult', 'sourceProviderApiCalls'), 1),
            ('configuration', ('servicesStarted',), True), ('configuration', ('databaseOpened',), True),
            ('configuration', ('providerBackendAuthenticationVerified',), True),
            ('configuration', ('nativeBuildersAccepted',), True),
            ('release', ('continuity', 'sourceRevisionAuthenticated'), True),
            ('release', ('continuity', 'archiveSha256'), 'd' * 64),
            ('images', ('contexts', 'archiveSha256'), 'd' * 64),
            ('images', ('images', 'server', 'payloadFilesMatched'), 55),
            ('images', ('images', 'signer', 'metadata', 'id'), 'sha256:' + H),
            ('images', ('historicalSourceImageReproduced',), True),
            ('images', ('applicationOrIssuerStarted',), True), ('audit', ('independentCustodyVerified',), True),
        ]
        baseline = copy.deepcopy(self.reports)
        for kind, path, value in mutations:
            with self.subTest(kind=kind, path=path):
                self.reports = copy.deepcopy(baseline)
                node = self.reports[kind]
                for key in path[:-1]:
                    node = node[key]
                node[path[-1]] = value
                self.pin()
                self.refused()

    def test_audit_count_cannot_disagree_with_rows_even_when_login_is_rebased(self):
        inventories = self.reports['database']['databaseInventories']
        inventories['fleetory']['tableCounts']['platform.audit_events'] = 3
        inventories['fleetory']['totalRows'] = 3
        for key in ('databaseInventoriesBefore', 'databaseInventoriesAfter'):
            self.reports['login'][key] = copy.deepcopy(inventories)
        self.pin()
        self.refused()

    def test_login_must_link_exact_database_report_pin(self):
        self.reports['login']['sourceRestoreProofSha256'] = 'd' * 64
        packet = json.dumps(self.reports['login']).encode()
        (self.root / policy.REPORTS['login']).write_bytes(packet)
        self.record['reports']['login'] = dict(bytes=len(packet), sha256=hashlib.sha256(packet).hexdigest())
        packet = json.dumps(self.record).encode()
        (self.root / policy.MANIFEST).write_bytes(packet)
        self.expected = hashlib.sha256(packet).hexdigest()
        self.refused()

    def test_consumed_provider_operation_requires_canonical_nonempty_uuid(self):
        for value in ('', None, 1, {}, '00000000-0000-0000-0000-000000000000', 'not-an-operation'):
            with self.subTest(value=value):
                self.reports['provider']['operationId'] = value
                self.reports['provider']['controllerResult']['operationId'] = value
                self.pin()
                self.refused()

    def test_claims_missing_fields_and_wrong_types_refused(self):
        for kind in policy.REPORTS:
            with self.subTest(kind=kind):
                baseline = copy.deepcopy(self.reports)
                self.reports[kind]['fullSystemRecoveryVerified'] = True
                self.pin()
                self.refused()
                self.reports = baseline

    def test_duplicate_json_unknown_schema_and_malformed_utf8_refused(self):
        for packet in (b'{"schema":"a","schema":"b"}', b'\xff', b'[]', b'{"value":NaN}', b'{}'):
            with self.subTest(packet=packet):
                (self.root / policy.MANIFEST).write_bytes(packet)
                self.expected = hashlib.sha256(packet).hexdigest()
                self.refused()

    def test_report_limits_checked_before_opening_any_report(self):
        self.record['reports']['database']['bytes'] = policy.MAX_REPORT + 1
        packet = json.dumps(self.record).encode()
        (self.root / policy.MANIFEST).write_bytes(packet)
        self.expected = hashlib.sha256(packet).hexdigest()
        original = policy.files.inspect_file
        with patch.object(policy.files, 'inspect_file', wraps=original) as reader:
            self.refused()
        self.assertEqual(reader.call_count, 1)

    def test_report_growth_and_same_size_corruption_refused_without_content(self):
        path = self.root / policy.REPORTS['configuration']
        path.write_bytes(b'X' * self.record['reports']['configuration']['bytes'])
        result = self.cli()
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, b'')
        self.assertNotIn(b'XXXXX', result.stderr)

    def test_hardlink_report_and_linked_root_refused(self):
        path = self.root / policy.REPORTS['database']
        alias = self.root / 'alias.json'
        os.link(path, alias)
        self.refused()

    def test_cli_has_no_root_or_manifest_path_switch(self):
        for args in (('--root', str(self.root)), ('--manifest', '../secret.json')):
            with self.subTest(args=args):
                self.assertEqual(self.cli(*args).returncode, 2)


if __name__ == '__main__':
    unittest.main()
