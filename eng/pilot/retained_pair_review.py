"""Pinned retained-pair metadata reconciliation only; no restore or authorization API."""
import argparse
import json
import re
import sys

import fresh_server_pair as packet
import recovery_composition as composition

SCHEMA = 'fleetory.retained-pair-metadata-manifest.v1'
RESULT_SCHEMA = 'fleetory.retained-pair-metadata-review.v1'
KINDS = 'database audit capture observation'
MAX_REPORT = 64 * 1024
MAX_BODY = 384 * 1024
APPLICATION_COUNTS = {
    'core.__EFMigrationsHistory': 6, 'core.agent_certificate_recoveries': 0,
    'core.agent_certificates': 0, 'core.agent_enrollment_grants': 0,
    'core.agent_rotation_intents': 0, 'core.devices': 0,
    'platform.__EFMigrationsHistory': 9, 'platform.admin_certificate_registrations': 1,
    'platform.admin_certificate_revocations': 0, 'platform.audit_events': 4,
    'platform.audit_export_queue': 0, 'platform.authorization_assignments': 1,
    'platform.authorization_role_permissions': 1, 'platform.authorization_role_versions': 1,
    'platform.authorization_roles': 1, 'platform.authorization_scope_versions': 0,
    'platform.authorization_scopes': 0, 'platform.person_projections': 0,
}
SIGNER_COUNTS = {'signer.client_certificate_revocations': 0, 'signer.signing_rejections': 3,
                 'signer.signing_requests': 1, 'signer.signing_results': 1}


def require(condition):
    composition.archive.require(condition)


def same(left, right):
    # Canonical JSON preserves the type distinction between False and zero.
    require(composition.archive.canonical(left) == composition.archive.canonical(right))


def state_point(value):
    packet.keys(value, 'db txId txHash signature precommittedTxId precommittedTxHash')
    composition.expect(value, {'db': 'fleetoryaudit', 'txId': '5', 'precommittedTxId': '5'})
    digest = packet.decode(value['txHash'], 32)
    require(len(digest) == 32 and value['precommittedTxHash'] == value['txHash'])
    packet.keys(value['signature'], 'publicKey signature')
    public = packet.decode(value['signature']['publicKey'], 65)
    require(len(public) == 65 and public[0] == 4)
    signature = packet.decode(value['signature']['signature'], 80)
    require(8 <= len(signature) <= 72)
    # Shape and point continuity only. Existing signed-state verification is
    # reported by the pinned acceptance; this function does not repeat it.
    return value['db'], value['txId'], value['txHash'], value['signature']['publicKey']


def inventory_profile(value, counts):
    composition.expect(value, {'sequenceCount': 0, 'tableCount': len(counts), 'totalRows': sum(counts.values())})
    same(value['tableCounts'], counts)


def capture_review(capture, database, manifest):
    composition.expect(capture, {'schema': 'fleetory.coherent-database-capture.v1',
                                'observedStableCaptureWindow': True,
                                'sourceRolesPasswordsOrPoliciesModified': False,
                                'sourceRootRecoveryRepeated': False})
    composition.partial(capture)
    packet.keys(capture['databases'], 'fleetory fleetory_signer')
    for name in sorted(composition.DATABASES):
        entry = capture['databases'][name]
        composition.expect(entry, {'singleMvccSnapshotForDumpAndInventory': True, 'dumpContainsOwnersAndAcls': True})
        composition.integer(entry['dumpBytes'], 64)
        same(entry['inventory'], database['databaseInventories'][name])
        require(composition.digest(entry['dumpSha256']) == composition.digest(database['dumpSha256'][name]))
    require(capture['postgresImage'] == manifest['postgresImage'])
    before, after = state_point(capture['immudbBefore']), state_point(capture['immudbAfter'])
    require(before == after)
    return before


def event_metadata(events):
    require(type(events) is list and len(events) == 4)
    identities = set()
    for event in events:
        packet.keys(event, 'eventId key revision valueSha256')
        identity = packet.identity(event['eventId'])
        require(identity not in identities)
        identities.add(identity)
        key = ('fleetory/audit/v1/' + identity.replace('-', '')).encode('ascii')
        require(packet.decode(event['key'], 64) == key)
        composition.expect(event, {'revision': 1})
        composition.digest(event['valueSha256'])


def review(manifest_bytes, expected_pin, reports):
    """Consume only four caller-supplied pinned metadata packets; never open paths."""
    require(type(manifest_bytes) is bytes and packet.digest(manifest_bytes) == packet.hex_value(expected_pin))
    manifest = packet.strict_json(manifest_bytes, packet.MAX_MANIFEST)
    packet.keys(manifest, 'schema scope sourceApplicationCommit sourceConfigurationCommit postgresImage reports')
    composition.expect(manifest, {'schema': SCHEMA, 'scope': 'metadata-only-no-execution-grant'})
    for name in ('sourceApplicationCommit', 'sourceConfigurationCommit'):
        require(type(manifest[name]) is str and re.fullmatch('[a-f0-9]{40}', manifest[name]) is not None)
    require(manifest['postgresImage'] == 'postgres:18.6@sha256:74935e72241653ca55e0414067e6d8763aceb8a810eb51b452253ec3dcfc4336')
    packet.keys(reports, KINDS)
    packet.keys(manifest['reports'], KINDS)
    frozen = {}
    for name in KINDS.split():
        data = reports[name]
        require(type(data) in (bytes, bytearray) and 0 < len(data) <= MAX_REPORT)
        frozen[name] = bytes(data)
    records = {}
    for name, data in frozen.items():
        reference = manifest['reports'][name]
        packet.keys(reference, 'bytes sha256')
        composition.expect(reference, {'bytes': len(data)})
        require(packet.digest(data) == packet.hex_value(reference['sha256']))
        records[name] = packet.strict_json(data, MAX_REPORT)
        composition.partial(records[name])
    database, audit, capture, observation = (records[name] for name in KINDS.split())
    composition.database(database, manifest)
    composition.audit(audit, database, manifest)
    for name, counts in (('fleetory', APPLICATION_COUNTS), ('fleetory_signer', SIGNER_COUNTS)):
        inventory_profile(database['databaseInventories'][name], counts)
    point = capture_review(capture, database, manifest)
    composition.expect(observation, {'database': 'fleetoryaudit', 'transactionCount': 5,
                                    'sourceStateUnchanged': True, 'sourceProcessesUnrestarted': True,
                                    'sourcePrivateSigningKeyCopied': False, 'sourceRootRecoveryRepeated': False})
    # Observation schema and backup pins belong to the already accepted audit
    # report. No pathname in either report is followed.
    require(observation['schema'] == 'fleetory.pilot-immudb-capture.v1')
    require(state_point(observation['state']) == point)
    require(composition.digest(observation['backupSha256']) == composition.digest(audit['backupSha256']))
    composition.expect(observation, {'backupBytes': composition.integer(audit['backupBytes'], 64)})
    event_metadata(observation['knownEvents'])
    return dict(schema=RESULT_SCHEMA, manifestSha256=expected_pin, verifiedMetadataOnly=True,
                reports=4, applicationTables=18, applicationRows=24, signerTables=4, signerRows=5,
                auditEvents=4, auditTransactions=5, revisionOneEventBindings=4,
                nativeV1Equivalent=False, originalInventoryV2Recomputed=False,
                loginCapabilitiesCoveredByV2=False, sourcePasswordsRecovered=False,
                priorSignedStateVerificationReported=True, cryptographicVerificationRepeated=False,
                perEventTransactionBindingsVerified=False, completeAuditKeysetVerified=False,
                releaseSourceRevisionAuthenticated=False, executionAuthorized=False,
                originalServiceRecoveryVerified=False, fullSystemRecoveryVerified=False, phase7Complete=False)


def run():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pin', required=True)
    arguments = parser.parse_args()
    body = packet.strict_json(sys.stdin.buffer.read(MAX_BODY + 1), MAX_BODY)
    packet.keys(body, 'manifestBase64 reports')
    packet.keys(body['reports'], KINDS)
    return review(packet.decode(body['manifestBase64'], packet.MAX_MANIFEST), arguments.pin,
                  {name: packet.decode(value, MAX_REPORT) for name, value in body['reports'].items()})


if __name__ == '__main__':
    try:
        result = run()
    except Exception:
        print('Retained pair metadata refused; no report contents logged.', file=sys.stderr)
        sys.exit(1)
    print(json.dumps(result, sort_keys=True))
