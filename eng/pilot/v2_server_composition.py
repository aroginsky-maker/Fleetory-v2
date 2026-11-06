"""Generated three-archive composition only; no file, credential or execution API."""
import argparse
import base64
from dataclasses import dataclass
import json
import sys

import audit_history_inputs as history
import fresh_server_pair as packet
from retained_pair_review import APPLICATION_COUNTS, SIGNER_COUNTS

SCHEMA = 'fleetory.generated-v2-server-composition.v1'
MAX_BODY = 36 * 1024 * 1024
COUNTS = {'fleetory': APPLICATION_COUNTS, 'fleetory_signer': SIGNER_COUNTS}


class CompositionMismatch(ValueError):
    """Only valid native observations with different data/security/identity."""


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def observation(value):
    packet.keys(value, 'postgres audit')
    history.point(value['audit'])
    packet.keys(value['postgres'], 'fleetory fleetory_signer')
    for database, counts in COUNTS.items():
        pg_observation(value['postgres'][database], database, counts)


def pg_observation(pg, database, counts):
    packet.keys(pg, 'schema inventory additionalSecuritySha256 generatedRolePolicyAccepted nativeMeasurementAuthenticated originalInputsVerified executionAuthorized fullSystemRecoveryVerified')
    packet.require(pg['schema'] == 'fleetory.native-pg-v2-readback.v1' and type(pg['generatedRolePolicyAccepted']) is bool)
    for name in ('nativeMeasurementAuthenticated', 'originalInputsVerified', 'executionAuthorized', 'fullSystemRecoveryVerified'):
        packet.require(pg[name] is False)
    packet.hex_value(pg['additionalSecuritySha256'])
    inventory_observation(pg['inventory'], database, counts)


def inventory_observation(inv, database, counts):
    packet.keys(inv, 'algorithm database inventorySha256 securitySha256 tableCount totalRows sequenceCount tableCounts audit rolePasswordsAndLoginRecoveryVerified globalAtomicSnapshotClaimed')
    packet.require(inv['algorithm'] == 'fleetory.application-signer-recovery.v2' and inv['database'] == database)
    for name in ('inventorySha256', 'securitySha256'):
        packet.hex_value(inv[name])
    packet.require(type(inv['tableCounts']) is dict and set(inv['tableCounts']) == set(counts))
    packet.require(all(type(n) is int and 0 <= n <= 1000000 for n in inv['tableCounts'].values()))
    for name, expected in dict(tableCount=len(counts), totalRows=sum(inv['tableCounts'].values()), sequenceCount=0).items():
        packet.require(type(inv[name]) is int and inv[name] == expected)
    packet.require(inv['rolePasswordsAndLoginRecoveryVerified'] is False and inv['globalAtomicSnapshotClaimed'] is False)
    if database == 'fleetory':
        audit = inv['audit']
        packet.keys(audit, 'snapshotSha256 events pendingExportCount')
        packet.hex_value(audit['snapshotSha256'])
        packet.require(type(audit['events']) is int and type(audit['pendingExportCount']) is int)
        packet.require(audit['events'] == 4 and audit['pendingExportCount'] == 0)
    else:
        packet.require(inv['audit'] is None)


def accepted_source(value):
    observation(value)
    for database, counts in COUNTS.items():
        pg = value['postgres'][database]
        packet.require(pg['generatedRolePolicyAccepted'] is True and pg['inventory']['tableCounts'] == counts)


def compare(source, target):
    accepted_source(source)
    observation(target)
    same_pg = canonical(source['postgres']) == canonical(target['postgres'])
    a, b = source['audit'], target['audit']
    same_audit = all(type(v) is type(b[k]) and v == b[k] for k, v in a.items() if k != 'keyFingerprint')
    if not same_pg or not same_audit or a['keyFingerprint'] == b['keyFingerprint']:
        raise CompositionMismatch('Generated composition mismatch.')


@dataclass(frozen=True)
class CapturedComposition:
    application: bytes
    signer: bytes
    audit: bytes


def admit(manifest_bytes, pin, fixture, artifacts):
    packet.require(type(manifest_bytes) is bytes and 0 < len(manifest_bytes) <= packet.MAX_MANIFEST)
    packet.require(packet.hex_value(pin) == packet.digest(manifest_bytes))
    manifest = packet.strict_json(manifest_bytes, packet.MAX_MANIFEST)
    packet.keys(manifest, 'schema scope fixture probeSha256 images sourceContainers point capture artifacts')
    packet.require(manifest['schema'] == SCHEMA and manifest['scope'] == history.SCOPE and manifest['fixture'] == packet.identity(fixture))
    packet.hex_value(manifest['probeSha256'])
    packet.keys(manifest['images'], 'postgres audit')
    for image in manifest['images'].values():
        packet.require(type(image) is str and image.startswith('sha256:'))
        packet.hex_value(image[7:])
    packet.keys(manifest['sourceContainers'], 'postgres audit')
    for container in manifest['sourceContainers'].values():
        packet.hex_value(container)
    packet.require(len(set(manifest['sourceContainers'].values())) == 2)
    accepted_source(manifest['point'])
    packet.keys(manifest['capture'], 'before after')
    for point in manifest['capture'].values():
        accepted_source(point)
        packet.require(canonical(point) == canonical(manifest['point']))
    packet.keys(artifacts, 'application signer audit')
    packet.keys(manifest['artifacts'], 'application signer audit')
    captured = {}
    for name, blob in artifacts.items():
        packet.require(type(blob) in (bytes, bytearray) and 64 <= len(blob) <= packet.MAX_ARTIFACT)
        frozen = bytes(blob)
        packet.require(frozen.startswith(b'IMMUBACKUP' if name == 'audit' else b'PGDMP'))
        record = manifest['artifacts'][name]
        packet.keys(record, 'bytes sha256')
        packet.require(type(record['bytes']) is int and record['bytes'] == len(frozen))
        packet.require(packet.hex_value(record['sha256']) == packet.digest(frozen))
        captured[name] = frozen
    return CapturedComposition(**captured)


def run():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('capture', 'compare'))
    parser.add_argument('--pin')
    parser.add_argument('--fixture')
    args = parser.parse_args()
    body = packet.strict_json(sys.stdin.buffer.read(MAX_BODY + 1), MAX_BODY)
    if args.mode == 'compare':
        packet.require(args.pin is None and args.fixture is None)
        packet.keys(body, 'source target')
        compare(body['source'], body['target'])
        return dict(category='matching-generated-composition', executionAuthorized=False, signaturesVerified=False)
    packet.keys(body, 'manifestBase64 applicationBase64 signerBase64 auditBase64')
    artifacts = {name: packet.decode(body[name + 'Base64'], packet.MAX_ARTIFACT) for name in ('application', 'signer', 'audit')}
    captured = admit(packet.decode(body['manifestBase64'], packet.MAX_MANIFEST), args.pin, args.fixture, artifacts)
    return dict(schema=SCHEMA, generatedOnly=True, executionAuthorized=False, signaturesVerified=False,
                originalInputsVerified=False, fullSystemRecoveryVerified=False,
                **{name + 'Base64': base64.b64encode(getattr(captured, name)).decode() for name in artifacts})


if __name__ == '__main__':
    try:
        result = run()
    except CompositionMismatch:
        print(json.dumps(dict(category='generated-composition-mismatch', executionAuthorized=False)))
        sys.exit(1)
    except Exception:
        print('Generated v2 composition refused; no contents logged.', file=sys.stderr)
        sys.exit(2)
    # Payload-bearing private pipe: caller must not log capture output.
    print(json.dumps(result))
