"""Generated audit-history capture only; no file/endpoint/credential/approval API."""
import argparse
import base64
from dataclasses import dataclass
import json
import sys

import fresh_server_pair as packet

SCHEMA = 'fleetory.generated-audit-history-capture.v1'
SCOPE = 'generated-only-no-original-approval'
MAX_BODY = 12 * 1024 * 1024


def point(value):
    packet.keys(value, 'database tx txHash keyFingerprint historySha256 events keys transactions')
    packet.require(value['database'] == 'fleetoryaudit')
    for name, expected in dict(tx=5, events=4, keys=5, transactions=5).items():
        packet.require(type(value[name]) is int and value[name] == expected)
    for name in ('txHash', 'keyFingerprint'):
        packet.hex_value(value[name], upper=True)
    packet.hex_value(value['historySha256'])
    return value


def same_data_distinct_signers(source, target):
    """Caller must verify both signatures/public pins before this comparison."""
    point(source)
    point(target)
    packet.require(source['keyFingerprint'] != target['keyFingerprint'])
    for name in source.keys() - {'keyFingerprint'}:
        packet.require(type(source[name]) is type(target[name]) and source[name] == target[name])


@dataclass(frozen=True)
class CapturedHistory:
    backup: bytes
    manifest_sha256: str
    fixture: str


def admit(manifest_bytes, expected_pin, expected_fixture, backup):
    packet.require(type(manifest_bytes) is bytes and 0 < len(manifest_bytes) <= packet.MAX_MANIFEST)
    packet.require(packet.digest(manifest_bytes) == packet.hex_value(expected_pin))
    packet.identity(expected_fixture)
    packet.require(type(backup) in (bytes, bytearray) and 64 <= len(backup) <= packet.MAX_ARTIFACT)
    captured = bytes(backup)
    packet.require(captured.startswith(b'IMMUBACKUP'))
    manifest = packet.strict_json(manifest_bytes, packet.MAX_MANIFEST)
    packet.keys(manifest, 'schema scope fixture probeSha256 imageId sourceContainer point capture artifact')
    packet.require(manifest['schema'] == SCHEMA and manifest['scope'] == SCOPE and manifest['fixture'] == expected_fixture)
    packet.hex_value(manifest['probeSha256'])
    packet.hex_value(manifest['sourceContainer'])
    image = manifest['imageId']
    packet.require(type(image) is str and image.startswith('sha256:'))
    packet.hex_value(image[7:])
    point(manifest['point'])
    packet.keys(manifest['capture'], 'before after')
    expected = packet.digest(json.dumps(manifest['point'], sort_keys=True, separators=(',', ':')).encode())
    for value in manifest['capture'].values():
        point(value)
        packet.require(packet.digest(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()) == expected)
    packet.keys(manifest['artifact'], 'bytes sha256')
    packet.require(type(manifest['artifact']['bytes']) is int and manifest['artifact']['bytes'] == len(captured))
    packet.require(packet.hex_value(manifest['artifact']['sha256']) == packet.digest(captured))
    return CapturedHistory(captured, expected_pin, expected_fixture)


def run():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', nargs='?', choices=('capture', 'compare'), default='capture')
    parser.add_argument('--pin')
    parser.add_argument('--fixture')
    arguments = parser.parse_args()
    body = packet.strict_json(sys.stdin.buffer.read(MAX_BODY + 1), MAX_BODY)
    if arguments.mode == 'compare':
        packet.require(arguments.pin is None and arguments.fixture is None)
        packet.keys(body, 'source target')
        same_data_distinct_signers(body['source'], body['target'])
        return dict(schema=SCHEMA, sameDataDistinctSigners=True, signaturesVerified=False,
                    originalKeyContinuityVerified=False, executionAuthorized=False)
    packet.require(arguments.pin is not None and arguments.fixture is not None)
    packet.keys(body, 'manifestBase64 backupBase64')
    result = admit(packet.decode(body['manifestBase64'], packet.MAX_MANIFEST), arguments.pin, arguments.fixture,
                   packet.decode(body['backupBase64'], packet.MAX_ARTIFACT))
    return dict(schema=SCHEMA, fixture=result.fixture, manifestSha256=result.manifest_sha256,
                backupBase64=base64.b64encode(result.backup).decode(), generatedOnly=True,
                nativeChecksumVerified=False, signaturesVerified=False, executionAuthorized=False,
                originalKeyContinuityVerified=False, fullSystemRecoveryVerified=False)


if __name__ == '__main__':
    try:
        result = run()
    except Exception:
        print('Audit history capture refused; no packet contents logged.', file=sys.stderr)
        sys.exit(1)
    # Payload-bearing private pipe; the owning native process must not log it.
    print(json.dumps(result))
