"""Fresh native-pair byte admission, not an original recovery/approval format. No file input API."""
import argparse
import base64
from dataclasses import dataclass
import hashlib
import json
import re
import sys
import uuid

SCHEMA = 'fleetory.fresh-native-server-pair.v1'
SCOPE = 'generated-only-no-original-approval'
MAX_ARTIFACT = 8 * 1024 * 1024
MAX_PACKET = 24 * 1024 * 1024
MAX_MANIFEST = 16384


class PairError(ValueError):
    """Closed and sanitized input refusal."""


def require(condition):
    if not condition:
        raise PairError('Fresh native pair refused.')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def keys(value, names):
    require(type(value) is dict and set(value) == set(names.split()))


def hex_value(value, upper=False):
    require(type(value) is str and re.fullmatch('[A-F0-9]{64}' if upper else '[a-f0-9]{64}', value) is not None)
    return value


def identity(value):
    require(type(value) is str and str(uuid.UUID(value)) == value and value != str(uuid.UUID(int=0)))
    return value


def strict_json(data, bound):
    require(type(data) is bytes and 0 < len(data) <= bound)

    def pairs(items):
        result = {}
        for name, value in items:
            require(name not in result)
            result[name] = value
        return result

    def invalid_number(_):
        raise PairError('Nonfinite JSON refused.')

    return json.loads(data.decode('utf-8', errors='strict'), object_pairs_hook=pairs, parse_constant=invalid_number)


@dataclass(frozen=True)
class CapturedPair:
    postgres: bytes
    audit: bytes
    manifest_sha256: str
    fixture: str

    def packet(self, name):
        require(name in ('postgres', 'audit'))
        return self.postgres if name == 'postgres' else self.audit


def admit(manifest_bytes, expected_pin, expected_fixture, postgres, audit):
    hex_value(expected_pin)
    identity(expected_fixture)
    # Freeze before comparing, so a mutable caller cannot alter a checked packet.
    require(type(postgres) in (bytes, bytearray) and type(audit) in (bytes, bytearray))
    require(64 <= len(postgres) <= MAX_ARTIFACT and 64 <= len(audit) <= MAX_ARTIFACT)
    pg_bytes, audit_bytes = bytes(postgres), bytes(audit)
    require(pg_bytes.startswith(b'PGDMP') and audit_bytes.startswith(b'IMMUBACKUP'))
    manifest = strict_json(manifest_bytes, MAX_MANIFEST)
    require(digest(manifest_bytes) == expected_pin)
    keys(manifest, 'schema scope fixture probeSha256 images sourceContainers postgresInventorySha256 point capture artifacts')
    require(manifest['schema'] == SCHEMA and manifest['scope'] == SCOPE and identity(manifest['fixture']) == expected_fixture)
    hex_value(manifest['probeSha256'])
    hex_value(manifest['postgresInventorySha256'])
    keys(manifest['images'], 'postgres audit')
    for image in manifest['images'].values():
        require(type(image) is str and image.startswith('sha256:'))
        hex_value(image[7:])
    keys(manifest['sourceContainers'], 'postgres audit')
    for container in manifest['sourceContainers'].values():
        hex_value(container)
    require(len(set(manifest['sourceContainers'].values())) == 2)
    point = manifest['point']
    keys(point, 'eventsSha256 auditTx auditHash auditKeyFingerprint tables rows queueRows events fields')
    hex_value(point['eventsSha256'])
    hex_value(point['auditHash'], upper=True)
    hex_value(point['auditKeyFingerprint'], upper=True)
    for name, expected in dict(auditTx=4, tables=18, rows=23, queueRows=0, events=4, fields=10).items():
        require(type(point[name]) is int and point[name] == expected)
    keys(manifest['capture'], 'before after')
    canonical = lambda value: json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)
    require(canonical(manifest['capture']['before']) == canonical(point) == canonical(manifest['capture']['after']))
    keys(manifest['artifacts'], 'postgres audit')
    for name, packet in (('postgres', pg_bytes), ('audit', audit_bytes)):
        artifact = manifest['artifacts'][name]
        keys(artifact, 'bytes sha256')
        require(type(artifact['bytes']) is int and artifact['bytes'] == len(packet))
        require(hex_value(artifact['sha256']) == digest(packet))
    return CapturedPair(pg_bytes, audit_bytes, expected_pin, expected_fixture)


def decode(value, maximum):
    require(type(value) is str and len(value) <= 4 * ((maximum + 2) // 3))
    result = base64.b64decode(value, validate=True)
    require(0 < len(result) <= maximum and base64.b64encode(result).decode() == value)
    return result


def run():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pin', required=True)
    parser.add_argument('--fixture', required=True)
    arguments = parser.parse_args()
    body = strict_json(sys.stdin.buffer.read(MAX_PACKET + 1), MAX_PACKET)
    keys(body, 'manifestBase64 postgresBase64 auditBase64')
    pair = admit(decode(body['manifestBase64'], MAX_MANIFEST), arguments.pin, arguments.fixture,
                 decode(body['postgresBase64'], MAX_ARTIFACT), decode(body['auditBase64'], MAX_ARTIFACT))
    return dict(schema=SCHEMA, fixture=pair.fixture, manifestSha256=pair.manifest_sha256,
                postgresBase64=base64.b64encode(pair.packet('postgres')).decode(),
                auditBase64=base64.b64encode(pair.packet('audit')).decode(), generatedOnly=True,
                externalApprovalVerified=False, originalInventoryV2Verified=False, fullSystemRecoveryVerified=False)


if __name__ == '__main__':
    try:
        result = run()
    except Exception:
        print('Fresh native pair refused; no packet contents logged.', file=sys.stderr)
        sys.exit(1)
    # Payload-bearing private pipe. The owning bounded process must never log it.
    print(json.dumps(result))
