"""Capture four existing retained data inputs; no restore, service or secret-provider API."""
from dataclasses import dataclass, field
import json
from pathlib import Path
import sys

if __name__ == '__main__':
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import audit_archive_input as audit
import audit_expectation_source as expectations
import retained_input_selection as selection
from historical import postgres_pair_capture as postgres

packet, files = postgres.packet, postgres.files
KINDS = (*postgres.KINDS, 'audit-immudb', 'audit-export')
MAX_TOTAL = postgres.MAX_PAIR
MAX_BODY = selection.MAX_SELECTION * 2 + expectations.MAX_BODY


@dataclass(frozen=True)
class CapturedServiceInputs:
    postgres: object = field(repr=False)
    audit: object = field(repr=False)
    expectations: object = field(repr=False)
    nonce: str
    input_bytes: int
    artifact_pins: tuple

    def packet(self, kind):
        packet.require(type(kind) is str and kind in KINDS)
        if kind in postgres.KINDS:
            return self.postgres.packet(kind)
        return self.audit.data if kind == 'audit-immudb' else self.expectations.snapshot

    def report(self):
        return dict(schema='fleetory.retained-service-inputs.v1', nonce=self.nonce,
            verifiedArtifacts=4, verifiedInputBytes=self.input_bytes, artifactPins=dict(self.artifact_pins),
            selectionSha256=self.postgres.selection_sha256,
            metadataPins=dict(self.expectations.metadata_pins), frozenBytes=True,
            exportPacketIsCanonicalEventSnapshot=True, otherArtifactsOpened=False,
            nativeRestorePerformed=False, databaseInventoryVerified=False,
            originalServiceStarted=False, providerOrIdentityRead=False,
            credentialsRecovered=False, signaturesVerified=False, executionAuthorized=False,
            independentCustodyVerified=False, fullSystemRecoveryVerified=False, phase7Complete=False)


def _metadata(raw, expected_pin, metadata, pins, nonce):
    # Freeze every caller-owned packet and pin before parsing or opening an artifact.
    packet.require(type(raw) in (bytes, bytearray) and 0 < len(raw) <= selection.MAX_SELECTION)
    packet.keys(metadata, 'manifest checkpoint')
    packet.keys(pins, 'manifest checkpoint')
    frozen = {}
    frozen_pin = packet.hex_value(expected_pin)
    frozen_pins = {name: packet.hex_value(pins[name]) for name in ('manifest', 'checkpoint')}
    for name in ('manifest', 'checkpoint'):
        value = metadata[name]
        packet.require(type(value) in (bytes, bytearray) and 0 < len(value) <= expectations.MAX_METADATA)
        frozen[name] = bytes(value)
    raw = bytes(raw)
    identity = packet.identity(nonce)
    selected, pin = selection.decode_report(raw, frozen_pin)
    source = expectations.source_plan(frozen, frozen_pins)
    packet.require(dict(selected.metadata_pins)['manifest'] == frozen_pins['manifest'])
    manifest = packet.strict_json(frozen['manifest'], expectations.MAX_METADATA)
    entries = selection.manifest_entries(manifest)
    for ref in selected.artifacts:
        packet.require(dict(path=ref.path, bytes=ref.bytes, sha256=ref.sha256) == entries[ref.kind])
    audit.audit_reference(raw, pin)
    packet.require(sum(ref.bytes for ref in selected.artifacts[:2]) <= postgres.MAX_PAIR)
    total = sum(ref.bytes for ref in selected.artifacts) + source.artifact.bytes
    packet.require(total <= MAX_TOTAL)
    digests = [ref.sha256 for ref in selected.artifacts] + [source.artifact.sha256]
    packet.require(len(set(digests)) == 4)
    return raw, pin, frozen, frozen_pins, identity, source, total


def capture(root, selection_bytes, selection_pin, export_metadata, export_pins, nonce, *, maximum_input=MAX_TOTAL):
    raw, pin, metadata, pins, identity, source, total = _metadata(
        selection_bytes, selection_pin, export_metadata, export_pins, nonce)
    packet.require(type(maximum_input) is int and 0 < maximum_input <= MAX_TOTAL and total <= maximum_input)
    # This path is only compared, never opened independently from the owner root.
    with files.rooted(root) as (directory, _):
        packet.require(expectations.metadata_path_matches(source.absolute_path, directory, source.artifact.path))
    pg = postgres.capture(root, raw, pin)
    native = audit.capture(root, raw, pin)
    expected = expectations.capture(root, metadata, pins, identity)
    artifact_pins = (*pg.artifact_pins, ('audit-immudb', native.artifact_sha256),
                     ('audit-export', expected.export_sha256))
    return CapturedServiceInputs(pg, native, expected, identity, total, artifact_pins)


def read_capture(*, maximum_input=MAX_TOTAL):
    parser = audit.CaptureArgumentParser(description=__doc__)
    for name in ('selection-sha256', 'manifest-sha256', 'checkpoint-sha256', 'nonce'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    body = packet.strict_json(sys.stdin.buffer.read(MAX_BODY + 1), MAX_BODY)
    packet.keys(body, 'selection manifest checkpoint')
    selected = packet.decode(body['selection'], selection.MAX_SELECTION)
    metadata = {name: packet.decode(body[name], expectations.MAX_METADATA) for name in ('manifest', 'checkpoint')}
    return capture(Path.cwd(), selected, args.selection_sha256, metadata,
        dict(manifest=args.manifest_sha256, checkpoint=args.checkpoint_sha256), args.nonce, maximum_input=maximum_input)


def run():
    return read_capture().report()


if __name__ == '__main__':
    try:
        result = run()
    except Exception:
        print('Retained service input capture refused; no paths or contents logged.', file=sys.stderr)
        sys.exit(1)
    print(json.dumps(result, sort_keys=True))
