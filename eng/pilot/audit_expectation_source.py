"""Separate pinned PostgreSQL audit-export source. No native archive, restore or connection API."""
from dataclasses import dataclass
import ctypes
import json
import os
from pathlib import Path
import re
import sys

import audit_archive as archive
from audit_archive_input import CaptureArgumentParser
import fresh_server_pair as packet
import recovery_files as files
import retained_input_selection as selection

MAX_METADATA = 64 * 1024
MAX_BODY = 200 * 1024
MAX_EXPORT = 1024 * 1024
MAX_SNAPSHOT = 128 * 1024
CHECKPOINT_FIELDS = ('source artifactPath exportSha256 bytes snapshotCount eventCount lastReceiptSha256 '
    'portableVerification isolatedFileRestore checkpointVerified tamperedRestoreRejected '
    'independentCustodyVerified administratorTamperProof fullSystemRecoveryVerified verifiedAtUtc')


@dataclass(frozen=True)
class SourcePlan:
    artifact: selection.ArtifactReference
    absolute_path: str
    snapshots: int
    last_receipt_sha256: str
    metadata_pins: tuple


@dataclass(frozen=True)
class CapturedSource:
    snapshot: bytes
    nonce: str
    export_sha256: str
    export_bytes: int
    last_receipt_sha256: str
    metadata_pins: tuple

    def report(self):
        return dict(schema='fleetory.audit-expectation-source.v1', purpose='postgresql-event-value-expectations',
            nonce=self.nonce, metadataPins=dict(self.metadata_pins), exportSha256=self.export_sha256,
            exportBytes=self.export_bytes, snapshotSha256=packet.digest(self.snapshot), snapshotBytes=len(self.snapshot),
            lastReceiptSha256=self.last_receipt_sha256, events=4, pendingExportCount=0, verifiedArtifacts=1,
            frozenSnapshotBytes=True, sourceLineageMetadataPinsMatched=True, historicalRestoreChecksReused=True,
            otherArtifactsOpened=False, nativeSelectionBroadened=False, sourceOriginAuthenticated=False,
            sourceIndependenceAuthenticated=False, signaturesVerified=False, independentCustodyVerified=False,
            administratorTamperProof=False, executionAuthorized=False, fullSystemRecoveryVerified=False, phase7Complete=False)


def source_plan(metadata, expected_pins):
    packet.keys(metadata, 'manifest checkpoint')
    packet.keys(expected_pins, 'manifest checkpoint')
    pins = tuple((name, packet.hex_value(expected_pins[name])) for name in sorted(expected_pins))
    frozen = {}
    for name, value in metadata.items():
        packet.require(type(value) in (bytes, bytearray) and 0 < len(value) <= MAX_METADATA)
        frozen[name] = bytes(value)
    records = {}
    for name, pin in pins:
        packet.require(packet.digest(frozen[name]) == pin)
        records[name] = packet.strict_json(frozen[name], MAX_METADATA)
    entries = selection.manifest_entries(records['manifest'])
    entry = entries['audit-export']
    packet.require(re.fullmatch(r'audit-archive-[0-9]{8}T[0-9]{6}Z-[a-f0-9]{32}/export\.json', entry['path']) is not None)
    packet.require(64 <= entry['bytes'] <= MAX_EXPORT)
    checkpoint = records['checkpoint']
    packet.keys(checkpoint, CHECKPOINT_FIELDS)
    packet.require(checkpoint['bytes'] == entry['bytes'] and type(checkpoint['bytes']) is int)
    packet.require(packet.hex_value(checkpoint['exportSha256']) == entry['sha256'])
    packet.require(type(checkpoint['artifactPath']) is str and 0 < len(checkpoint['artifactPath']) <= 1024)
    packet.require(type(checkpoint['snapshotCount']) is int and 1 <= checkpoint['snapshotCount'] <= archive.MAX_ENTRIES)
    packet.require(type(checkpoint['eventCount']) is int and checkpoint['eventCount'] == 4)
    for name in ('portableVerification', 'isolatedFileRestore'):
        packet.require(checkpoint[name] == 'PASS')
    for name in ('checkpointVerified', 'tamperedRestoreRejected'):
        packet.require(checkpoint[name] is True)
    for name in ('independentCustodyVerified', 'administratorTamperProof', 'fullSystemRecoveryVerified'):
        packet.require(checkpoint[name] is False)
    packet.require(type(checkpoint['source']) is str and 0 < len(checkpoint['source']) <= 512)
    packet.require(type(checkpoint['verifiedAtUtc']) is str and 0 < len(checkpoint['verifiedAtUtc']) <= 64)
    return SourcePlan(selection.ArtifactReference(kind='audit-export', **entry), checkpoint['artifactPath'],
        checkpoint['snapshotCount'], packet.hex_value(checkpoint['lastReceiptSha256']), pins)


def extract(data, plan, nonce):
    # This validates the new consumer's source boundary; no old restore/crypto operation is repeated.
    identity = packet.identity(nonce)
    packet.require(type(data) in (bytes, bytearray) and 64 <= len(data) <= MAX_EXPORT and len(data) == plan.artifact.bytes)
    frozen = bytes(data)
    packet.require(packet.digest(frozen) == plan.artifact.sha256)
    value, last, events = archive.validate_export(frozen)
    packet.require(len(value['receipts']) == plan.snapshots and last == plan.last_receipt_sha256 and len(events) == 4)
    snapshot = value['snapshot']
    packet.require(type(snapshot['pendingExportCount']) is int and snapshot['pendingExportCount'] == 0)
    canonical = archive.canonical(snapshot)
    packet.require(0 < len(canonical) <= MAX_SNAPSHOT)
    return CapturedSource(canonical, identity, plan.artifact.sha256, len(frozen), last, plan.metadata_pins)


def windows_short_prefix(prefix):
    # prefix is exclusively an already checked operator-root ancestor, never metadata input.
    convert = ctypes.WinDLL('kernel32', use_last_error=True).GetShortPathNameW
    convert.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32]
    convert.restype = ctypes.c_uint32
    buffer = ctypes.create_unicode_buffer(32768)
    length = convert(str(prefix), buffer, len(buffer))
    packet.require(0 < length < len(buffer))
    return Path(buffer.value)


def bound_components(candidate, allowed):
    return len(candidate) == len(allowed) and all(os.path.normcase(part) in options for part, options in zip(candidate, allowed))


def metadata_path_matches(value, directory, relative):
    candidate = Path(value)
    if not candidate.is_absolute():
        return False
    allowed = []
    for index, part in enumerate(directory.parts):
        names = {os.path.normcase(part)}
        if os.name == 'nt':
            names.add(os.path.normcase(windows_short_prefix(Path(*directory.parts[:index + 1])).parts[-1]))
        allowed.append(names)
    allowed.extend({os.path.normcase(part)} for part in files.relative_parts(relative))
    return bound_components(candidate.parts, allowed)


def capture(root, metadata, expected_pins, nonce):
    identity = packet.identity(nonce)
    plan = source_plan(metadata, expected_pins)
    with files.rooted(root) as (directory, descriptor):
        # The metadata path is only compared, never resolved/opened as an independent path.
        packet.require(metadata_path_matches(plan.absolute_path, directory, plan.artifact.path))
        digest, size, data = files.inspect_file(directory, descriptor, plan.artifact.path, plan.artifact.bytes, retain=True)
    packet.require(size == plan.artifact.bytes and digest == plan.artifact.sha256)
    return extract(data, plan, identity)


def run():
    parser = CaptureArgumentParser(description=__doc__)
    parser.add_argument('--manifest-sha256', required=True)
    parser.add_argument('--checkpoint-sha256', required=True)
    parser.add_argument('--nonce', required=True)
    arguments = parser.parse_args()
    body = packet.strict_json(sys.stdin.buffer.read(MAX_BODY + 1), MAX_BODY)
    packet.keys(body, 'manifest checkpoint')
    metadata = {name: packet.decode(value, MAX_METADATA) for name, value in body.items()}
    return capture(Path.cwd(), metadata, dict(manifest=arguments.manifest_sha256,
        checkpoint=arguments.checkpoint_sha256), arguments.nonce).report()


if __name__ == '__main__':
    try:
        result = run()
    except Exception:
        print('Audit expectation source refused; no paths or event contents logged.', file=sys.stderr)
        sys.exit(1)
    print(json.dumps(result, sort_keys=True))
