"""Audit-only byte capture from a pinned native selection. No restore or execution API."""
import argparse
from dataclasses import dataclass
import json
from pathlib import Path
import sys

import fresh_server_pair as packet
import recovery_files as files
import retained_input_selection as selection

MAX_SELECTION = 16 * 1024
MAX_CAPTURE = packet.MAX_ARTIFACT


class CaptureArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        raise packet.PairError('Capture arguments refused.')


@dataclass(frozen=True)
class CapturedAudit:
    data: bytes
    selection_sha256: str
    artifact_sha256: str

    def report(self):
        return dict(schema='fleetory.audit-archive-byte-capture.v1', kind='audit-immudb',
            verifiedArtifacts=1, verifiedBytes=len(self.data), selectionSha256=self.selection_sha256,
            artifactSha256=self.artifact_sha256, frozenBytes=True, ordinaryFileAndDigestVerified=True,
            otherSelectedArtifactsOpened=False, nativeChecksumVerified=False, nativeObservationPerformed=False,
            independentEventExpectationsVerified=False, originalKeyContinuityVerified=False,
            signaturesVerified=False, executionAuthorized=False, fullSystemRecoveryVerified=False, phase7Complete=False)


def audit_reference(selection_bytes, expected_pin):
    pin = packet.hex_value(expected_pin)
    packet.require(type(selection_bytes) in (bytes, bytearray) and 0 < len(selection_bytes) <= MAX_SELECTION)
    frozen = bytes(selection_bytes)
    packet.require(packet.digest(frozen) == pin)
    record = packet.strict_json(frozen, MAX_SELECTION)
    packet.require(type(record) is dict)
    packet.require(type(record.get('selected')) is list and len(record['selected']) == 3)
    references, paths, digests = [], set(), set()
    for kind, item in zip(selection.NATIVE, record['selected']):
        packet.keys(item, 'kind path bytes sha256')
        packet.require(item['kind'] == kind)
        path = '/'.join(files.relative_parts(item['path'])).casefold()
        digest = packet.hex_value(item['sha256'])
        packet.require(type(item['bytes']) is int and 0 < item['bytes'] <= files.MAX_ARTIFACT)
        packet.require(path not in paths and digest not in digests)
        paths.add(path)
        digests.add(digest)
        references.append(selection.ArtifactReference(**item))
    entries = {item.kind: dict(path=item.path) for item in references}
    selection.native_path_profile(entries)
    pins = record.get('metadataPins')
    packet.keys(pins, 'manifest database audit')
    metadata = tuple((name, packet.hex_value(pins[name])) for name in sorted(pins))
    # Reconstruct the exact selector report, including all false authority/scope flags.
    expected = selection.Selection(tuple(references), metadata).report()
    packet.require(json.dumps(record, sort_keys=True, allow_nan=False) ==
                   json.dumps(expected, sort_keys=True, allow_nan=False))
    audit = references[2]
    packet.require(64 <= audit.bytes <= MAX_CAPTURE)
    return audit, pin


def capture(root, selection_bytes, expected_pin):
    audit, pin = audit_reference(selection_bytes, expected_pin)
    # root belongs to the invoking operator, never to the supplied selection.
    # Reuse actual-open guards; never invoke the broad six-component verifier.
    with files.rooted(root) as (directory, root_fd):
        digest, size, data = files.inspect_file(directory, root_fd, audit.path, audit.bytes, retain=True)
    packet.require(size == audit.bytes and digest == audit.sha256 and len(data) == size)
    packet.require(data.startswith(b'IMMUBACKUP'))
    return CapturedAudit(data, pin, digest)


def run():
    parser = CaptureArgumentParser(description=__doc__)
    parser.add_argument('--expected-selection-sha256', required=True)
    arguments = parser.parse_args()
    # stdin is bounded selection metadata, not a path or a raw archive packet.
    data = sys.stdin.buffer.read(MAX_SELECTION + 1)
    return capture(Path.cwd(), data, arguments.expected_selection_sha256).report()


if __name__ == '__main__':
    try:
        result = run()
    except Exception:
        print('Audit archive byte capture refused; no paths or contents logged.', file=sys.stderr)
        sys.exit(1)
    # The command emits a sanitized receipt; captured archive bytes stay in memory.
    print(json.dumps(result, sort_keys=True))
