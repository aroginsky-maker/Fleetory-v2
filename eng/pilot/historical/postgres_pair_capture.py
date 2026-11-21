"""Capture only the selected coherent PostgreSQL pair; no restore or execution authority."""
from dataclasses import dataclass, field
import json
from pathlib import Path
import sys

if __name__ == '__main__':
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from audit_archive_input import CaptureArgumentParser
import fresh_server_pair as packet
import recovery_files as files
import retained_input_selection as selection

KINDS = ('application-postgres', 'signer-postgres')
MAX_PAIR = 64 * 1024 * 1024


@dataclass(frozen=True)
class CapturedPostgresPair:
    application: bytes = field(repr=False)
    signer: bytes = field(repr=False)
    selection_sha256: str
    artifact_pins: tuple

    def packet(self, kind):
        packet.require(type(kind) is str and kind in KINDS)
        return self.application if kind == KINDS[0] else self.signer

    def report(self):
        return dict(schema='fleetory.postgres-pair-byte-capture.v1', verifiedArtifacts=2,
            verifiedBytes=len(self.application) + len(self.signer), selectionSha256=self.selection_sha256,
            artifactPins=dict(self.artifact_pins), frozenBytes=True, ordinaryFilesAndDigestsVerified=True,
            customFormatMagicMatched=True, otherArtifactsOpened=False, nativeChecksumVerified=False,
            nativeRestorePerformed=False, databaseInventoryVerified=False, credentialsRecovered=False,
            signaturesVerified=False, executionAuthorized=False, fullSystemRecoveryVerified=False, phase7Complete=False)


def capture(root, selection_bytes, expected_pin):
    selected, pin = selection.decode_report(selection_bytes, expected_pin)
    references = selected.artifacts[:2]
    packet.require(tuple(ref.kind for ref in references) == KINDS and sum(ref.bytes for ref in references) <= MAX_PAIR)
    captured, pins = [], []
    # The invoking owner supplies this root; selection metadata cannot replace it.
    # All references and bounds are validated before opening either file.
    with files.rooted(root) as (directory, descriptor):
        for ref in references:
            digest, size, data = files.inspect_file(directory, descriptor, ref.path, ref.bytes, retain=True)
            packet.require(digest == ref.sha256 and size == ref.bytes and len(data) == size)
            packet.require(data.startswith(b'PGDMP'))
            captured.append(data)
            pins.append((ref.kind, digest))
    return CapturedPostgresPair(captured[0], captured[1], pin, tuple(pins))


def run():
    parser = CaptureArgumentParser(description=__doc__)
    parser.add_argument('--expected-selection-sha256', required=True)
    arguments = parser.parse_args()
    raw = sys.stdin.buffer.read(selection.MAX_SELECTION + 1)
    return capture(Path.cwd(), raw, arguments.expected_selection_sha256).report()


if __name__ == '__main__':
    try:
        result = run()
    except Exception:
        print('PostgreSQL pair byte capture refused; no paths or contents logged.', file=sys.stderr)
        sys.exit(1)
    print(json.dumps(result, sort_keys=True))
