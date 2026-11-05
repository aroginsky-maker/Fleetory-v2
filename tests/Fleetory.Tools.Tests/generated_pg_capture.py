"""Binary transport fixture only: freshly generated dump in, immutable capture out. Never use retained data."""
import base64
import hashlib
import json
from pathlib import Path
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'eng' / 'pilot'))
import recovery_composition_tests as fixture
import server_data_inputs as admission


def capture(packet, audit):
    admission.archive.require(0 < len(packet) <= admission.MAX_INPUT and 0 < len(audit) <= admission.MAX_INPUT)
    digest = hashlib.sha256(packet).hexdigest()
    audit_digest = hashlib.sha256(audit).hexdigest()
    with tempfile.TemporaryDirectory(prefix='fleetory-generated-pg-') as directory:
        root = Path(directory)
        reports = fixture.synthetic_reports()
        # This graph is an explicit policy-shape fixture, not a native inventory
        # measurement or evidence of provider/identity/release approval.
        for report in reports.values():
            report['fixtureScope'] = 'synthetic-not-approval-not-native-inventory'
        reports['database']['dumpSha256']['fleetory'] = digest
        reports['login']['sourceDumpSha256']['fleetory'] = digest
        reports['audit'].update(backupSha256=audit_digest, backupBytes=len(audit))
        manifest = dict(schema=admission.composition.SCHEMA, sourceApplicationCommit=fixture.APP,
                        sourceConfigurationCommit=fixture.CONFIG, operatorRevision='c' * 40, reports={})
        component_pin = fixture.pin_reports(root, reports, manifest)
        record = dict(schema=admission.SCHEMA, componentManifestSha256=component_pin,
                      candidateCommit='d' * 40, candidateBuildSha256='e' * 64,
                      artifacts={'application-postgres': dict(bytes=len(packet), sha256=digest),
                                 'audit-immudb': dict(bytes=len(audit), sha256=audit_digest)})
        (root / 'application.dump').write_bytes(packet)
        (root / 'audit.backup').write_bytes(audit)
        encoded = json.dumps(record).encode()
        (root / admission.MANIFEST).write_bytes(encoded)
        capsule = admission.load(root, hashlib.sha256(encoded).hexdigest())
        (root / 'application.dump').write_bytes(b'replaced-after-capture')
        (root / 'audit.backup').write_bytes(b'replaced-after-capture')
        captured = capsule.packet('application-postgres')
        admission.archive.require(captured == packet and capsule.packet('audit-immudb') == audit)
        try:
            admission.load(root, hashlib.sha256(encoded).hexdigest())
        except admission.archive.ArchiveError:
            pass
        else:
            raise admission.archive.ArchiveError('Replacement was accepted.')
        return captured, capsule.packet('audit-immudb')


def run():
    packet = sys.stdin.buffer.read(admission.MAX_INPUT + 1)
    admission.archive.require(64 <= len(packet) <= admission.MAX_INPUT and packet.startswith(b'PGDMP'))
    captured, _ = capture(packet, b'SYNTHETIC_PLACEHOLDER_NOT_A_NATIVE_IMMUDB_BACKUP')
    return dict(schema='fleetory.generated-pg-capture.v1', dumpBase64=base64.b64encode(captured).decode(),
                    dumpSha256=hashlib.sha256(captured).hexdigest(), dumpBytes=len(captured), sourceReplacementRejected=True,
                    capturedBytesSurviveReplacement=True, componentReportsAreSyntheticFixtures=True,
                    originalInventoryV2Verified=False, auditBackupRestored=False,
                    fullSystemRecoveryVerified=False, phase7Complete=False)


if __name__ == '__main__':
    try:
        result = run()
    except Exception:
        print('Generated dump capture failed; no packet contents logged.', file=sys.stderr)
        sys.exit(1)
    # The owning bounded native-process caller captures this private pipe; it must
    # never forward this payload-bearing response to logs or published evidence.
    print(json.dumps(result))
