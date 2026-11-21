"""Test-only audit pipe. The other slot is a placeholder, not a PostgreSQL backup."""
import base64
import hashlib
import json
import sys

from generated_pg_capture import admission, capture


def run():
    audit = sys.stdin.buffer.read(admission.MAX_INPUT + 1)
    admission.archive.require(64 <= len(audit) <= admission.MAX_INPUT and audit.startswith(b'IMMUBACKUP'))
    _, captured = capture(b'SYNTHETIC_PLACEHOLDER_NOT_A_NATIVE_POSTGRES_BACKUP', audit)
    return dict(schema='fleetory.generated-audit-capture.v1', backupBase64=base64.b64encode(captured).decode(),
                backupSha256=hashlib.sha256(captured).hexdigest(), backupBytes=len(captured),
                capturedBytesSurviveReplacement=True, sourceReplacementRejected=True,
                componentReportsAreSyntheticFixtures=True, applicationBackupRestored=False,
                originalInventoryV2Verified=False, fullSystemRecoveryVerified=False, phase7Complete=False)


if __name__ == '__main__':
    try:
        result = run()
    except Exception:
        print('Generated audit capture failed; no packet contents logged.', file=sys.stderr)
        sys.exit(1)
    # Only the owning bounded caller may consume this private payload-bearing pipe.
    print(json.dumps(result))
