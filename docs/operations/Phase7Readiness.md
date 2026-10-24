# PHASE 7 deployment-readiness record

The final deployment gate can be checked before approval with:

    ./eng/verify-phase7-readiness.ps1 `
      -RecordPath C:\ProgramData\Fleetory\evidence\phase7-readiness.json

The read-only verifier requires the `fleetory.phase7-readiness.v1` schema,
distinct requester/approver/operator identities, monotonic UTC approval and
expiry timestamps, all five production control confirmations, a passing CI run
and Sonar Quality Gate, at least 80% coverage, a WORM/SIEM evidence reference,
and a validated rollback plan. It rejects a failed gate, duplicate identities,
invalid fingerprints/hashes, non-monotonic timestamps, relative paths and
missing controls.

The output is a compact verification summary suitable for the change record.
It does not contact GitHub, Sonar, a secret manager or WORM/SIEM; operators must
retain those external records independently.
