# Privileged change and recovery evidence

This record format closes the operational evidence boundary for PHASE 7
privileged changes. It applies to certificate lifecycle, signer/key rotation,
scope reparenting, break-glass recovery and any future command approval flow.
The record is retained by the independent audit/WORM system; Fleetory stores
only the durable audit/outbox event and correlation reference required to trace
the decision.

## Required record fields

Every approved change must contain:

- a unique change or incident reference and the affected environment;
- the exact action, target identity/scope/DeviceId and canonical payload or
  evidence-bundle SHA-256;
- expected current revision, old and new certificate/key fingerprints, when
  applicable;
- requester, independent approver and deployment operator identities;
- requested-at, approved-at, expiry/overlap deadline and completed-at times in
  UTC;
- the Fleetory correlation ID, audit EventId(s), CI/Sonar run URL and the
  independent WORM/SIEM object identifier;
- rollback plan, validation result, rollback deadline and the final outcome.

The requester and approver must be distinct identities. A missing, expired,
replayed or mismatched approval is a denial. Changing the target, revision,
fingerprint, payload hash or evidence hash requires a new approval record.

## Retention and recovery

1. Write the approval and impact-review record before the privileged mutation.
2. Commit the Fleetory state change, audit event and export-queue entry in one
   transaction where the operation is database-backed.
3. Copy the completed record, verification output and receipt/export package to
   the independently administered WORM/SIEM destination. Record its object ID,
   retention deadline and legal-hold status.
4. For a lost acknowledgement, query the correlation ID and durable audit state
   before taking any retry action. Never repeat a signer operation or recovery
   grant solely because an HTTP response was lost.
5. At expiry, revoke temporary grants/overlap and attach the revocation result to
   the same change record. A failed validation blocks completion and starts the
   recorded rollback procedure.

The repository tests validate transactional audit links, two-person recovery,
scope-reparenting preflight and fail-closed expiry/replay behavior. Production
closure still requires the organization's approval, retention, legal-hold and
recovery records in the independent control plane.
