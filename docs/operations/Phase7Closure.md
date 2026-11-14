# Evidence required to close Phase 7

Phase 7 closes when its Baseline controls have actual, retained acceptance
evidence. Passing software tests is necessary; a generated fixture or a
well-formed readiness record cannot substitute for deployment, human or custody
evidence. The [security foundation](../architecture/SecurityFoundation.md) and
[readiness record](Phase7Readiness.md) remain the governing implementation and
final gate documentation.

| Control | Implemented verification available | Evidence still required for closure |
| --- | --- | --- |
| `caPki` | Certificate/trust checks, mTLS refusal tests and lifecycle runbook | Actual issuance and protected custody, rotation/recovery/revocation records, physical Agent acceptance and relevant human admission |
| `signer` | Isolated mTLS signing host, journal, request/revocation controls and provider fixtures | Accepted deployed service/configuration/key lineage, actual provider authentication and independent approvals/custody |
| `immudbTls` | Authenticated TLS, dedicated-account, signed-state, receipt and restore verification | Accepted deployed trust/network/rotation settings, retained backup/restore and retention evidence |
| `wormAnchor` | Hash-linked receipts, export/checkpoint verification and pilot archival | Independently controlled immutable retention, object/version/hash and custody evidence; a mutable local copy or self-asserted flag is insufficient |
| `recovery` | Scoped component restores, generated native service tests, bounded input/process/resource contracts | One accepted complete recovery scope with code/configuration/secret/provider/PKI/identity continuity, human/Agent acceptance, failure/cleanup evidence and measured full RPO/RTO |

The current public cleanup work is preparation for the last row. Read-only OS
identity observations and a retained local consumed-attempt record do not prove
independent supervisor lifetime, actual create-receipt origin or cleanup after
controller/supervisor death. Those properties must be demonstrated before
original service recovery depends on them. Local process-restart replay refusal
also does not authenticate independent anti-rollback custody of the operator disk.

Before each new sensitive operation, prepare the actual executable plan and its
revision/hash, exact already-retained input inventory, proposed reads/transfers,
target isolation, token/privilege scope, maximum duration, negative checks and
owned cleanup. Obtain the applicable current permission before accessing new
secrets, private PKI or privileged provider material. Consumed one-shot grants
do not renew themselves. Preserve completed original recovery evidence and
repeat only an operation needed for a new explicitly reviewed acceptance scope.

Final acceptance must identify the actual independent requester, approver and
deployer, the deployed revision and current successful CI/Sonar, time-valid
evidence for all five controls and a validated rollback plan. Independently
verify the referenced objects, hashes, retention and identities before setting
the corresponding controls to true and running the readiness verifier. Neither
an operator alias nor the assistant can stand in for a missing independent actor.

If any control or its authority remains unverified, retain the exact open item
and its next concrete action. Keep Phase 7 open and PR #2 draft/unmerged; do not
fabricate approvals, production readiness or a completed full-system recovery.
