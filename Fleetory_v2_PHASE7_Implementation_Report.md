# Fleetory v2 — PHASE 7 Security Foundation progress report

**Status:** IN PROGRESS, 17 October 2026. PHASE 6 is complete; PHASE 8 has not started. Draft [PR #2](https://github.com/aroginsky-maker/Fleetory-v2/pull/2) contains the current implementation. The detailed controls and limits are maintained in [SecurityFoundation](docs/architecture/SecurityFoundation.md) and the [local lab guide](docs/architecture/SecurityLab.md).

## Implemented

- Separate Agent and Admin mTLS gateways, pinned CA roots, intermediate chains, device/person SAN validation, certificate binding, one-time Agent enrollment grants, rotation overlap and revocation.
- Local PostgreSQL RBAC with exact permissions and scoped grants; Admin OIDC gate validates signed tokens, WebAuthn AMR, client ID and certificate subject matching. Keycloak lab realm enforces WebAuthn and S256 PKCE.
- PostgreSQL audit event and outbox transaction, lease-based background export and retry. Optional immudb sink uses conditional EventId writes, readback and revision checks. The lab supplies its password through OpenBao.
- File and OpenBao secret providers; Agent-local ECDSA command verification, deny-by-default policy, durable SQLite replay store and per-device public-key trust files. No Agent command execution endpoint is exposed.

## Verification snapshot

| Check | Latest verified result |
| --- | ---: |
| Local strict Release build | 0 warnings, 0 errors |
| Local tests after adding lab verifier | 138/138 passed |
| Local coverage after adding lab verifier | 90.99% |
| Local immudb | First delivery, matching retry, conflicting EventId rejection passed |
| Local full audit pipeline | PostgreSQL outbox → Fleetory worker → immudb readback passed |
| CI coverage at `6653b9f` | 90.37% |
| Sonar PR coverage at `6653b9f` | 88.4% |
| Sonar new-code coverage at `6653b9f` | 88.36% |
| Sonar duplication at `6653b9f` | 0.0% |
| Sonar Quality Gate at `6653b9f` | PASS |

The CI and Sonar numbers come from [run 39032654425](https://github.com/aroginsky-maker/Fleetory-v2/actions/runs/39032654425). The Sonar project card for `main` remains a separate analysis until PR #2 merges; PR metrics cannot be substituted for that card.

## Required before completion

- Positive browser WebAuthn ceremony and signed-token request against the local realm; audited administration of roles and scopes.
- CA issuance and renewal policy, secure grant delivery, Admin certificate lifecycle, identity collision and audit reconciliation procedures.
- Protected command signing and trust-file distribution, approval protocol for high-risk and bulk commands, and Agent runtime enforcement before execution is enabled.
- Production immudb TLS and dedicated credentials, retention/backups and independently anchored verification; complete coverage of critical security call sites.
- Negative and recovery security tests, then final strict build, full test suite and current Sonar Quality Gate.

The local self-hosted lab validates integration behavior; it is not a production security deployment. PR #2 remains draft and unmerged while these controls are open.
