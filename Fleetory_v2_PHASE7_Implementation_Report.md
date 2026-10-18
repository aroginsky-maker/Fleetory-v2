# Fleetory v2 — PHASE 7 Security Foundation progress report

**Status:** IN PROGRESS, 18 October 2026. PHASE 6 is complete; PHASE 8 has not started. Draft [PR #2](https://github.com/aroginsky-maker/Fleetory-v2/pull/2) contains the current implementation. The detailed controls and limits are maintained in [SecurityFoundation](docs/architecture/SecurityFoundation.md) and the [local lab guide](docs/architecture/SecurityLab.md).

## Implemented

- Separate Agent and Admin mTLS gateways, pinned CA roots, intermediate chains, device/person SAN validation, certificate binding, one-time Agent enrollment grants, rotation overlap and revocation.
- Local PostgreSQL RBAC with exact permissions and scoped grants; Admin OIDC gate validates signed tokens, WebAuthn AMR, client ID and certificate subject matching. Keycloak lab realm enforces WebAuthn and S256 PKCE.
- Platform-owned Admin routes create immutable roles and scopes, assign scoped roles and revoke assignments. Every write requires the global `platform.authorization.manage` permission; authorization, state change and audit/outbox entry share a serializable PostgreSQL transaction. No management grant is seeded.
- Offline first-admin bootstrap requires the Admin certificate SAN UUID, refuses a second global manager bootstrap and writes the initial grant with audit/outbox atomically. Integration tests exercise the real SQL procedure.
- Controlled break-glass recovery grants a replacement Admin identity under an approved incident reference, records the database operator in audit/outbox, and refuses duplicate or missing-manager recovery. It leaves the old assignment for verified, audited revocation after the replacement can authenticate.
- Assignment revocation refuses to remove the last global `platform.authorization.manage` grant. The refusal is audited in the same transaction and returns HTTP 409; no access is lost.
- Roles and scopes can be retired through audited Admin routes only after their assignments or child scopes are removed. In-use objects return 409; the database also rejects direct cascading deletion of an assigned role.
- PostgreSQL audit event and outbox transaction, lease-based background export and retry. Optional immudb sink uses conditional EventId writes, readback and revision checks. The lab supplies its password through OpenBao.
- File and OpenBao secret providers; Agent-local ECDSA command verification, deny-by-default policy, durable SQLite replay store and per-device public-key trust files. No Agent command execution endpoint is exposed.
- Lab-only OpenBao Transit signing key with a separate sign-only token and DeviceId-bound public trust file. The Server token is read-only for its KV secrets.
- Reproducible local browser S256 PKCE and virtual WebAuthn check: the signed token carries `amr=webauthn` and the certificate-bound subject; the Admin route returns 401 without it and 403 at RBAC with it.
- Admin Gateway startup rejects wildcard bind addresses, keeping its listener on loopback or an explicitly selected management IP.
- Windows CI provisions an ephemeral root and intermediate in the runner certificate stores, then confirms the actual Admin listener sends two certificates and passes root-only OpenSSL verification. Windows hosts require equivalent approved CA-store provisioning.
- Lab certificate provisioning restricts the local key directory before copying new keys, validates each leaf certificate/key pair, archives the previous pair for rotation recovery and removes temporary leaf keys from CA containers. An isolated crypto-backed test verifies successful rotation and failed-copy rollback without touching the live lab.
- Negative security checks exercise malformed Admin RBAC requests through the real mTLS listener, fail-closed Gateway startup for a wrong key, foreign CA and malformed chain, and rejection of mixed or incomplete OpenBao configuration and unsafe Admin rate-limit values.
- Agent grant creation, certificate binding and certificate revocation now commit their Core state, completion audit event and export-queue entry in one PostgreSQL transaction. A completion-audit failure rolls back the Core change; integration tests cover failure and retry. The Platform audit writer accepts the caller's transaction while retaining ownership of its tables. The architecture guide includes a read-only recovery procedure for a lost commit acknowledgement.
- Agent identity collision checks now require the Admin to name a previously bound certificate fingerprint when issuing a replacement grant. The expectation is stored with the token digest and checked again under a per-device PostgreSQL row lock at redemption. Missing or foreign fingerprints return 409; a stale initial grant cannot bind a second certificate after another grant succeeds. Collision denials are audited, and integration tests cover both a stale grant and concurrent first enrollments. The physical-device verification and approval process remains an operational requirement.
- Replacement grants additionally require the global `core.agent_certificate.rotate` permission alongside enrollment permission. Without it, the Admin route returns 403 and writes a denial audit event without issuing a token; real mTLS/PostgreSQL tests cover denial and authorized rotation. Neither permission is seeded by default.

## Verification snapshot

| Check | Latest verified result |
| --- | ---: |
| Local strict Release build | 0 warnings, 0 errors |
| Local tests after separate rotation permission | 157/157 passed |
| Local production coverage | 92.44% |
| CI production coverage at `0a2e22e` | 92.69% |
| Local immudb | First delivery, matching retry, conflicting EventId rejection passed |
| Local full audit pipeline | PostgreSQL outbox → Fleetory worker → immudb readback passed |
| Local live certificate renewal | 4/4 new pairs validated; 4/4 previous pairs archived and matched backup; identity UUIDs retained; OpenBao TLS secrets matched |
| Isolated certificate provisioning checks | Rotation archive, failed-copy rollback and mismatched-key rejection passed |
| Local WebAuthn/OIDC with real Admin mTLS | 401 without token; 403 with WebAuthn token at RBAC |
| Windows server TLS chain in CI with provisioned OS CA stores | 2 certificates sent; root-only OpenSSL verification code 0 |
| Linux container server TLS chain | 2 certificates sent; root-only OpenSSL verification code 0 |
| Sonar PR coverage at `0a2e22e` | 91.2% |
| Sonar new-code coverage at `0a2e22e` | 91.69% |
| Sonar duplication at `0a2e22e` | 0.0% |
| Sonar new-code duplication at `0a2e22e` | 0.0% |
| Sonar Quality Gate at `0a2e22e` | PASS |

The latest completed CI and Sonar numbers come from [run 39133056768](https://github.com/aroginsky-maker/Fleetory-v2/actions/runs/39133056768). A live renewal of the local self-hosted CA leaf certificates and an OpenBao-backed Fleetory startup with both gateways and the PostgreSQL → immudb audit pipeline passed on 18 October 2026. The PowerShell provisioning test runs in CI and remains under Sonar static analysis; it is excluded from the .NET coverage denominator because `dotnet-coverage` cannot instrument PowerShell. The Sonar project card for `main` remains a separate analysis until PR #2 merges; PR metrics cannot be substituted for that card.

## Required before completion

- Production Windows PKI provisioning and renewal must install the approved root and intermediate in the host certificate stores. The automated root-only wire test passes on an ephemeral runner; the earlier local machine without those store entries still needs its own provisioning before that probe can pass.
- Validate the controlled Admin recovery runbook with production incident approval and credential custody; define role/scope replacement and versioning beyond safe retirement.
- CA issuance and renewal policy, secure grant delivery, Admin certificate lifecycle and verified physical-device approval for certificate replacement.
- Protected command signing and trust-file distribution, approval protocol for high-risk and bulk commands, and Agent runtime enforcement before execution is enabled.
- Production immudb TLS and dedicated credentials, retention/backups and independently anchored verification; complete coverage of critical security call sites.
- Negative and recovery security tests, then final strict build, full test suite and current Sonar Quality Gate.

The local self-hosted lab validates integration behavior; it is not a production security deployment. PR #2 remains draft and unmerged while these controls are open.
