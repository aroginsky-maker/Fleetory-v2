# Fleetory v2 — PHASE 7 Security Foundation progress report

**Status:** IN PROGRESS, 18 October 2026. PHASE 6 is complete; PHASE 8 has not started. Draft [PR #2](https://github.com/aroginsky-maker/Fleetory-v2/pull/2) contains the current implementation. The detailed controls and limits are maintained in [SecurityFoundation](docs/architecture/SecurityFoundation.md) and the [local lab guide](docs/architecture/SecurityLab.md).

## Implemented

- Separate Agent and Admin mTLS gateways, pinned CA roots, intermediate chains, device/person SAN validation, certificate binding, one-time Agent enrollment grants, rotation overlap and revocation.
- Local PostgreSQL RBAC with exact permissions and scoped grants; Admin OIDC gate validates signed tokens, WebAuthn AMR, client ID and certificate subject matching. Keycloak lab realm enforces WebAuthn and S256 PKCE.
- Platform-owned Admin routes create immutable roles and scopes, assign scoped roles and revoke assignments. Every write requires the global `platform.authorization.manage` permission; authorization, state change and audit/outbox entry share a serializable PostgreSQL transaction. No management grant is seeded.
- Offline first-admin bootstrap requires the Admin certificate SAN UUID, refuses a second global manager bootstrap and writes the initial grant with audit/outbox atomically. Integration tests exercise the real SQL procedure.
- PostgreSQL audit event and outbox transaction, lease-based background export and retry. Optional immudb sink uses conditional EventId writes, readback and revision checks. The lab supplies its password through OpenBao.
- File and OpenBao secret providers; Agent-local ECDSA command verification, deny-by-default policy, durable SQLite replay store and per-device public-key trust files. No Agent command execution endpoint is exposed.
- Lab-only OpenBao Transit signing key with a separate sign-only token and DeviceId-bound public trust file. The Server token is read-only for its KV secrets.
- Reproducible local browser S256 PKCE and virtual WebAuthn check: the signed token carries `amr=webauthn` and the certificate-bound subject; the Admin route returns 401 without it and 403 at RBAC with it.
- Admin Gateway startup rejects wildcard bind addresses, keeping its listener on loopback or an explicitly selected management IP.

## Verification snapshot

| Check | Latest verified result |
| --- | ---: |
| Local strict Release build | 0 warnings, 0 errors |
| Local tests | 145/145 passed |
| Local coverage | 89.61% |
| Local immudb | First delivery, matching retry, conflicting EventId rejection passed |
| Local full audit pipeline | PostgreSQL outbox → Fleetory worker → immudb readback passed |
| Local WebAuthn/OIDC with real Admin mTLS | 401 without token; 403 with WebAuthn token at RBAC |
| Windows server TLS chain | 1 certificate sent; root-only validation fails |
| Linux container server TLS chain | 2 certificates sent; root-only OpenSSL verification code 0 |
| CI coverage at `6514c49` | 89.87% |
| Sonar PR coverage at `6514c49` | 88.9% |
| Sonar new-code coverage at `6514c49` | 88.96% |
| Sonar duplication at `6514c49` | 0.0% |
| Sonar Quality Gate at `6514c49` | PASS |

The latest completed CI and Sonar numbers come from [run 39072972801](https://github.com/aroginsky-maker/Fleetory-v2/actions/runs/39072972801). The Sonar project card for `main` remains a separate analysis until PR #2 merges; PR metrics cannot be substituted for that card.

## Required before completion

- Wire-level server certificate chain delivery on Windows: Kestrel currently sends only the leaf, so a client trusting just the root fails TLS verification. The same build passed root-only verification on Linux. The Baseline requires equal Windows Server and Linux support, so the Windows path must be fixed and root-only wire verification automated.
- Emergency recovery when an existing administrator loses certificate or OIDC access, role/scope lifecycle beyond creation, and prevention of administrative lockout.
- CA issuance and renewal policy, secure grant delivery, Admin certificate lifecycle, identity collision and audit reconciliation procedures.
- Protected command signing and trust-file distribution, approval protocol for high-risk and bulk commands, and Agent runtime enforcement before execution is enabled.
- Production immudb TLS and dedicated credentials, retention/backups and independently anchored verification; complete coverage of critical security call sites.
- Negative and recovery security tests, then final strict build, full test suite and current Sonar Quality Gate.

The local self-hosted lab validates integration behavior; it is not a production security deployment. PR #2 remains draft and unmerged while these controls are open.
