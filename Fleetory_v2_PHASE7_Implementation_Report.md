# Fleetory v2 — PHASE 7 Security Foundation progress report

**Status:** IN PROGRESS, 17 October 2026. PHASE 6 is complete; PHASE 8 has not started.

## Delivered in PR #2

1. `Fleetory.Core.Contracts` defines a targeted signed-command envelope and interfaces for trusted public keys, Agent-local command policy and durable replay detection.
2. `Fleetory.Core` verifies ECDSA P-256/SHA-256 signatures, exact payload binding, device target, timestamps, bounded lifetime, policy and atomic nonce/command-ID consumption before returning a verified payload copy. Fleetory Server holds no command signing private key and exposes no command execution route.
3. Platform migration `202610160001_AddPlatformAuditOutbox` adds owned `platform.audit_events` and `platform.audit_export_queue` tables.
4. `IAuditWriter` has a PostgreSQL implementation that inserts the event and queue entry in one transaction and propagates storage failure. Context size is bounded and sensitive key names are rejected.
5. Architecture and security tests cover the new boundaries, invalid commands and real PostgreSQL audit writes.
6. Platform migration `202610160002_AddPlatformAuthorization` and `IAuthorizationService` implement local, deny-by-default RBAC decisions over exact permissions and a Platform-owned scope hierarchy. There is no seeded admin grant or privileged route.
7. Platform migration `202610160003_AddAuditExportLease` and a conditional background worker add concurrent-safe at-least-once outbox delivery through `IAuditExportSink`, with retry and lease recovery. A production external sink is still required.
8. `ISecretProvider` is owned by Platform contracts. A file adapter reads an externally mounted PostgreSQL secret with size, encoding, name and Unix permission checks. Non-development Server startup rejects direct connection strings and fails closed when the file is missing or invalid. Both Core and Platform use the same cached secret.
9. Core certificate-binding contracts and migration `20261016212919_AddAgentCertificateBindings` bind an X.509 certificate SHA-256 digest to one `DeviceId`. The verifier rejects unknown, revoked, wrong-device, expired and invalid-purpose certificates. Two bindings permit rotation overlap. The TLS handshake, CA, issuance and enrollment flow remain open.

## Local verification

| Gate | Result |
| --- | ---: |
| Strict Release build | PASS, 0 warnings and 0 errors |
| All tests | PASS, 95/95 |
| Architecture tests | PASS, 26/26 |
| Core tests | PASS, 26/26 |
| PostgreSQL integration tests | PASS, 21/21 |
| Disposable PostgreSQL and migrations | PASS |
| Windows/Linux server packages and Windows production smoke | PASS |
| Local production line coverage | 92.63% |
| CI production line coverage | Awaiting CI analysis for this increment |
| Sonar overall coverage | Awaiting CI analysis for this increment (previous: 90.6%) |
| Sonar new-code coverage | Awaiting CI analysis for this increment (previous: 91.78%) |
| Sonar overall duplication | Awaiting CI analysis for this increment (previous: 0.0%) |
| Sonar new-code duplication | Awaiting CI analysis for this increment (previous: 0.0%) |
| Open Sonar issues for PR | Awaiting CI analysis for this increment (previous: 0) |
| Sonar Quality Gate | Awaiting CI analysis for this increment |

Local PHASE 6 verification passed with disposable PostgreSQL, migrations, Windows/Linux packages and a Windows production smoke test using the secret file. The certificate-binding increment still awaits GitHub Actions and Sonar results. The previous Secret Provider increment passed [GitHub Actions run 38968698518](https://github.com/aroginsky-maker/Fleetory-v2/actions/runs/38968698518). PHASE 7 as a whole remains IN PROGRESS.

## Required before PHASE 7 completion

- mTLS gateway and Fleetory CA trust, proof-of-possession enrollment and issuance, audited rotation/revocation management, and termination of existing sessions after revocation.
- Protected command signing and key distribution, production Agent-local policy and durable replay store.
- Human authentication with MFA/WebAuthn foundation, audited role/scope administration and enforcement at privileged routes.
- Concrete external SIEM/WORM audit sink, retention policy and coverage of all critical security call sites.
- External secret-manager provisioning and rotation procedure for deployment environments; audit-sink credentials still need integration.
- Negative security, abuse and recovery tests plus current Sonar Quality Gate.

The exact implementation boundary and remaining risks are recorded in `docs/architecture/SecurityFoundation.md`.
