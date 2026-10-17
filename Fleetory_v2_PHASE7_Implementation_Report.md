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
9. Core certificate-binding contracts and migration `20261016212919_AddAgentCertificateBindings` bind an X.509 certificate SHA-256 digest to one `DeviceId`. The verifier rejects unknown, revoked, wrong-device, expired and invalid-purpose certificates. Two bindings permit rotation overlap.
10. An opt-in Kestrel Agent listener requires mutual TLS, a pinned Fleetory root CA, a SAN `DeviceId` and an active Core certificate binding on every request. Its `/agent/identity` probe is isolated from the web and health listener. Real TLS/PostgreSQL integration tests cover acceptance, revocation, unknown bindings and absent client certificates. Certificate issuance and enrollment remain open.
11. An internal Core revocation service requires the global `core.agent_certificate.revoke` grant and persists an audit record before atomically changing the binding. Denied attempts are audited. No administrative route or default grant is exposed; confirmed outcome auditing and authenticated administration remain open.

## Local verification

| Gate | Result |
| --- | ---: |
| Strict Release build | PASS, 0 warnings and 0 errors |
| All tests | PASS, 98/98 |
| Architecture tests | PASS, 26/26 |
| Core tests | PASS, 26/26 |
| Server tests | PASS, 14/14 |
| PostgreSQL integration tests | PASS, 23/23 |
| Disposable PostgreSQL and migrations | PASS |
| Windows/Linux server packages and Windows production smoke | PASS |
| Local production line coverage | 92.39% |
| CI production line coverage | Pending this increment |
| Sonar overall coverage | Pending this increment |
| Sonar new-code coverage | Pending this increment |
| Sonar overall duplication | Pending this increment |
| Sonar new-code duplication | Pending this increment |
| Open Sonar issues for PR | Pending this increment |
| Sonar Quality Gate | Pending this increment |

Local PHASE 6 regression verification passed with disposable PostgreSQL, migrations, Windows/Linux packages and Windows runtime smoke. The prior mTLS increment passed [GitHub Actions run 39001771983](https://github.com/aroginsky-maker/Fleetory-v2/actions/runs/39001771983) at commit `9c82564`: Sonar reported 90.52823315118397% new-code coverage, 89.9% overall coverage, 0.0% duplication and zero open PR issues. The current revocation increment awaits CI/Sonar analysis. Security Hotspots were not separately available from the metrics report. PHASE 7 as a whole remains IN PROGRESS.

## Required before PHASE 7 completion

- Proof-of-possession enrollment and issuance, CA lifecycle, authenticated administration with confirmed revocation outcomes, rotation, and revocation propagation to future long-lived streams.
- Protected command signing and key distribution, production Agent-local policy and durable replay store.
- Human authentication with MFA/WebAuthn foundation, audited role/scope administration and enforcement at privileged routes.
- Concrete external SIEM/WORM audit sink, retention policy and coverage of all critical security call sites.
- External secret-manager provisioning and rotation procedure for deployment environments; audit-sink credentials still need integration.
- Negative security, abuse and recovery tests plus current Sonar Quality Gate.

The exact implementation boundary and remaining risks are recorded in `docs/architecture/SecurityFoundation.md`.
