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

## Local verification

| Gate | Result |
| --- | ---: |
| Strict Release build | PASS, 0 warnings and 0 errors |
| All tests | PASS, 86/86 |
| Architecture tests | PASS, 26/26 |
| Core security tests | PASS, 18/18 |
| PostgreSQL integration tests | PASS, 20/20 |
| Disposable PostgreSQL and migrations | PASS |
| Windows/Linux server packages and Windows production smoke | PASS |
| Local production line coverage | 91.45% |
| CI production line coverage | 92.17% |
| Sonar overall coverage | 90.6% |
| Sonar new-code coverage | 91.78% |
| Sonar overall duplication | 0.0% |
| Sonar new-code duplication | 0.0% |
| Open Sonar issues for PR | 0 |
| Sonar Quality Gate | PASS |

Local PHASE 6 verification passed with disposable PostgreSQL, migrations, Windows/Linux packages and a Windows production smoke test using the secret file. [GitHub Actions run 38968058071](https://github.com/aroginsky-maker/Fleetory-v2/actions/runs/38968058071) passed for commit `1c58a4d`; Sonar reported 91.78082191780823% new-code coverage, rounded to 91.78% above. The Sonar issues API reported zero open issues for PR #2. Security Hotspots were not separately available from the metrics report. PHASE 7 as a whole remains IN PROGRESS.

## Required before PHASE 7 completion

- Per-device certificate identity, mTLS, enrollment, rotation and revocation.
- Protected command signing and key distribution, production Agent-local policy and durable replay store.
- Human authentication with MFA/WebAuthn foundation, audited role/scope administration and enforcement at privileged routes.
- Concrete external SIEM/WORM audit sink, retention policy and coverage of all critical security call sites.
- External secret-manager provisioning and rotation procedure for deployment environments; audit-sink credentials still need integration.
- Negative security, abuse and recovery tests plus current Sonar Quality Gate.

The exact implementation boundary and remaining risks are recorded in `docs/architecture/SecurityFoundation.md`.
