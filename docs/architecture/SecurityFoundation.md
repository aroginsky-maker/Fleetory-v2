# Fleetory PHASE 7 Security Foundation

**Status:** IN PROGRESS — Command Plane verification, local audit persistence/export transport and RBAC evaluation, 17 October 2026.

The Fleetory Development Baseline places Agent identity, mTLS, certificate lifecycle, RBAC enforcement, durable audit, secret abstraction, signed commands and replay protection in PHASE 7, before Agent Protocol v2 and the first Agent deployment. A compromised application server must not automatically gain authority to command the whole fleet.

## Implemented first slice

`Fleetory.Core.Contracts` owns `SignedCommandEnvelope` and the public verification-key, replay-store and local execution-policy interfaces. `Fleetory.Core` provides `SignedCommandVerifier`. The verifier accepts a command only after checking:

1. format, bounded identifiers, payload and signature size;
2. exact target device, issue/expiry times and a maximum five-minute lifetime;
3. a trusted target-specific P-256 public key and ECDSA/SHA-256 signature;
4. local command policy;
5. atomic consumption of both command ID and nonce by a durable replay store.

The signature input is a deterministic binary sequence: each variable field has a 32-bit big-endian byte length; numeric fields use big-endian integers. The field order is domain separator `Fleetory.Command.v1`, format version, target `DeviceId` as 32 lowercase hexadecimal UTF-8 characters, command ID in the same form, command type UTF-8, SHA-256 of exact payload bytes, issue and expiry UTC ticks, nonce UTF-8 and signing-key ID UTF-8. ECDSA signatures use the 64-byte IEEE P1363 `r || s` form. A signing key ID is included in the signed material to prevent key substitution. The incoming payload and signature are copied before storage. The verifier returns a separate payload copy for execution.

This is a security contract, **not** the PHASE 8 Agent wire protocol. Private signing keys and command signing are not implemented in Fleetory Server. The key provider must bind a trusted public key to the local target device and support revocation. The replay store must atomically reject reuse of either command ID or nonce for that device and persist across restarts; failure to read or write the store must prevent execution. The Agent-side policy must classify commands and deny unsupported or high-risk operations without the required approval. No permissive production implementations of these interfaces are registered.

The new Core security tests cover valid signatures, target mismatch, expiry/future/overlong windows, payload and nonce tampering, unknown and malformed keys, policy denial, repeated commands and nonce reuse, oversized/malformed envelopes, input-copy isolation and replay-store failure. Architecture tests keep the contracts in Core ownership.

## Implemented local audit persistence

Platform now registers `IAuditWriter` backed by PostgreSQL. A write inserts an append-only `platform.audit_events` row and a matching `platform.audit_export_queue` row in the same transaction. The method returns only after commit. A database or transaction failure propagates to the caller; critical call sites must not swallow it. Both tables and their indexes are created by Platform migration `202610160001_AddPlatformAuditOutbox`. No foreign key crosses a module schema.

Audit input validates bounded actor, action, target and correlation identifiers. Context is limited in size and rejects sensitive key names such as passwords, tokens and credentials. Callers must still avoid putting secret values under innocuous keys. The audit tables are owned by Platform; modules use only `IAuditWriter` and do not read Platform tables directly.

The outbox preserves pending export state so that an unavailable external sink does not block the local transaction. This is durable local storage, not a claim of tamper-proof audit after a full database compromise. No privileged endpoint is exposed by this slice.

## Implemented audit export transport

Platform migration `202610160003_AddAuditExportLease` adds attempt count, due time and a bounded lease to each pending export. `PostgreSqlAuditExportPump` claims due entries using PostgreSQL row locks with `SKIP LOCKED`; multiple Server nodes cannot claim the same live lease. It publishes outside the database transaction through `IAuditExportSink` and deletes a queue entry only after the sink reports durable acceptance. Delivery failures clear the lease and schedule exponential retry, capped at one hour. A crashed worker leaves a recoverable lease. Entries are never silently discarded because of retry count. The event ID is stable across all attempts, so a sink must deduplicate by that ID. Delivery is **at least once**; order across nodes is not guaranteed.

The optional background worker starts only with `Fleetory:AuditExport:Enabled=true`. Enabling it requires an `IAuditExportSink` registration; without one, Server startup fails instead of pretending that export works. The default remains disabled while no production SIEM/WORM sink and Secret Provider are configured. The worker batches at most three entries under a two-minute lease and gives each sink call a 30-second cancellation deadline. If a sink ignores cancellation, another node may retry after lease expiry; sink idempotency remains required. Retry logs contain event IDs and attempt counts, not sink exception messages. Integration tests cover successful delivery, failed delivery and retry, expired lease recovery, concurrent claims and the enabled background worker.

A concrete external SIEM/WORM sink, its credential loading and retention controls remain open. The outbox and delivery contract are ready for that integration; they do not by themselves prove external immutable retention.

## Implemented local RBAC evaluation

Platform migration `202610160002_AddPlatformAuthorization` owns scope hierarchy, roles, exact permissions and actor-role assignments in the `platform` schema. `IAuthorizationService` now has a PostgreSQL evaluator. A grant may be global or tied to a Platform scope; scoped grants apply to that scope and its descendants, while unrelated scopes and unknown scope IDs are denied. Requests without a scope require a global assignment. Actor kind and subject ID must match exactly, permissions are case-sensitive and never use wildcards. Anonymous actors and malformed requests are denied. Each decision reads the current local database state, so removing an assignment affects the next decision without waiting for an external identity provider or stale cache. Storage failure propagates rather than producing an allow decision.

This is an evaluator and persistence boundary, not a login or role-administration surface. The current Server exposes no privileged product endpoint; future endpoints must authenticate the actor, call this service before protected work and use the durable audit writer for critical decisions and changes. No default administrative grant is seeded. Direct database writes used by integration tests are not a production administration mechanism. Role/scope management, external-group mapping, MFA/WebAuthn and authorization of all future privileged routes remain open.

## Remaining PHASE 7 work

- Per-device X.509 identity, mTLS transport, proof-of-possession enrollment, certificate rotation and revocation.
- A protected signing service and trust distribution, plus production durable Agent-side replay storage and policy enforcement.
- Human authentication with MFA/WebAuthn foundation, audited role/scope administration and enforcement at future privileged routes.
- Concrete external SIEM/WORM audit sink, Secret Provider integration and retention controls; wiring audited security call sites as those flows are implemented.
- Secret Provider abstraction and production secret loading; no plaintext production secrets.
- Abuse, negative authorization, recovery and cross-platform security tests, then the full Sonar Quality Gate.

PHASE 7 remains open until these controls are integrated and independently verified. No Agent execution endpoint or privileged command route is exposed by this slice.
