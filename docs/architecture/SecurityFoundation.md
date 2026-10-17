# Fleetory PHASE 7 Security Foundation

**Status:** IN PROGRESS — Command Plane verification, local audit persistence/export transport, RBAC evaluation and an initial Agent mTLS listener, 17 October 2026.

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

The optional background worker starts only with `Fleetory:AuditExport:Enabled=true`. Enabling it requires an `IAuditExportSink` registration; without one, Server startup fails instead of pretending that export works. The default remains disabled while no production SIEM/WORM sink is configured. The worker batches at most three entries under a two-minute lease and gives each sink call a 30-second cancellation deadline. If a sink ignores cancellation, another node may retry after lease expiry; sink idempotency remains required. Retry logs contain event IDs and attempt counts, not sink exception messages. Integration tests cover successful delivery, failed delivery and retry, expired lease recovery, concurrent claims and the enabled background worker.

A concrete external SIEM/WORM sink, its credential loading and retention controls remain open. The outbox and delivery contract are ready for that integration; they do not by themselves prove external immutable retention.

## Implemented local RBAC evaluation

Platform migration `202610160002_AddPlatformAuthorization` owns scope hierarchy, roles, exact permissions and actor-role assignments in the `platform` schema. `IAuthorizationService` now has a PostgreSQL evaluator. A grant may be global or tied to a Platform scope; scoped grants apply to that scope and its descendants, while unrelated scopes and unknown scope IDs are denied. Requests without a scope require a global assignment. Actor kind and subject ID must match exactly, permissions are case-sensitive and never use wildcards. Anonymous actors and malformed requests are denied. Each decision reads the current local database state, so removing an assignment affects the next decision without waiting for an external identity provider or stale cache. Storage failure propagates rather than producing an allow decision.

This is an evaluator and persistence boundary, not a login or role-administration surface. The current Server exposes no privileged product endpoint; future endpoints must authenticate the actor, call this service before protected work and use the durable audit writer for critical decisions and changes. No default administrative grant is seeded. Direct database writes used by integration tests are not a production administration mechanism. Role/scope management, external-group mapping, MFA/WebAuthn and authorization of all future privileged routes remain open.

## Implemented Secret Provider boundary

`Fleetory.Platform.Contracts` owns `ISecretProvider`; Platform implements a bounded UTF-8 file adapter for an externally provisioned secret mount. In non-development environments, Server requires an absolute `Fleetory:Secrets:Directory` and reads `fleetory-postgresql` before startup. Both Platform and Core obtain their PostgreSQL connection string from the same provider. Direct `ConnectionStrings:Fleetory` is rejected in these environments and cannot be combined with a secret directory. The provider caches values for the process lifetime, so rotation requires a restart. It rejects missing, empty, oversized, invalid UTF-8 and unsafe names. On Unix it rejects secret files readable by group or others; Windows deployment must enforce an ACL granting only the service identity access.

The secret manager or OS mount is responsible for provisioning, access control and rotation. This adapter does not yet implement a Vault API or production delivery of external audit-sink credentials. No secret contents are emitted in provider error messages.

## Implemented Agent certificate binding foundation

`Fleetory.Core.Contracts` owns the certificate-binding lookup and verifier contracts. Core migration `20261016212919_AddAgentCertificateBindings` adds `core.agent_certificates`. A unique SHA-256 digest of the certificate DER binds one certificate to one `DeviceId`; multiple certificates may be valid for the same device during rotation. The row stores validity bounds and an optional revocation timestamp. It references only Core-owned `devices`. Core registers a PostgreSQL lookup and verifier; storage failure propagates, so identity cannot silently become accepted.

The verifier checks the certificate validity interval, end-entity Basic Constraints, Digital Signature Key Usage, Client Authentication EKU, exact registered digest, target `DeviceId`, binding validity and revocation. The initial gateway calls it on **every Agent request**, including a request sent over an existing TLS connection. A revoked binding is denied on the next request. Two active bindings permit rotation overlap without changing the billable device identity. Integration tests cover overlap and revocation against real PostgreSQL; unit tests cover unknown, wrong-device, invalid-purpose and expired certificates.

The verifier is a binding check; the gateway supplies the certificate from Kestrel's client-certificate TLS handshake. Supplying a copied public certificate object to the verifier alone proves no possession of its private key.

## Implemented initial Agent mTLS listener

The opt-in `Fleetory:AgentGateway:Enabled=true` setting requires a mounted secret directory and two different explicit ports: `Fleetory:Web:Port` for the existing HTTP web/health surface and `Fleetory:AgentGateway:Port` for HTTPS with a mandatory client certificate. Kestrel builds a chain directly to the configured Fleetory root CA, checks Client Authentication purpose, and refuses certificates outside that trust root. The server certificate must chain directly to the same root and have Server Authentication purpose. Invalid or missing TLS material fails startup. The gateway reads `agent-gateway-root-ca` (PEM certificate), `agent-gateway-server-cert` (PEM certificate) and `agent-gateway-server-key` (matching PEM private key) through `ISecretProvider`. The root CA private key must stay outside Fleetory Server. TLS termination or a reverse proxy in front of this port must preserve the authenticated client-certificate boundary; the current implementation expects the handshake at Kestrel.

The only Agent route is `GET /agent/identity`, which returns `204` after successful mutual TLS and an active Core certificate binding. The Agent `DeviceId` is read from a single SAN URI `urn:fleetory:device:<guid>`; a missing, malformed or duplicate Fleetory URI is denied. The web port does not expose `/agent`, and the Agent port does not expose health or module routes. The gateway checks the binding on each request, so revocation blocks reuse of an established connection at the next request. An integration test exercises a real TLS handshake, port isolation, accepted, unknown and revoked bindings, and missing client certificates against disposable PostgreSQL.

This is an identity probe, not Agent Protocol v2, an enrollment or a production Agent operation. CA revocation lists and OCSP are not configured: the pinned direct CA chain is checked in TLS, while the local database binding controls individual certificate revocation per request. The CA and server certificate rotate through secret provisioning and process restart. A production deployment must restrict and encrypt the web listener at its ingress and protect the secret mount. Enrollment approval, certificate issuance and audited rotation/revocation administration remain open.

## Remaining PHASE 7 work

- Proof-of-possession enrollment and issuance, CA lifecycle, audited rotation/revocation administration, and propagation of revocation to future long-lived Agent streams.
- A protected signing service and trust distribution, plus production durable Agent-side replay storage and policy enforcement.
- Human authentication with MFA/WebAuthn foundation, audited role/scope administration and enforcement at future privileged routes.
- Concrete external SIEM/WORM audit sink, its credential integration and retention controls; wiring audited security call sites as those flows are implemented.
- Abuse, negative authorization, recovery and cross-platform security tests, then the full Sonar Quality Gate.

PHASE 7 remains open until these controls are integrated and independently verified. No Agent execution endpoint or privileged command route is exposed by this slice.
