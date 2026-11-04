# Generated native Server database and audit acceptance

Run `tests/Fleetory.Tools.Tests/NativeServerBackend.Tests.ps1` after solution
restore. It publishes `eng/ServerBackendProbe`, constructs the production
`FleetoryApplication` with its File provider and nine fresh configuration slots,
and resolves actual services through application DI. Agent/Admin gateways remain
configured with separate generated root CAs; required OIDC and immudb export stay
enabled. The full HTTP host, OIDC login, background export worker and issuer are
not started. No retained data, PKI, passwords, provider share or VPS is read.

## PostgreSQL

The fixture generates migration SQL from both real EF `IMigrator` registrations
without opening a database. A local peer administrator applies it under a
NOLOGIN owner in a fresh database. The runtime LOGIN has schema USAGE, table
SELECT and INSERT on audit events/outbox, with no owner membership or database
CREATE/TEMP grant. Its fresh password is verified to use SCRAM-SHA-256.

Both scoped `PlatformDbContext` and `CoreDbContext` open their registered native
connections. Independent queries verify current/session role, database, TCP TLS
v1.2/v1.3 and access to their respective empty model tables. The actual registered
PostgreSQL health check passes before/after refusals. It only executes `SELECT 1`;
its health result is not an ACL readiness assertion.

The real `IAuditWriter` commits one audit event and one matching outbox entry.
An explicit caller-owned transaction rolls back both. Revoking outbox INSERT
causes a native `42501` after the event INSERT; independent administrator counts
must show that the event was also rolled back. Five more `42501` refusals cover
audit UPDATE/DELETE, schema creation, TEMP creation and SET ROLE to the owner.
Wrong password (`28P01`), wrong CA (native TLS authentication failure) and
plaintext HBA rejection (`28000`) complete nine database refusal cases. Arbitrary
exceptions, missing objects or network failure cannot pass as privilege denials.
Verified TLS and SCRAM use explicit GSS encryption Disable, as in the native
[Signer journal fixture](NativeSignerJournal.md).

## immudb

The actual registered `IAuditExportSink` uses HTTPS against a fresh immudb 1.11.2
database. Its administrator, dedicated writer and reader credentials are newly
generated; exact read/write or read-only database grants are independently
checked. Only the fixture control uses its administrator credential, through
bounded stdin packets. Tokens and passwords never enter Docker arguments or
environment variables. REST administration follows the published
[immudb schema](https://github.com/codenotary/immudb/blob/v1.11.0/pkg/api/schema/schema.proto).

The native sink publishes an event, repeats it, and refuses conflicting content
under the same event ID. An independent scan checks that exactly one audit key
exists; a separate read checks its single stored revision and
all ten event fields. Wrong password, read-only writer, unavailable configured
database and wrong CA are refused through their exact native categories.
Authentication/privilege negatives use a distinct event ID, so an already stored
event cannot conceal an unauthorized write. Five audit refusal cases are
separate from PostgreSQL checks. This fixture does not claim signed checkpoints,
WORM, retained audit continuity or a full outbox-pump-to-immudb delivery.

## Boundary and cleanup

The pinned PostgreSQL and worker images and the derived immudb fixture share
only the positively owned PostgreSQL
`network=none` namespace with loopback. There are no published ports or data
mounts. Each container has a read-only root, dropped capabilities,
no-new-privileges, non-root UID, private PID/IPC, core dumps disabled, CPU/memory/
PID limits and independent 3300-second PID1 expiry with AutoRemove. Separate
0700 tmpfs mounts hold data and private configuration; file slots are 0600.
Only managed public probe payload is mounted read-only into the worker.

The official immudb image has no shell for an independent expiry process. A
fresh UUID-tagged fixture image copies only its binary from the pinned upstream
image into the pinned ASP.NET runtime. Its Dockerfile enters via stdin, has no
host build context or credentials, and uses network-none build steps. Both base
images must already be inspected/pulled by their digests. The exact resulting
image ID and UUID label bind container ownership; cleanup verifies both before
removing only its fresh tag, then checks image absence. No source or runtime
secrets enter image layers.
The fixture explicitly selects the classic builder for this COPY-only build:
the existing Linux Docker wrapper requires its temporary CLI config to remain
empty, whereas buildx stores state there. It uses no BuildKit-only instructions;
the previous process setting is restored on exit.
The generated CA bundle and empty CA directory are scoped to the immudb process
as well as the native client, including the REST proxy's internal gRPC connection.
No host trust store or certificate-validation callback is changed.

Portable contracts reject 16 PostgreSQL, 23 worker and 17 immudb runtime mutations;
nine shared-worker refusal/fault contracts also run. Windows CI runs portable
checks; Linux CI runs the full native fixture. Generated secret canaries must
be absent from bounded probe stdout/stderr. Startup waits for actual TLS health,
not a fixed delay. Cleanup validates ownership and absence for every container,
attempts all removals after failures, and deletes only its resolved public
artifact directory. Unknown cleanup never yields a verified result.

This is generated component acceptance, not original credential/PKI admission,
HTTP/mTLS service startup, post-restore human login, current revocations,
common-point or VPS-loss recovery. Physical Agent trust, independent WORM/custody/
approvals and full RPO/RTO remain open. Phase 7 is incomplete; PR #2 is not merged.
