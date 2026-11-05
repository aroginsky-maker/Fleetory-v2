# Fresh native PostgreSQL data roundtrip

Baseline section17's next service rehearsal needs nonempty native restore and
readback before a restored Server process may start. The existing Server backend
fixture requires empty application tables and writes its own audit events.
`tests/Fleetory.Tools.Tests/NativePgDataRoundtrip.Tests.ps1` adds a separate fresh
PostgreSQL-only proof; the existing empty-fixture regression remains unchanged.

The new `ServerBackendProbe restore-schema` mode generates the current Platform
and Core migration SQL using explicit offline options. It reads no File-provider
credential or migration connection environment variable, opens no database and
starts no host. The existing DI-backed `schema` mode independently requires the
same SQL, so CI checks equivalence rather than trusting a copied schema file.

Two UUID-owned PostgreSQL18.6 fixtures reuse the pinned journal image, complete
runtime/identity guards and bounded binary-process transport. Each runs as999:999
with network none, read-only root, cap-drop ALL, no-new-privileges, fixed CPU/PID/
memory limits and private tmpfs only. No host mounts or ports are published.
Before every command the held container identity/runtime is checked. Cleanup is
bound to those identities, verifies absence, and preserves an owned-resource
ledger/public payload directory if cleanup cannot be proved. A ten-minute per-fixture
deadline does not disable cleanup; each cleanup process remains separately bounded.
After the positive fixture is removed, a separately bounded120-second child injects
a failure after allocating both stores. The parent requires the deliberate fault
marker and typed cleanup record, then independently checks both IDs and the owned
payload directory are absent. The child exits nonzero; cleanup cannot turn failure
into a successful roundtrip.

Fresh roles/database bootstrap are created independently on both sides. The owner
is NOLOGIN and non-superuser; the runtime role receives a distinct generated target
SCRAM password. The source gets the real current application migrations and two
devices, two people and four audit events, with an empty outbox. Including migration
history, the checked fixture has18 tables/23 rows. This is distinct from the retained
original18-table/24-row point; no original dump or password is read.

The source custom-format `pg_dump` stays in bounded memory. The generated-only
Python transport fixture exercises the real two-input admission API, replaces its
temporary source files, verifies a new read is refused and returns only the captured
application bytes through a private bounded pipe. Its response is payload-bearing
and must never be forwarded to logs. Its component reports are policy-shape fixtures,
not actual inventory or provider/identity/release approvals. The audit slot contains
an explicit non-native placeholder: immudb backup/restore is not proved by this test.

The receiver checks length/SHA-256/PGDMP magic, then uses native `pg_restore --list`
and a cold `--single-transaction --exit-on-error` restore under the non-superuser
owner role. A truncated native header fails independently of its digest. A valid
archive with a missing target ACL role fails late and leaves zero application
objects, proving the transaction rolls back. Cluster roles and database ACL
bootstrap are supplied by the fixture, not recovered from a per-database dump.

`eng/pilot/server_pg_inventory.sql` reads one repeatable-read transaction, with
statement/lock deadlines, UTC and a fixed catalog search path. It returns schema,
columns/defaults, constraints, indexes, functions, triggers/rules, owners, normalized
table/column/default/database/schema/function ACLs, role capabilities/memberships
and sorted per-table SHA-256 row multisets/counts. Raw row values and role-password
hashes are not returned. The closed profile rejects extra schemas/extensions,
public objects, sequences, foreign/partitioned/materialized/view relations and RLS.
This fixture algorithm is `fleetory.server-pg-roundtrip.v1`; it does not claim
equivalence with the retained original `fleetory.application-signer-recovery.v2`.

Eight target mutations must change the fingerprint: same-count row tampering,
column deletion, table/column/default grants, ownership, role membership and role
capability. Nine cold restores preserve the complete expected fingerprint. Runtime
SCRAM readback, a wrong-password refusal, DELETE42501 and a PostgreSQL stop/start
verify data/permissions and target authentication remain coherent. The source
fingerprint is checked before/after dump and after all target cases: an observed
stable fixture window, not a cross-system atomic snapshot.

Portable policy tests reject19 malformed packet/pin/target/inventory cases on
Windows/Linux. Actual native roundtrip runs locally and in Linux CI. Final evidence
contains only counts/hashes/booleans, after verified cleanup. Original inputs, PKI,
VPS/provider/root/token operations, Server startup and production tokens are absent.
This does not close immudb restore, retained-data schema compatibility, Server
startup, post-restore human login, custody, full-system recovery or Phase7.

Next implement fresh native immudb roundtrip and a separate readback/startup mode
for nonempty data, then bind their actual inventory algorithms and build identity
to the complete controller. Existing data consent remains scoped; this fixture
renews no consumed original configuration/leaf/provider permission.
