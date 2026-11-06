# Native PostgreSQL v2 readback

The separate `eng/pilot/pg_inventory_v2.py` library supports the retained pilot's
application/signer table sets and zero sequences. Its fixed SQL generator uses one
PostgreSQL 18 repeatable-read, read-only transaction per database, explicit UTF-8,
UTC/ISO/float/bytea/search-path settings, five-second statements and two-second
lock waits. The native psql gate refuses unsupported relations, functions,
triggers, policies, extensions, large objects or namespaces **before table values
or their output functions are read**. Unsupported-object refusal in a decoder
after running all row queries would be too late.

The bounded stdin transcript decoder has no file, process, socket, restore or
credential API. It checks exact record order/count/labels, database/version and
read-only observations, supported table names, sorted row digests, scalar
cardinality, JSON/types and final table-list continuity. The decoder reports
`nativeMeasurementAuthenticated=false` and `executionAuthorized=false`: a supplied
transcript alone cannot authenticate a native measurement or grant an operation.
The fixture controller independently binds actual stdout to its owned, inspected
source/target container identities and pinned image.

Legacy `fleetory.application-signer-recovery.v2` hashing is preserved for this
supported profile. Raw PostgreSQL JSON text is UTF-8 encoded with an eight-byte
big-endian length prefix, while sorted row SHA-256 values are added as binary
bytes followed by a framed decimal row count. Security-only frames feed a separate
digest; audit snapshots retain their own canonical fingerprint. Raw text is not
reformatted or JSON-normalized before hashing. The portable golden vectors were
checked against the pin-verified historical pure encoder on generated replies,
including exact query text. Its original Session/backend entry points were not
used. No private operator module is imported as a runtime extension.

A separately versioned supplemental fingerprint adds LOGIN, connection limits,
role settings, incoming/outgoing membership and grantors, and database/role
configuration. It leaves the historical v2 hashes unchanged. A strict generated
role policy checks four application roles: two NOLOGIN owners, two runtime LOGINs,
no elevated capabilities, default connection limits, no settings or membership.
This generated policy is not an admission policy for retained original data.

`tests/Fleetory.Tools.Tests/NativePgInventoryV2.Tests.ps1` creates two non-root,
read-only-root, network-none PostgreSQL containers using the existing strict store
profile. Only tmpfs is writable; host mounts, published ports and added capabilities
remain absent. Fresh temporary runtime passwords and TLS material are generated;
original configuration, keys, provider state and VPS access are not inputs.

The source uses the real current application migrations and signer provisioning
schema: **18 tables / 24 rows** of registration/authorization/audit state and
**4 tables / 5 rows** of synthetic signer journal state. All four application roles
exist. This is distinct from the earlier 23-row devices/person fixture. Each
native dump is bounded and pinned, copied into a captured buffer, and its caller
buffer cleared. Native format checks precede target restore. Restore authenticates
as fresh postgres with an effective owner role and uses one transaction; it is
**not an untrusted archive sandbox**.

The fixture verifies both restored v2 inventories and the supplemental state,
late missing-role rollback, eight data/catalog/ACL/default/owner/membership/capability
mutations, and five real cases where historical v2 stays unchanged while the
supplement detects LOGIN/limit/settings/outgoing-membership/database-setting drift.
Runtime checks cover verified TLS/SCRAM, wrong password, plaintext, wrong CA and
DELETE denials; restart must preserve readback and runtime authentication. Owned
cleanup and a deliberately failed two-store child are independently checked.

The source is observed stable around capture; inventory and dump are separate
transactions. Neither a shared per-database dump/inventory MVCC snapshot nor global
atomicity is claimed for this generated rehearsal. The historical original
per-database snapshot evidence remains separate and is not repeated.

Portable tests run on Windows/Linux CI; the native fixture runs locally and in
Linux CI. Unchanged local .NET suites and old native restores need not be repeated.
Coverage/scanner gates, exclusions, runners, timeouts, visibility and the $0 Actions
budget remain unchanged.

This closes generated PostgreSQL v2 encoder/readback compatibility, not original
database or service recovery. The separate [generated audit history](NativeAuditHistory.md)
component measures four known events/five transactions, the full keyset and
per-key transaction, revision and value bindings without inferring them from
counts. Its source and target use distinct disposable signing identities. Keep
retained public signed-state trust separate from these generated identities. No
original private-key reuse or consumed provider/root grant follows from this test.
Independent custody/WORM/approvals, original service/configuration/provider/PKI,
revocation, physical Agent, human identity, coordinated original capture,
whole-VPS recovery and full RPO/RTO remain open. Phase 7 is incomplete and PR #2
remains draft/unmerged.
