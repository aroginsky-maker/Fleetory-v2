# Pilot application and signer database recovery

This procedure covers the existing `fleetory` and `fleetory_signer` PostgreSQL
backups under Baseline section 17. It preserves the approved database scope;
Keycloak, OpenBao, credential files, PKI and physical-Agent state are separate
recovery controls. Dumps and detailed proofs contain operational data and stay
in the protected operator offline directory, outside Git and PR descriptions.

## Capture and acceptance boundary

For each database, a read-only repeatable-read transaction exports a snapshot.
Both its logical inventory and custom-format `pg_dump` use that held snapshot.
The session remains open until the dump has finished and its digest is retained.
See the PostgreSQL 18 [pg_dump reference](https://www.postgresql.org/docs/18/app-pgdump.html)
and [snapshot transaction interface](https://www.postgresql.org/docs/18/sql-set-transaction.html).

The databases use separate snapshots. Fresh post-capture inventories must match
both captured inventories, and the signed immudb checkpoint must remain the
same before and after capture. This verifies an observed stable capture window;
`globalAtomicSnapshotClaimed` remains false. It is not a distributed transaction
or a fence against concurrent or adversarial changes. A changed observation
blocks acceptance; it does not reset the expected digest or edit the source.
Sequence values are not MVCC state and are additionally compared as observed
`last_value`/`is_called` values; no global sequence snapshot is claimed.

The inventory includes supported pilot tables, column definitions, constraints,
indexes, UTC-normalized row hashes with multiplicity, owners, database/schema/
table/column/sequence ACLs, default privileges, role capabilities and memberships.
It refuses unsupported executable, policy, foreign, partitioned and extension
objects instead of silently treating them as ordinary pilot tables. The row
hashes are produced inside PostgreSQL; rows and SQL diagnostics are not printed.
Role passwords and LOGIN recovery are excluded. Disposable roles are created
NOLOGIN, without superuser, role/database creation, replication or BYPASSRLS.

Preserve dump ownership and ACL entries when restoring into the isolated
cluster. Create the approved role names before `pg_restore --create`; do not
substitute a counts-only check or grant broad runtime permissions to make a
failed restore pass. Compare the complete inventory after restoration and after
a cluster restart. The restored Platform audit snapshot must match the retained
four-event export and the already verified immudb recovery evidence.

## Verified pilot result on 2 November 2026

Using the owner's earlier explicit approval for application/signer database
copies, new dumps were captured without modifying source application data,
roles, passwords, policies or PKI. Each dump and inventory shared one held MVCC
snapshot; all post-capture inventories matched. Both fresh immudb state
signatures were independently checked against the retained public key and the
previously verified transaction-5 checkpoint. Its hash/key tip did not change.

The application dump restored **18 tables and 24 rows**; the signer dump
restored **4 tables and 5 rows**. All captured row, schema and security
fingerprints matched. The application now contains the same **four audit
events**, exact snapshot digest and empty export queue as the retained audit
export; the previous full application snapshot contained only three events.

A uniquely labelled Docker cluster used the pinned PostgreSQL 18.6 image,
`network=none`, no published ports, UID 999, a read-only root, no capabilities and
a private data volume. The following nine negative cases were detected only in
that disposable clone:

- changing an audit action;
- deleting a signing-rejection row;
- removing a runtime table grant;
- adding a runtime column-update grant;
- changing default table privileges;
- changing a journal table owner;
- granting BYPASSRLS to the signer runtime role;
- adding membership in the signer owner role;
- restoring the older three-event application dump as the current point.

Each transactional mutation was rolled back and the baseline inventory matched
again. Restart preserved both databases and their inventories. The old dump was
retained unchanged as an explicit stale-point counterexample; it was rejected
rather than promoted to the current recovery set. The owned containers and data
volumes were removed. Source staging was removed only after both retained
copies and restores passed their hash checks. The Windows directory ACLs were
checked for the operator, SYSTEM and Administrators, with inheritance disabled.
Executed operator scripts and their SHA-256 manifests are retained privately.

This evidence uses tooling from `a261e13`; that checkout is not asserted to be
the deployed application binary revision. It validates database state/schema/
permission preservation in the supported pilot scope, with a stable observed
audit boundary. It does not validate recovered runtime passwords, external
approvals, independent WORM custody, identity-provider login, secret-manager
recovery, configuration/PKI/revocation/Agent recovery or full-system RPO/RTO.
No OpenBao source-root recovery was repeated. PHASE 7 remains open.
