# Native PostgreSQL TCP/TLS recovery

Baseline section 17 already has [retained database LOGIN/SCRAM](RuntimeLoginRecovery.md)
acceptance over private Unix sockets and a separate [original leaf-pair proof](LeafTlsRecovery.md).
Those results do not demonstrate native PostgreSQL TLS or plaintext downgrade
refusal. This exercise adds that distinct transport control with regenerated,
disposable test PKI and fresh target-only passwords.

```text
python -B tests/Fleetory.Tools.Tests/recovery_postgres_tls_tests.py
python -B tests/Fleetory.Tools.Tests/recovery_postgres_tls_tests.py --docker
```

Eight portable contracts run on Windows and Linux. Linux CI additionally starts
a pinned real PostgreSQL 18.6 fixture with synthetic databases and fresh test
certificates. It does not receive retained real dumps or original PKI. The local
synthetic exercise passed two TLS 1.3 readbacks with
`TLS_AES_256_GCM_SHA384`, plus two refusals each for wrong CA, wrong hostname,
plaintext and wrong password.

## Isolation and admission

The fixture reuses the accepted LOGIN sandbox's local-context, fresh-resource,
volume-ownership and runtime checks. The container uses network none with no
published ports, a read-only root, UID/GID 999, dropped capabilities,
no-new-privileges and fixed CPU/memory/PID limits. The only persistent mount is
its uniquely labelled data volume. TLS and password files enter owned tmpfs
through stdin with 0600/single-link/UID-999 checks. No credentials are placed in
CLI arguments or Docker environment/configuration. Generated test PKI stays
outside Git and is removed with the fixture. Original leaf keys are not reused.

PostgreSQL listens only on container loopback. Its fixed HBA admits the postgres
administrator through Unix-socket peer, rejects other local roles, admits only
the two exact runtime role/database pairs through loopback `hostssl` with
SCRAM-SHA-256, then rejects every other IPv4/IPv6 host connection. File contents,
parsed HBA errors and `listen_addresses`, `ssl` and minimum TLS settings are
checked. Owners remain NOLOGIN; no grants or memberships are added.

libpq explicitly uses `sslmode=verify-full`, expected hostname `postgres`,
hostaddr `127.0.0.1` and a dedicated generated root file. GSS encryption is
disabled for this TLS-specific proof. Each successful session checks current
and session user, database, own-table count and its own `pg_stat_ssl` row.
TLS must be at least 1.2 with a non-empty cipher. Wrong CA/name, plaintext and
wrong-password failures must match their specific native libpq/HBA diagnostics;
an arbitrary connection failure or missing table cannot pass as a refusal.

## Accepted actual-copy result on 3 November 2026

The reviewed tool at `14e6b56e4fbb5b4b56e15eac5624469c7636b35c` passed on the
already authorized retained application/signer pair: 18 tables/24 rows and four
tables/five rows. Both native runtime sessions used TLS 1.3 with
`TLS_AES_256_GCM_SHA384`, verified the generated server root/name and returned
the expected four audit events and one signing-result row. Two refusals each
for wrong CA, wrong hostname, plaintext and wrong password passed.

Complete before/after inventories matched the accepted data, schema, owners,
table/column/default grants and role capabilities/memberships. As in the prior
inventory algorithm, password and LOGIN fields are excluded from those hashes;
separate explicit checks verified two runtime LOGIN/SCRAM roles, two NOLOGIN
owners and no elevated role capabilities. The sanitized actual proof, exact
dump/tool hashes and inventory records remain private.

The target container/volume and generated test-material directory were removed,
with explicit absence checks. Source dump files were only read. No original
PKI, source passwords, VPS access, new source backup, provider/root/issuer
operation or production tokens were used. The earlier privilege, rotation and
original-leaf acceptance operations were not repeated.

## Actual-copy boundary

The existing explicit permission for retained application/signer copies covers
an isolated target restore. Such a new target is necessary specifically for the
previously excluded TCP/TLS control. Before using retained data, first pass the
synthetic contract/fixture, pin the retained dump hashes and accepted full
inventories, and retain the concrete execution plan. Check complete inventories
before and after, preserve all original dump files, and remove only owned
container/volume/tmpfs/generated material. Keep real evidence private.

Do not repeat the earlier 21 privilege checks, password rotation, original-leaf
operation or historical provider/identity recovery merely to claim this new
transport result. No new source backup, original password, original PKI,
provider token, seal share, source-root recovery or issuer activation is needed.

## Limits

Container loopback PostgreSQL/libpq TLS with regenerated test credentials does
not establish external routing/firewall policy, deployed certificate equality,
production trust distribution, mTLS client authorization or application startup.
It does not join historical identity/provider snapshots into a common recovery
point or verify human login, physical Agent trust, independent WORM/custody or
full-system RPO/RTO. Next use the separately scoped
[configuration/File-provider preflight](RecoveryConfiguration.md). Phase 7
remains open and PR #2 remains draft.
