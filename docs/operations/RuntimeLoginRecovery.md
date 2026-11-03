# Target-only PostgreSQL LOGIN/SCRAM recovery

The earlier [application/signer restore](ApplicationDatabaseRecovery.md)
deliberately created NOLOGIN roles and excluded password recovery. This Baseline
section 17 exercise closes the separate target-only runtime-authentication and
least-privilege check. It uses the already authorized retained dump pair with
fresh random test credentials; it does not read or reset source passwords.

`eng/pilot/recovery_login.py` fixes allowed role names, password format, HBA,
readback/denial queries and acceptance counts. It emits no credentials and
performs no Docker or source operations. The fixture provides a separate owned
local PostgreSQL sandbox:

```text
python -B tests/Fleetory.Tools.Tests/recovery_login_tests.py
python -B tests/Fleetory.Tools.Tests/recovery_login_tests.py --docker
```

The first command runs seven portable contracts without Docker. The second adds
real PostgreSQL 18.6 authentication on synthetic data. The Linux CI job runs
both; Windows runs the portable contracts. Real dumps and their evidence remain
outside Git and CI. Explicit local Docker context/endpoint checks refuse remote
overrides; cached PostgreSQL/Python digest pins are required.

## Isolation and credentials

The sandbox uses `network=none`, no published ports or source binds, a read-only
root, UID/GID 999, no capabilities, no-new-privileges and fixed CPU/memory/PID
limits. A uniquely labelled data volume is initialized by a separate, bounded,
network-none ownership helper with only CHOWN capability. Resource names must
be fresh; existing containers/volumes are refused before mutation, and the new
volume's ownership label is checked before CHOWN. PostgreSQL and client
temporary paths use tmpfs. Cleanup checks exact ownership before deleting only
the sandbox container and volume. There is no global prune or source operation.

PostgreSQL listens only on a private Unix socket. The fixed HBA admits the
postgres OS/database administrator via peer, requires `scram-sha-256` for other
local roles and rejects all host connections. Parsed HBA rules and exact file
contents are checked; stored password verifiers are inspected only as booleans
for the SCRAM prefix, never returned. Owner roles remain NOLOGIN and all role
capabilities/memberships stay unchanged.

Passwords are 32 random bytes encoded as 64 lowercase hexadecimal characters.
They enter administrative SQL and mode-0600 single-link, UID-999 password files
through stdin, not CLI arguments, Docker configuration or reports. Files exist
only in the sandbox's tmpfs. For the default Unix socket directory, libpq uses
the `localhost` password-file match; the client still explicitly selects the
Unix socket. See the [PostgreSQL password-file rules](https://www.postgresql.org/docs/18/libpq-pgpass.html).
The [HBA first-match rule](https://www.postgresql.org/docs/18/auth-pg-hba-conf.html)
has no fallback to a weaker authentication method after failure.

## Verified actual-copy result on 3 November 2026

The retained application dump (18 tables/24 rows, four audit events) and signer
dump (four tables/five rows) passed their existing pinned SHA-256 checks. Their
full data/schema/owner/grant/default-privilege/role-membership inventories matched
the accepted point after restoring into the isolated new sandbox. Another
restore was necessary specifically for the previously excluded LOGIN control;
the earlier accepted recovery evidence and original dump files were preserved.

For `fleetory_server` and `fleetory_signer`, the exercise verified:

- **Eight successful readback sessions** across initial admission, rotation and
  two independent post-restart checks. Each confirms current/session user,
  database and own-table count.
- **Four permitted zero-row INSERT probes** on the audit table and three signer
  journals, inside rolled-back transactions. These prove SQL INSERT privilege,
  not a new business event or command signature.
- **21 SQLSTATE-42501 privilege denials**: schema/database/role creation, owner
  membership, superuser escalation, TEMP creation, protected audit/history/Admin
  registry rewrites and signer journal/revocation mutations.
- Two wrong-password, two old-password, two NOLOGIN-owner and two cross-database
  refusals. Failures must have the expected authentication/permission class;
  arbitrary connection or missing-table errors cannot pass as denials.
- Target-only password rotation and restart persistence, without increasing
  role grants or enabling the owner roles.

The complete before/after database inventories match, including data and
security fingerprints. LOGIN/password fields are intentionally excluded from
the old inventory algorithm, so their new acceptance uses separate explicit
role/SCRAM metadata and actual authentication checks. Temporary credentials,
container and data volume were removed; only sanitized proof remains.

## Limits

This proves regeneration/use of ephemeral target runtime credentials and
least-privilege behavior on the retained pair. It does not recover the original
passwords, test remote TCP/TLS, start Fleetory/signer/Keycloak, activate an issuer,
load original PKI/seal material or repeat OpenBao source-root recovery. The old
identity/provider snapshots keep their historical scopes; a globally atomic
point and full-system RPO/RTO remain unverified.

The [leaf-only TLS proof](LeafTlsRecovery.md) and
[native PostgreSQL TCP/TLS control](PostgresTcpTlsRecovery.md) retain separate
scopes; original-key use remains specifically gated. Next review provider
credential and issuer activation.
Human post-restore login, physical Agent trust, independent
custody/WORM/approvals and full-service acceptance remain open. Phase 7 and PR #2
remain incomplete.
