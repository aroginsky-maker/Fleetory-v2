# Generated native Signer journal readiness

Run `tests/Fleetory.Tools.Tests/NativeJournalBackend.Tests.ps1` after restoring
the solution. This fixture uses public schema/source and newly generated PKI,
passwords and data only. It never reads operator backups, original keys or
source credentials, contacts the VPS or starts an original issuer.

`SignerJournalProbe` constructs the production `SigningHostApplication` with
the File provider in a private worker directory. It resolves the actual
registered `NpgsqlDataSource` and `SigningJournalReadiness` by its fixed type
name, then invokes that one service through `IHostedService.StartAsync`.
The readiness SQL is not copied into the probe. The full application host and
other hosted services are not started. Its HTTP lifetime is checked to remain
unstarted before a categorical result is returned. Placeholder Transit
configuration is generated and no Transit request is made.

The probe first independently verifies the role/session/database identity and
TCP TLS v1.2/v1.3 through the native data source. This prevents a network or
login failure from counting as successful detection of unsafe permissions.
The fixture accepts readiness before and after the negative cases. It rejects:

- Six privilege drifts: table UPDATE, column UPDATE, schema CREATE, owner-role
  membership, BYPASSRLS and INSERT on the revocation table.
- Five runtime SQL operations with PostgreSQL `42501`: journal UPDATE/DELETE,
  schema creation, revocation INSERT and SET ROLE to the owner.
- A wrong password with `28P01`, an untrusted TLS CA with an authentication
  exception in the native TLS handshake, and plaintext with `28000`.

Each unsafe grant is restored in a `finally` block. Authentication and SQL
refusals require exact native exception categories/SQLSTATEs, not arbitrary
exceptions. The genuine readiness service must return its known refusal for
each privilege drift. No raw SQL error, password, private key or connection
string is printed. Output is bounded and checked against generated canaries.

The fresh database has a dedicated LOGIN role and NOLOGIN owner. Its runtime
password is stored as SCRAM-SHA-256, inspected only as a boolean verifier-kind
check. HBA admits that role only over `hostssl` with SCRAM on loopback and
rejects other TCP routes. TLS v1.2 is the minimum. The fixture explicitly uses
`GSS Encryption Mode=Disable` with verified TLS/SCRAM. This avoids the optional
missing-Kerberos-library diagnostic described in the
[Npgsql 10 documentation](https://www.npgsql.org/doc/release-notes/10.0.html);
it does not ignore stderr or relax TLS authentication. Plaintext is enabled
only for its explicit negative case, which the server must reject.

## Isolation and cleanup

The digest-pinned PostgreSQL 18.6 container runs as 999:999 with network none,
no ports or host mounts, read-only root, cap-drop ALL, no-new-privileges,
384 MiB/1 CPU/128 PIDs and disabled core dumps. Three private tmpfs mounts hold
all database, socket and generated TLS state; no Docker data volume is created.
Its PID1 expires independently after 3,300 seconds with auto-removal.

The existing [native worker boundary](NativeSignerBackend.md#runtime-boundary)
is reused: pinned ASP.NET image, 1654:1654, private tmpfs, read-only validated
public-code mount, no external interfaces and only the positively owned
database's network namespace. The shared lifecycle helper publishes managed
code only, validates ownership/runtime before private writes and each probe,
protects all eight generated File-provider slots under the dedicated
`/run/fleetory-native/signer` tmpfs with 0600/0700 permissions,
and verifies absence after cleanup. Both containers expire independently.
Unknown cleanup cannot produce a verified result; both removals are attempted
even after one fails. Public payload deletion is restricted to its newly
created, resolved directory under repository artifacts.

Portable tests reject 16 unsafe PostgreSQL runtime mutations; the worker's
23 mutations remain separate checks. Windows CI runs both boundary
contracts. Linux CI also executes the native database and readiness cases.

## Acceptance limits

This proves generated-only native Signer database authentication and readiness
against real PostgreSQL. It is not Server `PlatformDbContext`/`CoreDbContext`
authentication, immudb export, a retained-role restore, full Signer HTTP/mTLS
startup or admission of an original caller. Dummy caller and Transit material
only permit unstarted builder construction; those trust paths are not tested
here. The earlier retained DB/TLS/provider operations are not repeated or
extended by this fixture. Original-material scopes require their own concrete
plan and authorization. Current revocations, human login, common-point/VPS-loss
recovery, independent WORM/custody/approvals, physical Agent and full RPO/RTO
remain open. Phase 7 and PR #2 remain incomplete.
