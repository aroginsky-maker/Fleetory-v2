# Keycloak identity backup acceptance

Baseline section 17 requires recovery to preserve identities, trust and security
state. The pilot's application and signer database copies are separate from the
Keycloak database. Keycloak contains password credential records, WebAuthn
public-key/counter records, realm signing private keys, client configuration and
authentication flows.

The tools here verify a bounded logical copy of that database. Retain deployment
configuration, runtime credentials, PKI/revocations, secret-provider recovery
material, audit/checkpoints and physical authenticators through their separate
custody and recovery procedures. Production RPO/RTO, WAL/PITR, retention and
independent approval/custody remain deployment acceptance controls.

## Approved data movement

Obtain approval for the exact source database, destination and custody before
transferring a real Keycloak copy. A dump includes password hashes and realm
signing private keys for all realms in the database, including administrative
realms. Keep both archive and manifest outside every Git checkout and out of
chat, CI artifacts, application secret volumes and shared directories.

The current local pilot profile uses a protected operator directory: current
Windows user, SYSTEM and Administrators only, or Unix owner-only files and
directories. This is a private local copy; independent custody and at-rest
encryption require their own deployment plan. Treat copying or deleting a
backup as an explicit operator operation. Do not delete or reset the live
database, identities, credentials, passkeys, signing keys or grants.

## Capture one consistent snapshot

Run the reviewed Python 3.11+ helper on the authorized Docker host, using a new
absolute output directory whose parent already exists:

```sh
python3 identity_backup.py capture \
  --container fleetory-pilot-postgres-1 --database keycloak \
  --realm fleetory --owner 11111111-1111-4111-8111-111111111111 \
  --output-directory /srv/fleetory/operator-backups/keycloak-approved-capture
```

The UUID is an example: use the actual existing provider subject. The helper
holds a read-only repeatable-read transaction, exports its PostgreSQL snapshot
and gives that same snapshot to `pg_dump`. Its inventory is calculated in the
held transaction, so concurrent credential/counter/session writes cannot put
the dump and expected inventory at different points in time.

Capture creates only `database.dump` and `manifest.json` with restrictive
permissions. It refuses reuse, symbolic-link/reparse ancestry and Git ancestry.
It bounds dump size to 64 MiB, table count to 512, rows to one million, query
time to 30 seconds and the operation to five minutes. Failed captures do not
produce a success marker; retain or remove their protected partial files under
the operator's cleanup policy.

Record the capture time, authorized host/image versions, helper revision and
printed `manifestSha256` through the protected evidence channel. Keep this
expected digest independently from the transferred bytes. Calculating a new
digest from an untrusted received manifest defeats this trust reference.

## Restore into an isolated scratch database

On the operator host:

```powershell
./eng/pilot/Test-IdentityBackup.ps1 -BackupPath C:\operator\private\database.dump -ManifestPath C:\operator\private\manifest.json -ExpectedManifestSha256 TRUSTED_CAPTURE_SHA256 -PythonExecutable python3
```

All input paths must be absolute, outside Git and privately protected. The
verifier checks strict bounded JSON, exact fields, true typed invariants and
the trusted manifest digest, then the retained archive's SHA-256 and custom
PostgreSQL format before creating a container.

The restore uses the pinned PostgreSQL 18.6 image in a fresh container with no
network or published ports, a read-only root filesystem, dropped capabilities,
no-new-privileges, resource limits and tmpfs database/archive storage. No host
directory or Docker socket is mounted. A separate LOGIN `restore_owner` has no
superuser, role-management, database-creation, replication, bypass-RLS or role
membership privileges. `pg_restore` connects as that role, rather than using a
superuser session with only `SET ROLE`.

PostgreSQL archives contain executable DDL. Accept only a snapshot captured
from the reviewed, trusted source database; these checks are not a general
validator for hostile SQL archives. Isolation and the restricted restore login
limit the restore's reach but do not establish trust in an unknown source.

Only the exact already-hashed archive bytes are transferred into the owned
container. SQL, archive contents, credentials and row-level digests are
suppressed from output. Cleanup removes only the validated newly created
container and its own storage; it cannot target the live deployment.

## Compared state and evidence

The shared versioned inventory hashes the schema metadata and every row of
every supported ordinary public table, with fixed PostgreSQL formatting and
deterministic ordering. Schema metadata covers visible column order, types,
defaults, nullability, identity/generated flags, collations, constraints and
indexes. It does not compare arbitrary function, trigger, RLS policy, view,
custom type or large-object definitions. Full credential and component configuration rows enter
the hash, including secret credential fields and generated signing private
keys; only one aggregate inventory digest is published.

The capture/restore invariant checks include the exact enabled owner under the
realm, cleared required actions, password and WebAuthn credential presence,
generated RSA signing material, and the native client's restricted PKCE,
redirect and token-mapper configuration. The restored inventory digest, table/
row counts and booleans must match the trusted capture.

The verifier reports `postRestoreHumanLoginVerified=false` and
`independentCustodyVerified=false`. Table equality proves preservation of the
captured records. Fresh password/passkey authentication after a real restore,
physical authenticator availability, HSM material, production role/ACL
provisioning and non-MVCC sequence state need separate checks. Preserve existing
WebAuthn counter state; an old snapshot does not authorize resetting counters
or enrolling replacement credentials.

Never expose a restored copy under the live issuer/domain or mint production
tokens from its copied signing keys. This verifier starts no restored Keycloak
service and performs no simulated WebAuthn login. A full deployment recovery
exercise needs an isolated issuer that production will reject, reviewed trust
handling and actual human authentication. Plan WebAuthn RP ID/origin continuity:
changing the RP ID makes existing passkeys unusable. Re-enrollment or counter
reset cannot be used as proof that the old identity was preserved.

## Regression fixture

`tests/Fleetory.Tools.Tests/IdentityBackup.Tests.ps1` initializes actual pinned
Keycloak/PostgreSQL on owned disposable resources, provisions only synthetic
identities/configuration on an owned bridge with only loopback Keycloak HTTP
publication, and seeds an opaque synthetic WebAuthn database
record. It exercises real capture/restore and rejection of altered or
malformed inputs. That fixture proves database preservation and parser/
isolation behavior, without claiming a human authenticator login.

References: [PostgreSQL pg_dump](https://www.postgresql.org/docs/18/app-pgdump.html)
and [exported snapshot synchronization](https://www.postgresql.org/docs/18/functions-admin.html#FUNCTIONS-SNAPSHOT-SYNCHRONIZATION).
