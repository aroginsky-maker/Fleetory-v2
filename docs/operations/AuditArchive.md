# Pilot audit archive without an additional service

The Ubuntu pilot can keep periodic, root-owned snapshots of
`platform.audit_events` on its existing disk. No cloud account, additional
container, listener or subscription is required. The hourly systemd job reads
through the existing PostgreSQL container; it does not use OpenBao, generate
root tokens, change grants or dispatch commands.

This is **same-host pilot retention**, not independently administered WORM or
protection from the VPS/root administrator. Administrator recovery, independent
approval/custody, legal retention and full-system disaster recovery remain open
Baseline controls. These files alone must not set readiness `wormAnchor=true`.

## Captured scope and boundaries

The fixed SELECT names all ten audit columns explicitly, including event and
actor identifiers, action, target, correlation, UTC timestamps and context JSON.
It also records the export-queue count from the same read-only, repeatable-read
transaction. `context_json` is retained as PostgreSQL's exact JSON text, with
Decimal-aware syntax validation, so numeric values above IEEE-754 precision
cannot collapse or hide a history rewrite. Future database columns are excluded. Passwords, private keys,
Keycloak tables, OpenBao state and signer journal rows are outside this capture.
Audit records may themselves contain confidential operational data: never put
raw snapshots/exports in Git, PR descriptions, logs or chat.

The operator helper uses a fixed container/database and fixed SQL. The existing
administrative Docker channel is privileged; it is not a new least-privilege
database principal. PostgreSQL is additionally forced read-only, with a
10-second statement timeout and two-second lock timeout. The process bounds
stdout and terminates its own Docker client on timeout/failure. This is a
periodic operator operation, not a synchronous application request dependency.
Server CLI commands also use the fixed `/var/lib/fleetory-audit-archive` root;
there is no argument or environment override for that directory.

Every changed snapshot receives a sequential receipt containing its SHA-256,
capture time and the preceding receipt SHA-256. Exact repeats are idempotent.
All previous event IDs and canonical content must remain in each later
snapshot; deletion or rewriting fails before publication. Pending queue-count
changes can produce a new observation without changing historical events.

The archive uses private root directories (`0700`) and sealed regular files
(`0400`). Cooperating publishers hold an exclusive file lock across validation
and publication. New files use exclusive creation; a complete, fsynced private
staging directory is renamed into the next sequence before success is returned.
Broken chains, incomplete publication, unexpected entries, links, multiple hard
links and changed permissions fail closed. It never repairs or resets history.
Ordinary application identities have no archive access or mount.

## Capacity and scheduling

Pilot limits are 8 MiB / 10,000 events per complete snapshot, 4,096 observations,
and 64 MiB of retained snapshot/receipt bytes. Publication also requires at least
512 MiB of free filesystem space. These are pilot guardrails, not supported
production sizing. The archive stops rather than deleting retained records or
growing past its cap. There is **no automatic deletion or certified retention
period**; an operator must resolve a capacity failure and retain its evidence.

`fleetory-audit-archive.timer` runs hourly in UTC with up to 30 seconds of jitter;
`Persistent=true` catches a missed calendar run when the timer becomes active.
That is the pilot observation interval, not a universal RPO. Unchanged history
does not consume another entry. Monitor the service's exit status: the timer
does not make a failed capture successful.

The oneshot has a read-only system view, one writable state directory, no
capabilities, no-new-privileges, Unix sockets only, a 40-second timeout, 256 MiB
memory limit and 10% CPU quota. It creates no new network route. It still shares
the host administrator and storage failure domain with the application.

## Installation and verification

After tests and CI have passed, copy the reviewed helper/installer to
`/srv/fleetory/eng/pilot/` and the service/timer templates to
`/srv/fleetory/infra/pilot/`. Keep their owner root and disallow group/other
writes. The installer validates every parent directory up to the filesystem
root, plus source files and reused unit owners/modes, before running the helper
or changing any unit. Maintain these parent protections for the entire service
lifetime. Changed existing unit files and links are rejected.

```sh
sudo bash /srv/fleetory/eng/pilot/install-audit-archive.sh
sudo python3 /srv/fleetory/eng/pilot/audit_archive.py verify
sudo systemctl status fleetory-audit-archive.service fleetory-audit-archive.timer
```

The compact summary contains counts and hashes, never event bodies. It always
reports `independentCustodyVerified=false`, `administratorTamperProof=false`
and `sourceSignedStateVerified=false`. Receipt hashes are integrity checks, not
signatures from an independent custodian or immudb signed-state verification.
Keep the existing pinned immudb state/receipt verification as separate evidence.

## Copy and verify outside the VPS

Export only through the approved, host-key-pinned SSH channel into a private
directory on the operator's separate computer. `export` checks the retained
archive and emits a bounded package of its receipt chain and latest complete
snapshot. Record the transfer hash through that approved channel and retain the
copy/hash outside the VPS. The initial checkpoint relies on the operator's
first trusted observation; it does not authenticate independent approval.

```text
cd PRIVATE_EXPORT_DIRECTORY
python ABSOLUTE_PATH_TO_TOOL/audit_archive.py verify-export --input export.json --expected-sha256 TRUSTED_SHA256
python ABSOLUTE_PATH_TO_TOOL/audit_archive.py verify-export --input export-new.json --expected-sha256 NEW_TRUSTED_SHA256 --checkpoint checkpoint-old.json --expected-checkpoint-sha256 OLD_TRUSTED_SHA256
```

Choose the private working directory as the caller. File arguments are ASCII
basenames only: `export.json`, `checkpoint.json`, or either prefix followed by a
hyphen and up to 64 letters/digits/underscores/hyphens. Absolute paths, directory
components, traversal, links and arbitrary JSON filenames are rejected before
reading. Resolved inputs must remain immediate children of the chosen directory.
Copy a retained checkpoint there and carry its separately retained trusted hash
forward. These path checks do not establish Windows atomic path custody or ACLs;
the caller must preserve the private working directory and trusted checkpoint.

The portable verifier checks the retained bytes, unique/typed fields, chain,
snapshot hash and, when supplied, the complete approved receipt prefix and
unchanged old events. Recomputing a digest from an untrusted replacement is not
approval of that replacement. Keep the checkpoint and its approved digest under
separate access control. Windows and Linux both run its regression cases.

Restoring an export into an empty directory and verifying it demonstrates
artifact preservation, not application/PKI recovery. This archive cannot
survive loss of the VPS unless an off-host copy has actually been made; the
local copy has its own availability and custody requirements.

## Tests and rollback

`AuditArchive.Tests.ps1` uses disposable, network-isolated PostgreSQL and a
digest-pinned Python image. Real SQL preserves Unicode, excludes an extra
synthetic sensitive column and rejects a write in read-only mode. Linux tests
exercise private files, an unprivileged process, links, corruption, concurrency,
capacity failure and restart. Portable cases cover exact-byte hashes, duplicate
JSON, schema errors, rollback and rehashed history substitution against a saved
checkpoint. Two actual PostgreSQL decimal values above 2^53 remain distinct and
rewriting the retained value is rejected. Installer tests exercise writable,
foreign-owned and symbolic parents and changed/untrusted existing units before
the helper can run. No test uses the pilot, real events or credentials.

To stop future observations, disable the timer; this preserves every archive:

```sh
sudo systemctl disable --now fleetory-audit-archive.timer
```

Do not delete snapshots to hide a failed check. Retain the data, service result
and reviewed recovery decision. Stopping this timer does not disable the
application's durable audit/outbox or immudb export.
