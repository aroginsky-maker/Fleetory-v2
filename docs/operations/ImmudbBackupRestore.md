# immudb backup and restore acceptance

This procedure is the production boundary around the Fleetory immudb audit sink. Fleetory owns the audit writer account and the signed-state receipt verifier. The immudb administrator owns backup, restore, retention and the independent receipt destination.

## Credentials and storage

Use separate identities for each operation:

- The Fleetory writer is a dedicated database-scoped read/write user for `defaultdb`. It is supplied to Fleetory through the secret provider and is never used for backup or restore.
- The backup and restore operator is an immudb administrator account held in the deployment credential manager. Its password is never placed in Fleetory configuration, command output, the repository or the restore acceptance record.
- The acceptance check uses a short-lived read-only bearer token. It can read the restored state and the selected audit key but cannot write keys, change users or create backups.
- The immudb public signing key fingerprint is approved and retained in a second control plane. A changed fingerprint requires a separate incident and key-rollover approval.

Keep backup files and receipt anchors outside the Fleetory host. The backup destination must use administrator-controlled immutable storage with object lock or an equivalent WORM policy. Record the retention period, legal hold policy and restore point in the change record.

## Backup and disposable restore

1. Record the current immudb database name, latest signed state (`txId`, `txHash` and public-key fingerprint), the retention policy and the audit `EventId` selected for acceptance.
2. With the separate immudb administrator identity, create a full backup or PITR-consistent backup according to the installed immudb version. Write it to the immutable off-host destination. Do not pass the Fleetory writer credential to `immuadmin`.
3. Restore the backup into a disposable immudb instance isolated from production. Provision its TLS certificate and the approved public signing key. Do not attach the disposable instance to the production audit writer path.
4. Create a short-lived read-only bearer token for the disposable instance. Grant only the database read permission needed for `GET /api/db/state`, `GET /api/db/use/{database}` and `GET /api/db/get/{key}`. The verifier selects the expected database and uses the returned database-scoped token for the acceptance readback.
5. Run the acceptance verifier from a protected operator host:

```powershell
$env:FLEETORY_IMMUDB_RESTORE_READ_TOKEN = '<short-lived-token>'
./eng/verify-immudb-restore.ps1 `
  -Address https://restored-immudb.example/ `
  -PublicKeyPath C:\ProgramData\Fleetory\immudb-state-public.pem `
  -AnchorPath C:\ProgramData\Fleetory\audit-state\restore-receipts.ndjson `
  -KnownEventId 00000000-0000-0000-0000-000000000001 `
  -ExpectedValueSha256 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF `
  -ExpectedRevision 1
Remove-Item Env:FLEETORY_IMMUDB_RESTORE_READ_TOKEN
```

The expected value hash is calculated from the decoded `value` returned by immudb for the selected `fleetory/audit/v1/{EventId:N}` key. Store that hash in the approved change record before the restore check. The script refuses HTTP, redirects, a wrong key, a wrong revision, a changed value, an invalid signed state, a rollback or a fork. It appends a local receipt only as a verification trace; copy that receipt to the independent WORM/SIEM destination before destroying the disposable instance.

For acceptance of an exact approved backup point, also supply
`-CheckpointPath <retained-export.json>` and
`-ExpectedCheckpointSha256 <digest-from-independent-change-record>`. Both
arguments are required together. The shared receipt verifier checks the exact
checkpoint bytes, schema, chain and every P-256 state signature against
`-PublicKeyPath`, before any remote request. The checkpoint database must match
`-ExpectedDatabase`. The restored transaction ID **and** transaction hash must
equal its final receipt; both older and newer states are rejected. Capture this
checkpoint at the approved backup boundary and retain its exact object version
and digest independently, as described in [ImmudbReceiptExport](ImmudbReceiptExport.md).

Acceptance reads and verifies the signed state, checks the known EventId, then
reads/verifies the signed state again. A changed transaction, hash or key
fingerprint rejects the run. Keep the disposable restore isolated and quiescent;
these checks are not a Merkle inclusion/consistency proof for the readback value.
The local anchor is appended only after all state, checkpoint and event checks
pass. Failed checks neither create nor advance it, and repeating a successful
acceptance is idempotent. Persisted state receipts include the preceding receipt
hash correctly when the live verifier returns an ordered dictionary.

The summary includes `receiptTxHash`, `checkpointVerified` and
`checkpointExportSha256`. Without checkpoint inputs, the flag is explicitly
false: local monotonicity and known-event checking alone do not prove that an
empty or jointly rolled-back local environment reached the independently
approved backup point. The verifier never updates the approved checkpoint.

Database selection, signed-state retrieval and audit readback use the same
HTTPS transport. Each read has a 20-second total deadline and a 16 KiB body
limit enforced during streaming, including responses without Content-Length.
Redirects are rejected before any request to the new address, and failure
messages include neither the read-only token nor remote response content.
Cookies and environment proxies are disabled. The operator host must trust the
approved CA and satisfy OS certificate/hostname/revocation checks; production
verification has no option to disable these checks.

6. Confirm the script output contains `fleetory.immudb-restore-acceptance.v1`, the expected database, the restored signed-state transaction and the expected EventId/revision/hash. Capture the output and the WORM object identifier in the change record.
7. Revoke the read-only token, destroy the disposable instance and retain the backup, restore log, acceptance output and WORM receipt for the approved retention period.

## Local disposable-drill evidence

On 2026-10-24 the checked-in security lab was used to verify the backup and restore mechanics without touching the running lab volume's data. The immudb `1.11.2` container produced a hot backup of `defaultdb` containing transactions 1 through 33 (19,908 bytes). A separate disposable immudb container restored that archive into a newly created replica database named `restored`; `immuadmin database list` reported the database as `LOADED`, `Is Replica=TRUE` and `Transactions=33`. The disposable container and temporary archive were destroyed after the check.

This evidence validates the local command path only. It does not replace production TLS, immutable off-host retention, independent WORM/SIEM anchoring, key custody or the read-only restore acceptance check described above.

## Acceptance criteria

- The backup was created by the separate immudb administrator and is present in immutable off-host storage.
- The restore was performed into a disposable instance with TLS and the approved signing key.
- The known audit `EventId` is present at the expected revision and its decoded value hash matches the change record.
- The signed state is valid, monotonic relative to the receipt anchor and uses the approved public-key fingerprint.
- A rollback, fork, malformed state, redirect, wrong EventId, wrong revision or changed value causes a non-zero exit.
- The Fleetory writer credential is absent from all backup, restore and acceptance command lines and output.
- The restore output and signed-state receipt are copied to the independently administered WORM/SIEM destination.

This procedure supplies repeatable acceptance evidence. It does not by itself prove that a production retention policy, object-lock configuration or key-custody process is correctly deployed; those controls require the external administrator's records and a scheduled restore drill.

## Actual pilot off-host restore on 2 November 2026

The deployed pilot writes to **`fleetoryaudit`**, not `defaultdb`. Select the
configured writer database explicitly for backup and acceptance; an empty
`defaultdb` is not evidence that the audit sink is empty. The capture used the
existing administrative credential, authenticated TLS with CA/hostname checks,
and a digest-pinned `immuadmin` client in the audit service's network namespace.
No new public port, source database, grant, password or production policy was
created or changed. The original application and signer were not restarted.

The hot backup retained transactions 1 through 5 in 3,342 bytes. Four known
Platform EventIds were read at the source and retained as acceptance hashes and
revisions. The signed transaction/hash/key tip was unchanged across capture.
Only audit database transactions were transferred to the owner's protected
Windows offline directory; no private signing key was downloaded from the VPS.

A separate local Docker instance used `network=none`, no published ports, UID
3322, a read-only root, no capabilities and a uniquely labelled data volume.
It restored the real backup, using the signing and TLS material already held by
the operator. Its transaction/hash/key tip matched the captured source, and all
four known events matched their exact value hashes and revisions. A disposable
read-only user could read them and was denied a write with an unchanged tip.
This build reports that native denial as HTTP 500 / gRPC code 13 with the exact
message `permission denied`; the check did not mistake an arbitrary error for
a permission test or claim HTTP 403. Restart preserved the restored state and
reader access. A changed backup checksum caused an actual restore rejection;
the failed target was discarded.

Existing Fleetory offline functions independently verified the source signature
and three restored-state signatures against the retained public key. They
checked the source receipt checkpoint, all four event readbacks, rejection of a
changed signature/value and idempotent receipts for the same state. The original
operator receipt anchor was not modified. The HTTPS observations were captured
by the isolated probe; this did not exercise the standalone PowerShell HTTP
transport against the clone. Checkpoint validity here is local verification,
not authenticated approval by an independent custodian.

The image's `IMMUDB_ADMIN_PASSWORD` overrides the same TOML setting. The isolated
fixture supplied a fresh disposable password through a private environment file;
it did not reuse or reset the source administrator password. That file and CLI
token state were removed with the owned containers and data volume. Temporary
source backup files were removed only after the retained copy and restore had
passed. Raw audit bodies, key material and private evidence remain outside Git.

This closes the bounded real-audit-database recovery check using tooling from
`c7e5ef0`; it does not identify that checkout as the deployed application binary
revision. It does not establish independent WORM/retention/legal hold, production
key custody, a coordinated cross-service restore point, PKI/revocation/Agent
recovery, a production RPO/RTO or full-system recovery. No OpenBao source-root
recovery was repeated. PHASE 7 remains open.
