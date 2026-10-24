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

6. Confirm the script output contains `fleetory.immudb-restore-acceptance.v1`, the expected database, the restored signed-state transaction and the expected EventId/revision/hash. Capture the output and the WORM object identifier in the change record.
7. Revoke the read-only token, destroy the disposable instance and retain the backup, restore log, acceptance output and WORM receipt for the approved retention period.

## Acceptance criteria

- The backup was created by the separate immudb administrator and is present in immutable off-host storage.
- The restore was performed into a disposable instance with TLS and the approved signing key.
- The known audit `EventId` is present at the expected revision and its decoded value hash matches the change record.
- The signed state is valid, monotonic relative to the receipt anchor and uses the approved public-key fingerprint.
- A rollback, fork, malformed state, redirect, wrong EventId, wrong revision or changed value causes a non-zero exit.
- The Fleetory writer credential is absent from all backup, restore and acceptance command lines and output.
- The restore output and signed-state receipt are copied to the independently administered WORM/SIEM destination.

This procedure supplies repeatable acceptance evidence. It does not by itself prove that a production retention policy, object-lock configuration or key-custody process is correctly deployed; those controls require the external administrator's records and a scheduled restore drill.
