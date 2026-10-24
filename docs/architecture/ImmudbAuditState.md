# immudb signed-state receipts

Fleetory's REST audit sink proves that one `EventId` can be written once and read back at revision 1. That check does not prove that the immudb server has not been rolled back or replaced. The separate `eng/verify-immudb-state.ps1` operation records an independently reviewable state receipt.

## State endpoint and signature

The verifier reads `GET /api/db/state` from an HTTPS origin. immudb exposes this endpoint as `ImmuService_CurrentState`; its `ImmutableState` contains the selected database name, the latest committed `txId`, a 32-byte `txHash`, and an optional `Signature` containing `publicKey` and `signature` bytes. Fleetory requires the expected database (`defaultdb` unless explicitly changed), a positive transaction ID, a 32-byte hash, and a signature. It pins the operator key and verifies the immudb v1.11.2 signing payload: a big-endian uint32 database-name length, UTF-8 database name, big-endian uint64 transaction ID and transaction hash. The signature is ECDSA P-256 ASN.1 DER, and `publicKey` is the 65-byte uncompressed point; verification uses the managed .NET cryptography API. A missing key, malformed base64, public-key mismatch, invalid signature or non-HTTPS origin fails closed.

The `/api/db/state` endpoint is not an audit writer API and must be reachable only through the restricted immudb network path. The verifier never sends a write request and never receives the Fleetory audit-writer secret. A bearer token can be supplied for deployments that protect the endpoint even though the upstream REST schema marks CurrentState as unauthenticated.

## Receipt anchor

The verifier writes newline-delimited canonical JSON receipts to an absolute anchor path. Each receipt has schema `fleetory.immudb-state-receipt.v1`, database, `txId`, base64 `txHash`, base64 state signature, SHA-256 of the pinned 65-byte public point and UTC observation time. The append operation has these invariants:

- an identical latest transaction is idempotent;
- a lower transaction ID is rejected as rollback;
- a changed hash at an existing transaction is rejected as a fork/conflict;
- a symbolic-link anchor and a relative path are rejected;
- malformed existing receipts stop the run before any append.

A local file is only a tamper-evident operational receipt. Production must send the receipt to a separate administrator-controlled WORM/object-lock or SIEM destination and retain the public-key fingerprint in a second control plane. The local path must not be treated as independent evidence when the Fleetory host and anchor share the same administrator.

Run the verifier from a protected scheduler or operator host:

```powershell
$env:FLEETORY_IMMUDB_STATE_BEARER_TOKEN = '<short-lived-token>'
./eng/verify-immudb-state.ps1 `
  -Address https://immudb-audit.example/ `
  -PublicKeyPath C:\ProgramData\Fleetory\immudb-state-public.pem `
  -AnchorPath C:\ProgramData\Fleetory\audit-state\receipts.ndjson
Remove-Item Env:FLEETORY_IMMUDB_STATE_BEARER_TOKEN
```

Keep the public key outside Git and rotate it through a dual-approved procedure. During a key rollover, verify both old and new keys against the approved overlap window, then archive the prior fingerprint in the external anchor. A key change without an approved receipt is an incident, not a successful rotation.

## What this does not establish

The verifier does not create a backup, restore a database or enforce retention. immudb retention can remove old value-log data while preserving proofs and schema; the retention period must therefore be chosen from the audit policy and recovery objective. Backups must be created by a separately privileged immudb administrator, copied to immutable off-host storage and restored in a disposable environment. The restored database must pass signed-state and known-EventId checks before it is considered usable. The repeatable acceptance procedure is documented in [ImmudbBackupRestore](../operations/ImmudbBackupRestore.md) and exercised by `tests/Fleetory.Tools.Tests/ImmudbRestoreAcceptance.Tests.ps1`.

The current Fleetory sink still uses HTTPS and a dedicated read/write audit account. Production must also configure TLS certificate trust, restrict the admin API, rotate writer credentials and keep immudb administrator credentials outside Fleetory.

References: [immudb state management](https://docs.immudb.io/master/management/state), [immudb REST schema](https://github.com/codenotary/immudb/blob/master/pkg/api/schema/schema.swagger.json), [immudb retention](https://docs.immudb.io/1.5.0/production/retention), and [immuadmin backup/restore](https://docs.immudb.io/1.3.1/connecting/clitools).
