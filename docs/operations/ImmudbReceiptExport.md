# immudb receipt export package

The local signed-state anchor can be packaged for transfer to an independently
administered WORM or SIEM destination:

    ./eng/export-immudb-receipt-anchor.ps1 -AnchorPath C:\ProgramData\Fleetory\audit-state\receipts.ndjson -ExportPath C:\ProgramData\Fleetory\audit-state\outbox\receipts-export.json

The operation re-validates every receipt and the SHA-256 chain, records the
database, transaction range, receipt count and exact source-anchor SHA-256, and
writes the package atomically without overwriting an existing different file.
Parsing and source-anchor hashing use the same bounded byte buffer. Anchors and
packages are limited to 8 MiB, and an output that exceeds the package limit is
rejected before creation. Existing export files are also checked for symbolic
links and size limits before idempotence comparison. The exporter runs on
PowerShell 7 and Windows PowerShell 5.1.
Repeating the same export is idempotent. Copy the resulting package to the
independently administered WORM/object-lock or SIEM destination and retain its
object identifier with the restore record. The script never deletes the local
anchor or contacts the external destination.

Before transfer, an independent operator can verify the package without access to
the Fleetory writer credential or the immudb server:

    ./eng/verify-immudb-receipt-export.ps1 `
      -ExportPath C:\ProgramData\Fleetory\audit-state\outbox\receipts-export.json `
      -AnchorPath C:\ProgramData\Fleetory\audit-state\receipts.ndjson `
      -PublicKeyPath C:\ProgramData\Fleetory\trust\immudb-state-public.pem

The verifier is read-only. It checks the export schema, receipt count and
transaction range and re-validates the receipt chain. With `-AnchorPath`, it
checks both the exact source-file SHA-256 and every receipt against that same
source buffer: count, order, signed state, chain hashes and observation time.
`anchorPathVerified` becomes true only after both checks. A matching claimed
hash alone cannot bind a truncated, extended or substituted signed receipt set.
Receipt v1 has exactly its nine defined fields; coerced numeric/string types,
missing fields and unbound extra fields are rejected. JSON property order and
whitespace are immaterial, and observation times are compared as UTC instants
so equivalent timezone spellings remain compatible across PowerShell versions.

With `-PublicKeyPath`, the verifier additionally checks every receipt signature
against the pinned P-256 public key. Without these optional paths, a successful
run establishes only structural/chain consistency: the corresponding
`anchorPathVerified` and `signaturesVerified` flags remain false. Before WORM
transfer, use both independently approved inputs and retain both true flags
and the exact `exportSha256` from the deterministic verification summary.

## Previously approved checkpoint

To detect rollback of both a candidate package and its matching local anchor,
retain a previously verified cumulative export in the independent WORM system.
Record its exact `exportSha256` in the approved change record. On the next run,
retrieve that specific retained version and pass the separately approved digest:

```powershell
./eng/verify-immudb-receipt-export.ps1 `
  -ExportPath C:\ProgramData\Fleetory\audit-state\outbox\receipts-export.json `
  -AnchorPath C:\ProgramData\Fleetory\audit-state\receipts.ndjson `
  -PublicKeyPath C:\ProgramData\Fleetory\trust\immudb-state-public.pem `
  -CheckpointPath C:\ProgramData\Fleetory\independent-evidence\previous-export.json `
  -ExpectedCheckpointSha256 '<SHA-256 from the independent approval record>'
```

Checkpoint mode requires both checkpoint arguments and the pinned public key.
It checks the checkpoint's exact file digest, schema, chain and every signature,
then requires the candidate to use the same database and retain the entire
checkpoint receipt sequence as its unchanged prefix. A shorter history, a
rewritten state at the same transaction, a higher transaction with rewritten
earlier history, or changed observation metadata fails. The identical approved
package is idempotent; a valid append-only extension is accepted.

The summary adds `checkpointVerified=true`, `checkpointExportSha256`,
`checkpointReceiptCount` and `checkpointLastTxId`. Without checkpoint inputs,
`checkpointVerified` is explicitly false. Validation never updates the retained
checkpoint. After independent review, copy the newly verified export to a new
immutable object version and record its SHA-256 for the next run; retain the
previous approved versions.
The first checkpoint requires independent source/signature review and explicit
approval; without a predecessor the tool cannot establish earlier history.

Do not recompute the expected digest from a suspect checkpoint file or obtain
both inputs from an untrusted candidate host. The independent system must supply
the latest approved checkpoint identity and digest. The check establishes
preservation of that receipt history, not global freshness or an immudb Merkle
consistency proof for later transactions. It does not fetch WORM objects,
authenticate approvals or enforce retention.

The source anchor and pinned key must be independently trusted. Matching a
package to a local file alone cannot prove freshness or detect replacement of
both with an older valid snapshot; the independently identified checkpoint and
off-host retention provide that boundary. Keep input directories protected and coordinate
export with the receipt writer; one read buffer is not a filesystem snapshot
against an untrusted concurrent writer.

The CI tests cover a valid signed prefix, rebased suffix, extension, substituted
signed state with unchanged count/range, changed observation metadata, a source
file changed after reading, size/UTF-8 failures and equivalent formatting. Both
export and independent verification run on Linux and Windows PowerShell 5.1.
Checkpoint tests cover joint candidate/anchor rollback, signed historical forks,
database mismatch, changed metadata, wrong or missing digest, invalid checkpoint
signatures, and valid idempotent/forward histories on both runtimes.
The scripts never contact the external destination. Production WORM retention,
custody, legal hold and transfer evidence remain deployment controls.
