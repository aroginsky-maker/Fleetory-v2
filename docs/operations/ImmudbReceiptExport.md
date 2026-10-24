# immudb receipt export package

The local signed-state anchor can be packaged for transfer to an independently
administered WORM or SIEM destination:

    ./eng/export-immudb-receipt-anchor.ps1 -AnchorPath C:\ProgramData\Fleetory\audit-state\receipts.ndjson -ExportPath C:\ProgramData\Fleetory\audit-state\outbox\receipts-export.json

The operation re-validates every receipt and the SHA-256 chain, records the
database, transaction range, receipt count and exact source-anchor SHA-256, and
writes the package atomically without overwriting an existing different file.
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
transaction range, re-validates the receipt chain, compares the exact source
anchor SHA-256 when `-AnchorPath` is supplied, and verifies every receipt
signature against the pinned P-256 public key when `-PublicKeyPath` is supplied.
It emits a deterministic verification summary and never contacts the external
destination. The CI tests cover valid and self-contained verification, wrong
anchor/key, chain tampering and path rejection. Production WORM retention,
custody, legal hold and transfer evidence remain deployment controls.
