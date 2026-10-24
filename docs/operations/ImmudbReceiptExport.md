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

The CI test covers chain validation, atomic first export, idempotence and tamper
rejection. Production WORM retention, custody, legal hold and transfer evidence
remain deployment controls.
