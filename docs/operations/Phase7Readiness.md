# PHASE 7 deployment-readiness record

The final deployment gate can be checked before approval with:

    ./eng/verify-phase7-readiness.ps1 `
      -RecordPath C:\ProgramData\Fleetory\evidence\phase7-readiness.json

The read-only verifier requires a UTF-8 JSON object of at most 64 KiB using the
`fleetory.phase7-readiness.v1` schema. Its required fields are:

- `environment` and `changeReference`: non-empty strings.
- `requestedBy`, `approvedBy`, `deployedBy`: stable identity identifiers using
  ASCII letters/digits and `._:@/\-`, at most 256 characters. Surrounding
  whitespace is trimmed and comparison ignores case. Use immutable identities
  from the approval system; display names and aliases cannot establish that
  three independent people participated.
- `approvedAt`, `validatedAt`, `expiresAt`: ISO-8601 UTC strings ending in `Z`,
  with zero to seven fractional-second digits. Approval must precede or equal
  validation, which must precede expiry. The verifier additionally requires
  `validatedAt <= current UTC time < expiresAt`; a future-dated or expired
  record fails. The CLI has no clock-override parameter.
- `controls`: an object containing `caPki`, `signer`, `immudbTls`, `wormAnchor`
  and `recovery`, each with the JSON boolean `true`. Strings such as `"true"`,
  numbers such as `1`, nulls and arrays are rejected.
- `ci`: an object with a credential-free `https://github.com/OWNER/REPO/actions/runs/ID`
  URL in `runUrl`, `sonarQualityGate` equal to `PASS`, and `coveragePercent`
  containing a finite number from 80 through 100. Coverage may be a JSON number
  or an invariant numeric string; `NaN` and infinities are rejected. Fleetory's
  working coverage target remains approximately 90% or higher.
- `evidence`: a non-empty array with at least one item for **each** control.
  Each item has `kind` equal to the exact control name, `sha256` containing 64
  hexadecimal characters, and an absolute object `reference` using `https`,
  `worm`, `siem`, `s3`, `gs` or `azblob`. References must identify an object and
  contain no credentials, query or fragment. Use stable, version-specific
  identifiers; do not save signed download URLs or bearer credentials.
- `rollback`: an object with a plan of at least 16 characters and `validated`
  equal to the JSON boolean `true`.

For example, an evidence item for the signer is:

```json
{
  "kind": "signer",
  "sha256": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  "reference": "worm://fleetory/phase7/CHG-2026-0007/signer-v1"
}
```

The example hash is a placeholder, not evidence. Supply the actual SHA-256 of
the retained object for every control; additional items for a control are
allowed. Existing records with one generic evidence item must be completed
before this gate can accept them.

The compact output includes `checkedAt`, `expiresAt` and `recordSha256`, the
SHA-256 of the exact bytes that were parsed. Retain this summary alongside that
record and re-run validation when approving or deploying; a summary does not
extend the record's expiry. The verifier runs on PowerShell 7 and Windows
PowerShell 5.1, including strict timestamp parsing on older PowerShell Core.

This is local structural and time-validity checking. It does not contact GitHub,
Sonar, an identity provider, a secret manager or WORM/SIEM; it cannot authenticate
approvals, confirm a CI conclusion, fetch or hash remote evidence, or verify
object lock and retention. Operators must independently verify the referenced
run belongs to the deployed revision, the three identities, each evidence hash,
custody, retention and approval records before completing PHASE 7.
