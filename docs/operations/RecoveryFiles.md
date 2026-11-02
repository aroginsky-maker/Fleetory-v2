# Recovery file preflight

Baseline section 17 needs an identified set of retained files before a whole-service
recovery exercise. `eng/pilot/recovery_files.py` verifies their exact bytes under
a caller-selected protected directory. Keep the manifest, backups and detailed
operator proofs outside Git and PR descriptions.

```text
python -B ./eng/pilot/recovery_files.py --root <approved-private-directory> --manifest recovery-files.json --expected-sha256 <retained-manifest-sha256>
```

Pin the manifest's exact-byte SHA-256 in the separately retained operator
checkpoint before invoking the verifier. Build entries from previously accepted
capture/restore proofs. A changed backup must fail against its retained digest;
recalculating that digest to accept whatever file is present would discard the
integrity boundary. The local pin has the custody/freshness limits of the
checkpoint that holds it.

The UTF-8 JSON envelope has exactly `schema` (`fleetory.recovery-files.v1`) and
`artifacts`. The latter is an object with exactly these six component keys:

| Component | Retained file |
| --- | --- |
| `application-postgres` | Current application database dump |
| `signer-postgres` | Current signer journal database dump |
| `audit-export` | Accepted portable audit export |
| `audit-immudb` | Accepted immudb backup |
| `identity-postgres` | Previously accepted Keycloak database dump |
| `provider-raft` | Previously accepted encrypted OpenBao Raft snapshot |

Every entry has exactly `path`, `bytes` and `sha256`: a portable relative path,
a positive JSON integer no larger than 64 MiB and 64 lowercase hexadecimal
characters. The manifest is bounded at 64 KiB. Paths have one to four ASCII
segments, each starting with a letter or digit; segments may additionally contain
letters, digits, underscores, dots and hyphens. Absolute paths, traversal,
backslashes, alternate streams, trailing dots and Windows reserved names are
rejected. Component paths must be unique even ignoring case and cannot name the
manifest itself. Unknown fields, duplicate JSON fields and incomplete component
sets fail before artifact reads.

All inputs must be regular, single-link files. Linux traverses child directories
using directory descriptors with no-follow opens and opens leaves nonblocking
to reject special files. Windows expands short root-directory names with [GetLongPathNameW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getlongpathnamew), validates both root spellings, refuses reparse parents/leaves and checks the final
handle path before reading and denies write/delete sharing. Hashing streams fixed
64-KiB chunks and checks file size/state again after reading. Preserve the trusted
directory and its protected ancestor paths throughout verification. The result
describes reads of six files; it does not create a simultaneous filesystem or
cross-service snapshot.

The command writes no files and emits only its manifest digest, verified file/
byte totals and explicit false values for full-system recovery, independent
custody, global atomicity and Phase 7 completion. Failure exits 1 without printing
input contents. Missing CLI arguments exit through normal argument validation.
No database, provider, network, key or token operation is performed.

## Verified pilot preflight on 2 November 2026

The existing protected full-system plan and its five pinned proof files were
rechecked. Six previously authorized retained artifacts, totalling **350,081
bytes**, passed the new byte preflight. Five negative cases rejected a wrong
manifest pin, the older three-event application dump at the current dump's digest,
a changed provider digest, a missing component and an added readiness claim.
The original artifacts remained unchanged; the temporary negative manifest was
removed. No backup, restore, source-root recovery or sensitive-data transfer was
repeated.

The synthetic regression suite passes **23 tests on Windows and 23 on Linux**,
without skips. It covers real path/link/special-file rejection, streamed memory
bounds, changed and missing files, strict metadata, manifest substitution and
live growth and an actual Windows 8.3 root alias. Windows refuses the concurrent writer; Linux detects the changed
stream. The CLI success/failure cases also verify read-only behavior and absence
of backup contents in output. Both existing CI jobs execute the suite.

Byte preservation is one preparation step. The identity and provider artifacts
retain their historical scoped acceptance, while the current application/signer
and audit point has separate consistency evidence. Human login, runtime
credentials, configuration/PKI/revocation/physical-Agent recovery, separate-host
provider recovery, independent custody/approvals and full-system RPO/RTO remain
open. See [application/signer recovery](ApplicationDatabaseRecovery.md),
[Keycloak recovery](KeycloakRecovery.md) and [OpenBao recovery](OpenBaoRecovery.md).
