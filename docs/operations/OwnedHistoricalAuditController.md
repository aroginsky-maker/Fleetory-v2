# Owned historical audit observation

`eng/pilot/Invoke-HistoricalAuditObservation.ps1` owns one disposable native
target for the historical comparison profile. Its only data interface is a
private, bounded stdin/stdout pipe. It accepts frozen archive bytes, historical
expectation metadata, a source signed state and one source **public** key. It
has no operator path, source address, SSH, provider, private PKI or issuer input.
Its output includes private comparison hashes; an owning operator must capture
that output outside Git and public logs.

The separately SHA-256-pinned plan uses schema
`fleetory.historical-audit-restore-plan.v1`, purpose
`historical-known-events-sandbox-observation.v1` and a canonical nonzero nonce.
It pins all four input byte strings, archive length, measured code bundle and
probe digest. CI/local evidence digests are binding metadata; this component
does **not** authenticate those external evidence records or claim consent.
The pure decoder rejects duplicate/extra fields, noncanonical Base64, stale
pins, wrong types and scope promotion. Archive and packet bounds are 64 KiB and
128 KiB. One historical null member, four ordered known values and the fixed
five-transaction database point remain required.

Before creating a container, the owner checks its public code/probe pins and
verifies the source state against the supplied public key. This authenticates
that signature under that pin, not the origin of the supplied pin. It creates
fresh credentials, TLS and a distinct signing key, uses network none, UID/GID
3322, read-only root, private tmpfs, capability drop, no-new-privileges, no host
mounts/ports and fixed memory/CPU/PID/core limits. Its native-operation deadline
is 600 seconds; the auto-remove container's configured main-process lifetime is
660 seconds. Existing fixture lifetimes are unchanged. Runtime inspection
requires the exact selected lifetime as well as ownership and isolation.

Native archive verification precedes the single restore. Integrity failures may
surface during either operation; only the explicit native transaction-checksum
diagnostic is classified as the tested corruption refusal. Connection, TLS,
authentication, permission, deadline and unexpected-EOF errors remain
operational failures. Eight portable refusal-policy cases check this separation.
Fresh target users
are created inside that copy. The historical observer checks independently
supplied known hashes, stable points, history/resolved/raw transaction witnesses
and both target signatures using that target's own fresh pin. Wrong-password
and reader-write refusals are separate checks. A restart must preserve the
observation. Source and target private signing keys are never interchanged;
original private-key continuity is not asserted. Unknown entries remain
unreviewed and the logical whole keyspace is not certified.

Public payload ownership is acquired only after native exclusive directory
creation succeeds. An existing file, directory or link cannot be adopted, even
when two owners race to create the same name. A failed claim never authorizes
payload cleanup. Successful cleanup consumes the in-process claim, so a repeat
cleanup cannot remove a later occupant. The private receipt distinguishes
`payloadClaimed`, `payloadRemoved` and `payloadAbsent`; skipping an unclaimed
path is not a claim that the path was removed.

Resource ledgers are written to exclusively created same-directory temporary
files, flushed to storage and atomically renamed over the previous record. An
invalid resource descriptor or a failure before publication preserves the last
published record; only the writer's own temporary file is cleaned up. Completed
reads contain a whole JSON record. Windows may temporarily refuse an open during
replacement; that is not evidence of an empty ledger or absent resources. A
publication error has an unverified outcome and must fail closed. This does not establish
directory durability across power loss or authenticate ownership after process
death. These helpers assume the existing trusted repository working directory;
the controller still chooses its namespace internally. Identity-held namespace
binding, a fixed external launcher and independent process-death cleanup remain
required before original dispatch or caller-selected namespaces are introduced.

Normal and handled-failure cleanup verifies deletion of the owned container,
image and public payload. The generated native contract exercises eight owner
invocations: success, failures after container creation and after restore,
wrong code/probe pins, wrong source public pin, invalid source signature and a
native checksum refusal after independently repinning corrupted archive bytes.
Operational failures cannot satisfy the typed refusal cases. It independently
checks resource absence, rejects a foreign fixture's longer lifetime and checks
that its generated source is unchanged. The public test proof includes no input
values or private comparison hashes.

```powershell
./tests/Fleetory.Tools.Tests/AuditDataResourceOwnership.Tests.ps1
python -B tests/Fleetory.Tools.Tests/historical_audit_restore_tests.py
./tests/Fleetory.Tools.Tests/NativeAuditHistory.Tests.ps1 -Profile historical-controller -Python python3
```

CI runs eighteen portable input contracts on both OSes and the generated native
profile in the database/audit job. These are generated acceptance results only.
The resource owner keeps `externalGatesAuthenticated` and
`exclusiveUseLedgerVerified` false. An original operation still needs a trusted
outer controller that verifies current gates/code/input/public-trust pins,
claims a fresh exclusive purpose ledger **before** reading original bytes,
uses the audit-only capture adapter and supervises cleanup if the owner process
is killed. The configured container lifetime is not a test of abrupt owner
termination. Existing audit-data consent persists; this component grants no new
secret, private PKI, provider, source-root or production-token authority.

The [pinned audit-use transaction](AuditUseTransaction.md) adds record admission,
an exclusive consumed nonce ledger and one audit-only capture/dispatch slot.
It keeps origin authentication and process/cleanup verification explicitly
unverified; a callback result is not a native acceptance receipt.

Writer admission, execution permission, independent custody/WORM/signoff,
unknown original state, original native observation and full-system RPO/RTO stay
open. Phase 7 is incomplete and PR #2 remains draft and unmerged.

The [held control identity](AuditControlIdentity.md) adds exclusive consumed
control namespaces, retained directory identities and immutable reservation and
child-assertion records. It neither exposes the owner's payload namespace nor
authenticates a child process. Its two generated writer-death tests are not
native backend cleanup acceptance; a fixed measured launcher and actual
owner/resource supervision remain separate integration work.

The [owned process fence](OwnedProcessFence.md) now verifies the fixed owner's
actual runtime image/birth identity and typed pre-admission refusal through
bounded private pipes. Process lifetime evidence is separate from native
payload/resource identity. The existing native payload is still internally
random; no positive restore or forced-owner-death backend cleanup is authorized
or certified by the new refusal probe.
