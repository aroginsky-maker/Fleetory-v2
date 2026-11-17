# Owned historical audit observation

`eng/pilot/Invoke-HistoricalAuditObservation.ps1` owns one disposable native
target for the historical comparison profile. Its only data interface is a
private, bounded stdin/stdout pipe. It accepts frozen archive bytes, historical
expectation metadata, a source signed state and one source **public** key. It
has no operator path, source address, SSH, provider, private PKI or issuer input.
Its output includes private comparison hashes; an owning operator must capture
that output outside Git and public logs.

The separately SHA-256-pinned plan uses schema
`fleetory.historical-audit-restore-plan.v2`, purpose
`historical-known-events-sandbox-observation.v1` and a canonical nonzero nonce.
It pins all four input byte strings, archive length, measured code bundle and
probe DLL and complete published application digest. The [input snapshots](LegacyAuditInputPins.md)
also measure the active root build inputs and Git revision. CI/local evidence digests are binding metadata; this component
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
image and public payload. The generated native contract exercises ten owner
invocations: success, failures after container creation and after restore,
wrong revision/code/probe/bundle pins, wrong source public pin, invalid source signature and a
native checksum refusal after independently repinning corrupted archive bytes.
Operational failures cannot satisfy the typed refusal cases. It independently
checks resource absence, rejects a foreign fixture's longer lifetime and checks
that its generated source is unchanged. The public test proof includes no input
values or private comparison hashes.

Each of those ten invocations now receives a distinct canonical operation
nonce. The case builder copies the plan and packet, consumes that child nonce
in a bounded, ordinal in-memory set before serialization, replaces only the
plan nonce and repins the encoded plan. It rejects the parent/source nonce,
noncanonical or zero identities, duplicate/changed-plan reuse, an eleventh case
and oversized output. Failed preparation stays consumed in that set. Caller
plans, packets, source expectation nonce and known event bytes are preserved.
The observation fingerprint stays tied to the same data while the expectation
hash changes with the operation. Portable tests and all ten native cases
check this separation. This fixture set is neither a durable purpose ledger
nor authority to retry an original operation. The owner's payload/image names
remain internally random; held control/resource binding is still open.

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


Container ownership now also requires a live, process-local claim made while the
fixed creator invokes its actual Docker client. The claim privately retains the
complete native exit code and raw stdout/stderr, binds the same context, store,
client and store-list objects, original start time, session, role, image and
configured lifetime, and accepts exactly one full lowercase container ID plus a
line ending. Inspection replies are retained before parsing. JSON ledgers,
copied objects, labels, a later name lookup and an externally supplied ID cannot
reconstruct the claim. Metadata changes are refused before a Docker lookup.

A create attempt is consumed before execution. Missing, partial, malformed or
failed replies leave an unknown outcome; cleanup must report that refusal.
Removal is likewise consumed before the native call and requires the complete
matching ID reply. Lost removal replies never authorize retry. Already absent
containers require the actual held inspect failure naming the exact claimed ID;
this closes the live claim without claiming a successful removal. This is a
trusted in-process code boundary, not protection against arbitrary code running
as that user, authentication of Docker, or authority that survives owner death.

Generated tests cover copied metadata, replaced clients/lists, mutated identity
and clocks, full/partial replies, transport failures and consumed attempts. The
native historical workflow additionally truncates a real create reply before
the tested owner receives it. That owner refuses lookup and removal even if an
ID is later supplied. A separate live fixture witness holds the original full
reply and checks the fresh runtime profile before disposing only that fixture;
its cleanup cannot be replayed. Existing normal four-event/five-transaction
observation, exact historical null preservation and refusal cases still run.

This closes only the container reply-custody prerequisite. The current image
builder still uses a tag/readback path and needs its own complete build-reply
custody review. A surviving outside owner, abrupt creator/daemon/host failure,
original input execution and full recovery remain open. No original bytes,
private PKI, provider, issuer or VPS access is introduced by these tests. The
accepted public probe profile and its inventories and durations are unchanged.


The fixture's final sweep skips only a matching process-local claim whose
complete removal or exact-ID absence was already confirmed. This read-only
closed-state check performs no Docker operation and cannot import a copied
context or journal. Unknown create/removal outcomes stay unclosed and fail the
sweep; explicitly requesting removal again still fails before any lookup.
Generated history deliberately removes four negative-test stores before the
final sweep, so these completed claims must be distinguished from live ones.


An exact-ID absence accepts only exit 1, an empty stdout or the CLI's canonical
empty inspect array, and an exact missing-object message naming that ID in
stderr. A nonempty array, unrelated ID or transport failure cannot close the
claim. The generated native fault fixture stops only its known, freshly checked
auto-remove container, verifies the full stop reply, then closes the live claim
from the real absent inspect reply without issuing `rm`. An unknown stop reply
does not authorize another mutation. This is scoped fixture fault injection,
not evidence of creator, daemon or host-loss recovery.


A complete removal acknowledgement consumes the mutation but does not yet close
the claim. A separately invoked, privately retained native inspect reply must
confirm exact-ID absence first. Transport loss, a nonempty array or an unrelated
missing-ID message keeps it unclosed. The final sweep cannot turn that state
into success or issue another removal. Separate refusal tests exercise all three
post-removal inspection failures and verify exactly one removal call.
