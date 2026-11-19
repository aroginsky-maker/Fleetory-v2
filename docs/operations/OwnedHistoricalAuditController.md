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

Container and image claims remain local to their live creator. A surviving
outside owner, abrupt creator/daemon/host failure, original input execution and
full recovery remain open. No original bytes, original private PKI, provider,
issuer or VPS access is introduced by these tests. The accepted public probe
profile and its inventories and durations are unchanged.


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


The historical image build now uses the same fixed three pinned public base
images, generated Dockerfile and bounded public-code tar, with `--quiet`,
`--network none`, `--pull=false` and no tag. Its process-local claim retains the
actual exit code and raw stdout/stderr, same client/context references, original
start time and an immutable copy of the bounded build input. Only the complete
`sha256:` image-ID reply can populate `ImageId`. Failed/partial replies or a
changed input stay unknown and consumed. A tag, label, inspected ID, copied
context, cleared boolean or JSON journal cannot repair them.

Containers obtain their full image ID from that live image claim with the same
client; both runtime image fields must match it. The legacy `image`/`ImageName`
metadata is only an unused logical namespace hint. No alias is created. Checking
that namespace name alone is not evidence that a physical image was deleted.
The actual owner confirms absence using its privately held full image ID.

Before deletion a fresh, retained native inspection requires the exact known
ID, generated build label, original creation window, fixed image user and
layered root filesystem. Any tag or digest reference refuses removal. The only
mutation is nonforced `image rm --no-prune` with the full owned ID. Its complete
`Deleted:` reply is required, followed by a separate retained exact-ID absence
reply before closing the claim. An unknown removal, lost verification or
unrelated missing-image message cannot close it or authorize another mutation.
An already absent image still needs a known original build reply and its own
native missing-image result. These rules do not authenticate Docker or protect
against arbitrary code acting as that user.

Additional generated models cover unknown build/removal replies, altered public
input, descriptor/client copies, cleared flags, foreign references, no-prune,
post-removal verification loss and replay. The native workflow truncates a real
quiet build reply before the tested owner sees it. A separate live fixture
witness executes that same actual build while retaining the full reply, then
disposes its own untagged image by ID with no pruning and confirms absence.
A modified actual inspection response containing a foreign tag is rejected
before removal; this is a readback fault test, not a claim that a real foreign
tag was created. The three pinned base images are checked after own deletion.
The existing container-reply fault uses a separate fresh image built through
its retained client, preserving the strict image-to-client binding.

All of this concerns freshly generated historical fixtures. It is not evidence
that an original deployed Server/signer/Keycloak image was reproduced, that a
registry currently serves a recorded digest, or that original release/build
inputs are authenticated. The outside owner, original recovery and independent
production controls remain separate open requirements.


Before the historical controller accepts its private input, it now creates a
separate, process-local native-probe profile with the original context/client
references and a monotonic 600-second deadline. It permits only `audit-health`,
`history-users`, `observation-history-read` and `observation-reader-denial`.
The profile constructs the fixed Docker exec arguments itself, obtains the full
container/image IDs from the original live custody claims and requires the
historical target's 660-second lifetime. No command, endpoint, path or mount
selector is accepted. Raw request bytes are bounded to 128 KiB, stdout to
256 KiB, stderr to 4 KiB and the profile to 64 calls. That covers both existing
20-attempt health loops and the normal historical operations.

Each actual call is consumed before invocation. Its original request commitment
and privately copied raw native reply are retained; mutable delivery bytes are
cleared on success and failure. Changed input/arguments/identity, transport loss,
null replies and output overflow permanently invalidate further probe calls for
that profile. A copied context, replacement client or second begin cannot reset
it. The original image/container cleanup claims remain available to their live
creator. Application result validation is still separate from transport capture.

This closes the historical command/request profile before OS-child lifetime
integration. It does not authenticate the native child's executable/birth/fence
or prove actual abrupt child death, input-loss cleanup, creator/daemon failure
or a surviving outside owner. Killing a Docker client does not establish that
its daemon-side exec workload has stopped. Those tests must retain the actual
creator and confirm disposal/absence of the owned container independently.
No original inputs, original secrets/private PKI or VPS operations are added.

The historical expectation and observation comparison run in a dedicated Python
child. The launcher uses the Windows Job object or an unreaped Linux process
group with a pidfd. It verifies the child executable and birth identity before
sending a length-prefixed request, and checks that no child group member remains
before accepting the result. The controller supplies hashes from its existing
code snapshot for the fixed worker source set and hashes its local interpreter.
The child performs the same historical comparison without Docker authority.

Two generated restore cases stop that exact comparison child or close its input
after the frame length and before the body. The original creator remains alive
to remove its own container, image and payload. These checks cover the host
comparison child. The in-container dotnet probe, the Docker daemon workload,
loss of the original resource creator, and retention outside that creator still
require separate evidence.

The generated historical controller runs its four .NET probes in fixed
children within the target container. The mode list consists of audit-health,
history-users, observation-history-read and observation-reader-denial. A Linux supervisor reads a bounded
request, holds the child with a pidfd, checks its executable, parent and birth
before sending the private frame, and observes actual exit before publishing the
result. Legacy program entrypoints retain their previous behavior. Within the owned
controller, the completed private frame is the only input passed to the existing
operations. The child uses a fixed temporary home for .NET TLS chain evaluation and the
existing fixture CA paths after checking user-only modes and rejecting links.
Generated interop targets the held Linux descriptor without extracting its native handle. The fault cases withhold the body or terminate the held
child before releasing it, and the original live controller verifies cleanup of
its own target. Normal tests verify health before and after restart, generated
user provisioning, observation and reader write denial through all four held
leaves. Each mode has separate real early EOF and abrupt-exit cases. A lost
Docker transport cannot supply successful exit evidence. This input and exit
proof requires a complete native exec reply. Process group containment and independent owner or daemon loss still
require separate evidence.

The generated transport fault also uses the real managed observation child.
The in-container supervisor pauses after verifying its executable and birth
and before releasing a request body. A second Docker exec binds a read-only
pidfd to that same child after checking the supervisor command, case nonce and
parent-child relationship. The fault harness interrupts the directly held Docker
client, then asks the surviving observer to distinguish continued life from an
already exited child and verify terminal exit on its original descriptor.
Wrong birth and copied case claims are refused. An interrupted observer produces
no terminal receipt. The fault returns no application success, and the live
creator verifies absence of its target container, image and payload. The native
workflow also verifies the separately held source and foreign fixture.

This is a generated check on the local Docker daemon. The CLI is launched
directly as the test user through an explicit local endpoint and an empty
configuration in the owned fixture. Linux requires the test user to have access
to that daemon. The observation channel cannot signal a container process,
claim a Docker resource or grant cleanup authority. Independent cleanup after
creator loss and daemon or host loss remain open.

The independent creator profile keeps the real container, image and payload
creation and cleanup in the original PowerShell process. A distinct, measured
Python application controller validates the expectation and requests the fixed
sequence of historical read, authentication denial, reader-write denial,
restart and post-restart read. It verifies both typed refusals and checks that
the two observations have the same fingerprint. The creator
verifies the target signatures and sends a projected producer identity instead
of passing on Docker identifiers, credentials or cleanup authority. The
private channel binds every bounded reply to the operation and attempt. The
creator consumes each operation once and checks the same monotonic lease before
and after its native call.
The controller has no Docker command interface in this profile.

The generated profile exercises normal completion, verified application
controller death and a five-second creator-owned lease expiry. A separate
handoff test terminates the held controller after the creator executes the
authentication check and before the controller receives its reply. The creator
keeps that request unconfirmed, performs no later operation and cleans up. The wrapper
holds the actual controller process and verifies absence of its owned group or
Job members before returning terminal evidence. On Linux it observes the
controller exit without reaping until the group check. The creator closes its
own Docker resources after the controller dies or while that controller still
waits on expiry. A late replay after expiry is refused without a native read.
The native tests verify the same source and the foreign fixture.

For a restart, a read-only observer holds the target immudb process with a
pidfd before dispatch, reading its PID from the private fixture data mount.
The stop command validates the same executable and
process birth and sends one SIGTERM through its own descriptor. The owner
requires both the complete native acknowledgement and exit on the observer's
original descriptor before starting immudb again. Two generated cases keep the
complete actual Docker reply in the test witness and withhold or truncate it at
owner admission. Both observe the daemon exit but refuse a late reply and a
second dispatch. The held application controller receives no restart result
and requests no post-restart read. The live creator verifies cleanup of the
owned resources. The surrounding test verifies that the source and foreign
fixture remain. The original
creator's live Docker custody remains required, including complete native
replies at creation. A separate recovery coordinator now gates the historical profile's allocation
and use. The PowerShell owner retains the context and original native replies
from payload, image and container creation through cleanup. The held
coordinator requests allocation, checks the receipt against the fixed
per-attempt exchange, and asks the owner to run the historical sequence.
Its receipt contains a digest bound to the fresh attempt and actual owned
resources. Docker commands, paths, identifiers and credentials stay with
the owner.

The generated tests terminate the exact coordinator while it waits for
admission and after it accepts the complete resource projection. They also
exercise a five-second lease while the coordinator is still live. The owner
finishes cleanup before rejecting the request sent after expiry. A normal
handoff runs the existing independent application logic through all five
stages and verifies cleanup. The tests check the actual generated image and
container are absent and the source and foreign fixture survive. For a missing or truncated
Docker create acknowledgement during allocation, the owner consumes the
attempt and refuses the coordinator's replay without a second Docker call.
A separate PowerShell witness runs the one fixed create command and retains
the complete native reply and its own claim. The witness inherits only the
environment needed to run the local CLI. It reports the exact generated
ID and the complete reply to the test owner only after it verifies container
absence. The owner refuses the authentic late reply and rejects cleanup by
the supplied ID. The coordinator receives an allocation refusal and sees no
resource projection or request to start the historical workload. The owner
then cleans its original image and temporary payload from its own claims.
Loss of the live resource owner, Docker daemon or host remains open.

The generated `coordinator-create-coordinator-exit` case holds the original
successful Docker API create reply at a loopback-only, authenticated gate. The
fixed native Docker client remains alive with zero stdout admitted while the
existing OS-fenced supervisor terminates the exact coordinator. Its process
identity is held and checked again after the coordinator exit. Only then is the
original reply released. This case uses `docker create --rm` and never starts
the container process. The surviving witness admits its own original native
reply once, checks the created state and removes the exact container from its
live claim. The parent allocation remains unknown and rejects cleanup, replay
and late ID adoption. The image and payload remain with the surviving owner.

The gate forwards at most one strictly constrained create and bounded HEAD
negotiation, with a fresh test-only header in a temporary configuration below
the owned payload. It has no general Docker operation endpoint. Both a bounded
Content-Length response and bounded chunked response retain their original wire
bytes. Duplicate headers/JSON fields, ambiguous framing, other images, commands,
users, networks, mounts, privileges and replay are rejected. The upstream native
daemon stream stays duplex through response completion. No original materials,
VPS access or original PKI are part of this case.

`NativeAuditHistory.Tests.ps1 -Profile historical-controller
-HistoricalCreateFault coordinator-exit` selects this one generated case for
diagnosis. The default continues to run the complete controller profile. A
selected case emits `fleetory.generated-historical-create-fault-subset.v1` and
explicitly reports `fullControllerSuiteExecuted=false`; it cannot substitute for
the full suite's receipt. An unknown result still supplies no automated cleanup
authority. Operator disposal of a fixture after a failed attempt must be kept
separate from program cleanup acceptance.

The unstarted create profile uses a dedicated container scratch mount at
`/run/fleetory-native-create` rather than the general `/tmp` location. Its
32-MiB tmpfs remains noexec/nosuid/nodev, owned by UID/GID 3322 with mode 0700.
The normal historical running profiles keep their existing mount layout.

The reply gate lives in the separate `eng/pilot/historical` profile namespace;
it does not expand the fixed public v1 source inventory. It binds its one-create
route to the lower of the same native client's API version and the daemon's
advertised version, with API 1.48 as the minimum supported contract. Docker 28's
legacy `OnBuild: null` field is accepted only as null. Build instructions or any
other value are refused. The command, image, user, network, privilege, resource,
mount, nonce and replay restrictions remain required.

The private create gate reports fixed refusal categories for request profile,
response status/framing/body and native transport completion. Its owning witness
copies only the bounded category into the typed refusal, never a request body,
header, token, daemon warning or arbitrary subprocess error. Native response
reader failures retain their category across the bounded reader thread; a
generic thread wrapper must not hide them as an unclassified ValueError. These
diagnostics add no retry, result admission or cleanup authority.
