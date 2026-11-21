# Separate public build create policy

The SDK build request has a separate `retained-public-offline-build.v1` policy.
It cannot be selected through the historical native gate's wire request. Each
policy refuses the other's body and namespace. Shared framing, authentication,
single-attempt consumption and response handling remain in the existing gate;
the historical default still uses its original values and image profile.

The SDK request fixes UID/GID 65534, network none, a read-only root, no added
capabilities or privileges, two CPUs, 2 GiB memory and 128 PIDs. Only the fixed
300-second timeout, five-second kill grace and build script can be requested.
The work/tmp tmpfs slots have fixed sizes, ownership and noexec/nosuid/nodev.
TMPDIR is fixed to the private /run/fleetory-build-tmp mount. There are no
host binds, devices, ports, arbitrary environment overrides or API operations
for start, exec or deletion. Invalid attempts cannot be repaired or replayed.

AutoRemove is deliberately false in this separate request profile: a future
live creator/witness must retain and inspect the actual exit record before its
own removal and absence verification. PID1 timeout alone does not prove cleanup.
This changes no historical/public-v1 limits or lifecycle behavior.

This module validates a request only. An image ID, nonce, context hash or matching
labels do not establish build provenance, original use or resource custody. No
SDK native entry point, creator, start or cleanup API is exposed. The new policy
must not be wired to native execution until the complete creator/witness path is
implemented and tested. SDK kernel isolation, offline restore/publish, exit and
controller-loss cleanup are not verified by these metadata tests.

The next live worker must own the entire input-image build and SDK lifecycle.
It must consume its original complete build/create replies, exact native client
and context objects, full IDs, readbacks and original deadlines. Moving a saved
image ID to another process cannot recreate the builder's cleanup rights. The
existing 16-MiB historical image context must remain fixed; the separately
bounded public context requires its own profile and custody before use.

The prepared public context contains source snapshot and signed package bytes
with a pinned SDK and no Dockerfile RUN step. That preparation did not create
an SDK container or publish an assembly. Source-origin authentication, the full
runtime/command/build inventory, the original-purpose owner and all external
Phase 7 requirements remain open. No original archives or service PKI were read.


## Separate live image custody

`PublicBuildImageCustody` retains a separate in-process claim table for public
build images, with an archive ceiling of exactly 64 MiB. `AuditImageCustody`
keeps its historical 16-MiB ceiling and public API. Both use the same internal
implementation; neither facade can retrieve or remove the other's live claim.
The SDK facade also binds the source context digest and pinned SDK reference
to the exact original context object and native client identity.

A build attempt is consumed before invoking the native operation. The complete
reply and a private copy of the input archive remain in the live claim. Changed
input, an incomplete ID response, copied objects and replay do not create new
authority. Removal is one attempt followed by exact native absence validation;
saved metadata cannot reconstruct ownership after process death.

The existing ownership regression exercises both facades, exact SDK archive
size and overflow, input mutation, foreign-client/context refusal, cross-facade
refusal and consumed unknown outcomes. These are synthetic native replies.
They do not prove an actual SDK build or independent cleanup after creator loss.
The independent worker that owns image build and the entire SDK lifecycle is
still required before native execution can be enabled.


## Trusted worker lifecycle APIs

The image transaction and SDK transaction now provide trusted in-process worker
APIs. The native client pins and holds its executable, creates an exclusive empty
Docker config, fixes the local endpoint, and uses an opt-in clean classic-builder
environment. It captures the actual policy and native function objects when
constructed; later ambient function replacement cannot redirect those callbacks.
Existing native-process callers keep their original environment.
The SDK client can bind once to the actual live public-image context and client.
It fixes create arguments, consumes creation/start/release/removal attempts and
refuses unknown IDs, arbitrary exec, foreign paths and repaired create requests.

SDK output lives in tmpfs. After publish, the fixed control script must mark
`/work/publish.ready` and wait on `/work/release`. The same worker reads only that
marker, captures `tar` bytes from `/work/output`, releases the FIFO once, observes
exit zero, and closes the container claim before the enclosing image transaction
closes its image claim. Unsupported Docker cp access to tmpfs is not exposed.
Both transactions retain their full native replies and use the original objects;
metadata and names cannot reconstruct those claims after the worker dies.

These APIs do not create a public native command entry point. A future launcher
must validate a closed no-RUN Dockerfile, fixed controls, bounded source/package
and trust inputs, freshness, and a trusted live byte intake before any build.
An arbitrary archive plus its supplied hash cannot authorize native work.
The independently surviving process and original-purpose admission still require
their own integration. General creator, daemon or host death is not covered.

Local prototypes exercised real offline publish and controller EOF/death/expiry
cleanup with pinned public inputs and strict signed-package/revocation checks.
Those operator records are separate from this commit's portable model tests.
They do not establish original release provenance, original-data execution,
production approvals or completion of Phase 7. Public vendor CRLs, certificates,
build artifacts, operator paths and one-use records are not repository inputs.


## Closed public context byte policy

`public_build/context.py` renders the no-RUN Dockerfile and fixed serial offline
restore/publish script, FIFO output handoff and strict NuGet trust configuration.
The SDK reference is a fixed digest. Source, package and public CRL byte sets
must exactly match the expected pins; the rendered tar is deterministic USTAR.
Validation compares the entire canonical archive, refusing changed controls,
extra headers, links, case aliases and appended bytes. Source/package counts,
individual sizes and the separate 64-MiB build-context ceiling are bounded.

`public_build/trust.py` fixes signatureValidationMode=require, the local-only
package source, reviewed repository signer fingerprints and owner set, with
allowUntrustedRoot=false. Public fingerprints carry no private key material.
CRL windows must be timezone-aware and retain more than 420 seconds of validity
at admission. This byte policy performs no cryptographic signature verification;
expected pins and verified CRL windows must come from trusted live intake.
The launcher must recheck freshness immediately before SDK start and enforce
its deadline independently. Those integrations remain required.

These are library APIs with no native commands, filesystem reader or execution
grant. A supplied manifest and matching archive cannot authenticate source
origin or authorize a build. Portable synthetic tests cover deterministic bytes,
control/trust changes, mismatched pins, stale/future CRLs and case aliases on
both CI platforms. They do not qualify original releases or restored services.

The SDK byte policies live in the `public_build` package. They do not extend the
legacy public cleanup controller's fixed 63-file source inventory or its command
namespace. The retained source catalog records this package independently.

The package uses Python's namespace-package mechanism, as the historical tools
already do; it has no `__init__.py` marker. The existing held-file reader refuses
that basename. Source-plan preflight now applies the same basename rules before
opening files, so an unsupported marker is rejected before a peer is started.
The source catalog regression holds the two nested SDK modules and preserves
the existing file-count, byte, link and reparse restrictions.


## Live public input capture

`public_build/intake.py` accepts roots and expected pins supplied by trusted host
code, validates all names/schemas/counts/sizes and CRL windows before opening an
input, and reuses the existing directory/file identity readers. Source content
is bounded by8MiB and768 entries for this separate public build profile; the
existing retained-source448-file bound is unchanged. Package and CRL counts
are bounded by64 and32, and the combined context retains its64-MiB ceiling.
The fixed55-byte SDK `global.json` is generated rather than read from a supplied
path. The pinned source snapshot must declare those exact generated bytes.

Captured immutable bytes remain independent of subsequent input-path or caller
metadata changes. Only the original live process/thread object can take the
context once. It cannot be reconstructed from its report. The420-second clock
starts before capture and never renews. The pre-start check consumes its attempt
before validation, requires305 seconds within the original budget and rechecks
the public CRL validity window. It performs no native dispatch or signature
verification and grants no original-data or resource custody authority.

Portable tests cover actual generated-file capture, hardlinks, copied/fabricated
objects, another thread, original expiry, consumed failed attempts, CRL freshness
and the exact previously admitted SDK bytes. Private byte/control handoff to the
surviving SDK worker still needs integration; a report or successful check alone
cannot start a restored service or authenticate an original release.


### Live source transport boundary

`public_build.peer.serve_capture` consumes an actual captured public-input object before writing a fixed 60-byte frame header and at most 64 MiB of immutable context bytes. A private one-byte request consumes the sole pre-SDK freshness attempt; replay, unknown commands, source expiry and broken output refuse the operation. No CLI accepts a report or hash as a permission grant.

`PublicBuildSourceTransport` receives that frame from an actual source-only Process under the original caller stopwatch (at most 420 seconds), checks the expected digest before allocating the context body, verifies the body, and consumes a single permit request. After the permit, an outstanding read detects EOF or unexpected source output. Failed frame capture cannot request a permit. Disposal closes the private input and, when needed, stops only this source-only child. This API never terminates a resource-owning worker and never adopts Docker resources.

Required Windows/Linux gates run six actual Python peer tests and seven actual child transport cases, including size/magic/digest/truncation refusals, deadline, permit refusal and replay. The transport gate uses a generated PowerShell byte peer on both operating systems. The retained source filename rules and legacy Python source inventory remain unchanged.

These libraries do not authenticate the original release or bind the complete Python runtime. The private surviving-owner integration and full native SDK handoff remain open. Windows-only held-file and controller/source/owner prototypes were tested separately on generated inputs with synthetic Docker replies; those results are not native recovery evidence. No original dumps, private PKI, live issuer or production tokens are admitted by this transport.

The intake lifetime and pre-SDK margin use integer monotonic nanoseconds. The exact 420-second expiry and 115-second pre-SDK boundary refuse admission; one nanosecond before each boundary remains within its unchanged limit. A backwards clock also refuses. This avoids floating-point subtraction rounding a nominal expiry below its deadline.


`Invoke-PublicBuildSourceTransaction` is the trusted in-process connection to the original image owner. It requires the actual typed source transport, checks upstream control before capture, combines upstream/source liveness for every image-transaction admission check, and consumes the source freshness permit before the caller uses the image for SDK creation. On success or refusal the image transaction first unwinds its original CWT custody; the outer finally then disposes only the source-only child. Caller callbacks must retain their original trusted state; no metadata/native CLI or recovery grant is introduced.

Its mandatory Windows/Linux gate uses actual generated child processes with synthetic Docker replies: normal use and replay refusal, upstream loss before capture and after build, source death after build, source deadline after build, malformed source frame, and source death during use. It checks zero native dispatch before admission and exactly one original build/removal/absence sequence after acquisition. Native public SDK results remain separate protected operator evidence; accepted original release/purpose, complete runtime admission and full recovery remain open.

The generated peer-test parent resolves its own temporary root before passing it to the isolated child. This normalizes Windows short-name aliases and lexical parent segments while retaining the child's strict canonical root check; production reader path checks are unchanged. Child startup failures include bounded fixture stderr in test diagnostics.

The use callback receives `(Context, Client, SourceAlive)`. Native SDK code must use this supplied composed callback throughout its lifecycle, rather than an upstream-controller-only callback. The during-use source-death test verifies that this callback becomes false and original image custody still unwinds exactly once.
