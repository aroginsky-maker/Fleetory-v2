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

`public_build_context.py` renders the no-RUN Dockerfile and fixed serial offline
restore/publish script, FIFO output handoff and strict NuGet trust configuration.
The SDK reference is a fixed digest. Source, package and public CRL byte sets
must exactly match the expected pins; the rendered tar is deterministic USTAR.
Validation compares the entire canonical archive, refusing changed controls,
extra headers, links, case aliases and appended bytes. Source/package counts,
individual sizes and the separate 64-MiB build-context ceiling are bounded.

`public_build_trust.py` fixes signatureValidationMode=require, the local-only
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
