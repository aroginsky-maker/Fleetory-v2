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
