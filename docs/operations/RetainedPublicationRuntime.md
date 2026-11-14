# Retained publication sleep runtime

This separate metadata profile requires the exact `RetainedProbeImageBinding`,
the same live controller capability and its completed stopped-copy readback.
The old probe runtime still admits only the exact original `ProbeImageBinding`;
its schema, labels, fixed profile and native receipt modes remain unchanged.
A generic object or subclass cannot enter either profile through this adapter.

The new intent and receipt bind the image record, image intent, source snapshot,
bundle manifest, publication continuation, readback and held-descriptor digest.
Four additional runtime/controller source files are pinned from the held public
repository before intent admission and checked throughout the target lifetime.
The native publisher's original 40-file inventory remains unchanged. Combined
with those still-held inputs, this gives a 44-file source chain; it does not
authenticate compiler/package provenance or an external software origin.

The runtime deadline is the earlier of publication and image admission expiry.
Both source capabilities remain checked on every access. Closing either source,
expiry, changed code/file/descriptor identity, foreign controller, corrupt intent
or observation refuses use. Invalid construction consumes the backend slot before
source/file admission; a failed observation stays consumed. Flushes that cross a
deadline cannot return an accepted binding. Closing this metadata object releases
only its four code pins and leaves the publication's enclosing context intact.

The runtime tuple reuses the existing pinned sleep-only profile: UID/GID 3322,
network none, read-only root, no capabilities, no-new-privileges, bounded memory,
CPU and process count, two noexec/nosuid/nodev tmpfs mounts, fixed environment and
core-dump limits. Shared validation is reused; old type and schema guards are not
broadened. Generated contracts cover lineage, both deadlines, pins, aliases,
replays and unsafe runtime mutations before any actual Docker execution.

The public native publication fixture adds one sleep worker after successful
image/stopped-copy readback. Locally and in Linux CI it checks the live kernel
state, UID/GID, capability sets, seccomp, no-new-privileges, mount flags, loopback,
absence of a default route and non-executable public scratch files. It removes
its own worker using its validated Docker create receipt, checks absence before
admission expiry and keeps image/readback records unchanged. Windows CI runs the
contracts and actual publication/context handoff; it does not claim Docker runtime
execution. No Server, signer, identity issuer, provider, original data or PKI runs.

The fixed sleep command lasts up to 660 seconds; the 60-second admission window
is not a runtime lifetime guarantee. This fixture disposes its worker while its
controller is alive. Independent expiry enforcement, abrupt controller death,
operational/service leases, production cleanup, daemon/compiler provenance,
coordinated full recovery and all remaining Baseline approvals remain open.
Phase 7 stays open and PR #2 remains draft and unmerged.

The next [cleanup protocol preparation](PublicSleepCleanupProtocol.md) pins
asserted identities, one own receipt and bounded model decisions. It provides
no executor and does not verify independent cleanup.

[Typed guardian preparation](RetainedGuardianPreparation.md) now binds the same
unobserved retained runtime and persisted intent to a real preparing controller
and fixed source/executable pins. It consumes no runtime observation and grants
no launch, own-create receipt or cleanup authority.
