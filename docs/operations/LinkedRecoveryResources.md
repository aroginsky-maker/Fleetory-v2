# Linked generated recovery image and container

The generated image and container gates now have a strict linked profile.
A container intent is admitted only after the same held controller has bound
an untagged image to its separate quiet-build receipt. It pins that immutable
image ID, the image intent digest and the exact held image-binding record
digest. A different controller, an unbound image or a stale source cannot
supply the dependency.

The container's image argument and observed Config.Image must both equal the
built sha256 ID. Neither the base-image reference nor a mutable tag can stand
in for it. Its labels also bind the image record. The container shares the
image expiry and rechecks the source binding through publication and report;
creating it later cannot extend the lifetime of the pair.

This profile uses the existing one-use backend slots and retains all runtime
constraints: Linux, the fixed Python command/entrypoint, UID/GID 65534, network
none, no ports or mounts, read-only root, cap-drop ALL, no-new-privileges,
64 MiB memory, 0.25 CPU, 32 PIDs, auto-remove and no restart. The original
base-image profile keeps its exact schema/reference and rejects linked
intents. The shared observation implementation has separate fixed callers;
wire data cannot select an arbitrary image policy.

Portable contracts cover dependency hashes, source/session substitution,
schema/version confusion, consumed refusals, source/intent mutation, all
runtime bounds, foreign records and deadline expiry during publication.
The real Docker fixture builds two label-only untagged images, accepts one
derived-image/container pair, rejects a matching-label container created
from the base image and rejects a foreign controller. A fresh sentinel stays
unchanged. Cleanup uses only the fixture's own create/build receipts after
independent metadata checks; containers are removed before their images,
images use no force or parent pruning, and the cached base is preserved.
An injected observation failure verifies cleanup of an additional own pair.

Both portable OS gates and the Linux native gate are mandatory in the
existing CI jobs. The local Windows Docker rehearsal and Linux CI compare
the same proof apart from engine version. No job, timeout, quality threshold,
budget or repository visibility change is required.

The library has no Docker, build, deletion, command or original-data API.
The fixture uses only public Python images and generated metadata.
Docker observation authenticity, application build provenance, full runtime
continuity and operational backend cleanup remain unverified.
[Native resource acknowledgement](NativeResourceAcknowledgement.md) adds a
separate metadata-only handshake with the actual PowerShell owner; it does
not turn these receipts into application or cleanup authority. Actual legacy application/probe
integration and original-data dispatch remain open. Phase 7 is incomplete.
