# Untagged image IDs bound to held control

`audit_image_binding.py` adds a separate generated-image intent and observation
to the identity-held control session. It reuses the container binding's consumed
attempts, retained records and post-publication deadline checks. Container and
image slots are distinct and individually one-use. Existing container schema,
record fields, fixed profile and authority flags are preserved.

The image intent pins the control nonce/revision/reservation, existing synthetic
Python base reference and local base ID, ordered base filesystem layer IDs,
three exact control labels and the digest of a fixed Dockerfile. That recipe
contains only FROM and LABEL. It admits no path, COPY, RUN, arbitrary command,
tag, registry target or private input. The fixture supplies an empty temporary
context and checks its held identity and emptiness before and after building.

A separate quiet-build receipt supplies the immutable `sha256:` image ID.
Selected image-inspect fields must match that ID, its base parent, labels,
unchanged ordered filesystem layers, Linux/amd64 profile and fresh UTC creation
time. Tags and registry digests must be empty. Wrong receipts, foreign labels,
changed filesystem/platform, published/tagged objects and old or future images
are refused. Failed validation or flush consumes the attempt. Existence of a
partially published record does not establish acceptance.

The native fixture pins inspect API 1.48, supported by the tested Docker 28/29
engines, because newer APIs omit the parent field. A missing parent is never
silently accepted as a match. This changes the metadata interface only; the
daemon, TLS, isolation and validation requirements are not relaxed.

The native fixture builds two fresh untagged label-only images, binds one ID,
rejects the other under a foreign control session and checks its sentinel is
unchanged. It removes only its known build-receipt IDs after checking their
labels, parent and lack of tags/digests. Removal uses no force and no parent
pruning; the cached base is checked unchanged. A further injected inspect
failure checks cleanup of one additional fresh image through a smaller
identity-only inspection. No container is started and no tag is created.

Docker tags provide a mutable alias rather than an exclusive claim. This
profile deliberately accepts untagged image IDs; it neither creates nor adopts
a tag namespace. The module has no build, Docker or deletion API and its report
does not authorize cleanup. The fixture's own successful build receipt is its
limited cleanup evidence. Unknown IDs or unexpected aliases fail closed.

These are generated image metadata checks, not authentication of Docker, the
builder, software origin, registry availability or full execution continuity.
They do not prove an application revision or accepted release build. This
profile cannot change the existing fixed empty-container profile into a legacy
service launcher. Legacy PowerShell owner readiness, payload/resource handoff,
full toolchain inputs and independent cleanup after abrupt owner death remain
open before original dispatch. Original archives, PKI, provider/root/issuer,
production tokens, full-system recovery and Phase 7 completion are outside this
acceptance. See [container binding](GeneratedContainerBinding.md) and
[application input snapshots](LegacyAuditInputPins.md).
