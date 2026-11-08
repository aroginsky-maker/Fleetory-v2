# Fixed probe runtime admission

A separate `ProbeRuntimeBinding` accepts only an already-bound exact
`ProbeImageBinding` from the same held control. Its intent pins the immutable
image ID, exact image binding/intent hashes, public bundle manifest hash and
source snapshot digest. Labels bind that image record and the profile; both
Image and Config.Image must equal the built sha256 ID. Original Python image,
linked container and native receipt modes keep their own types and schemas
and reject this profile.

The profile uses the existing one-use backend intent/observation slots and
shares the image's admission expiry. The original 60-second wall/monotonic
window is not extended. The fixed `exec /bin/sleep 660` argument does not
provide a 660-second operational lease, cleanup authority or a claim that a
service ran continuously for that duration. Generated tests inspect and remove
their own worker before admission expires.

The container layout is declarative data in `eng/pilot/probe-runtime-profile.json`.
The host opens only that fixed ordinary public file with a bounded, rooted read;
its complete SHA-256 is checked before parsing and on every source/report check.
The digest is pinned in the runtime intent, labels and binding record. Container
paths are never used as host filesystem targets. No rule suppression, accepted
issue, threshold change or path-string obfuscation is needed for this boundary.

The runtime tuple is fixed: UID/GID 3322, /bin/sh plus the bounded sleep command,
network none, no ports/user binds/devices, read-only root, cap-drop ALL,
no-new-privileges, 384 MiB memory, one CPU, 128 PIDs, core soft/hard limits zero,
auto-remove and no restart. Exactly two tmpfs entries are admitted:

- /data: rw,noexec,nosuid,nodev,size=256m,uid=3322,gid=3322,mode=0700
- /tmp: rw,noexec,nosuid,nodev,size=32m,uid=3322,gid=3322,mode=0700

Environment must match the six public inherited values of the already pinned
ASP.NET base, including its fixed PATH, APP_UID and runtime/version entries.
APP_UID is inherited image metadata; actual process UID/GID is separately
required to be 3322. No extra environment variable or secret slot is accepted.
The shared sandbox/identity implementation preserves the original Python
profile's constraints; only fixed library classes select their own tuples.
Wire data cannot choose a policy or relax a field.

Portable contracts cover each selected observation field, two tmpfs paths and
each security/size/owner/mode option, environment injection/order, ulimit types,
foreign controllers, type/schema confusion, replay, source mutation and expiry
during intent/binding flush. A refused observation consumes its attempt.
Foreign files and unknown post-publication state are preserved.

The native local Docker and Linux CI fixture requires a fresh image already
bound in its held controller. It reuses the real public publication and full
stopped-copy checks, then creates one additional sleep worker with the exact
runtime arguments. No backend is started. It verifies matching selected Docker
metadata and observes the worker's kernel state: PID 1 is sleep, all UID/GID slots 3322, zero
capability sets, NoNewPrivs=1, seccomp filter mode, read-only root, both tmpfs
sizes/flags/owners/modes, only loopback and no default route. Public scratch is
writable on each tmpfs; direct execution returns 126 on both noexec mounts;
files are removed. The worker metadata/source record is unchanged afterward.
A foreign controller and consumed observation replay are refused.

Only the fixture's own full create receipt ID, name, labels and image identity
permit its test cleanup. The worker is absent before the image admission
expires; the stopped copy and final image are then disposed by their original
owner. Builder intermediate cache and operational owner-death cleanup are not
claimed. Existing default image/copy/Python fixtures retain their behavior;
new callbacks exist only in the trusted generated test helper, not in a wire API.

The library has no Docker, launch, cleanup, key or original-data API. Reports
keep native owner acknowledgement, backend service execution, operational
lease, full runtime continuity, cleanup authorization and full-system recovery
false. Next is actual native publication/build/create receipt handoff and
bounded generated kill-after-build/create/restore cleanup. Accepted release
provenance and original-data purpose/gate admission remain separate. Existing
backup/restore evidence is preserved. Phase 7 remains open.
