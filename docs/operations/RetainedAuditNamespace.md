# Retained audit namespace custody

`eng/pilot/historical/RetainedAuditNamespace.ps1` defines a distinct coupled
resource profile for the next combined PostgreSQL/audit/Server stage. The existing
network-none audit store profile is unchanged. This helper is not yet called by
the retained PostgreSQL restore workflow and does not establish combined recovery.

The child context holds an in-process identity link to the actual PostgreSQL
creator context/store and actual audit image creator context. Namespace and image
IDs are resolved through live native custody objects. Copied context dictionaries,
including upstream image/parent claims, are refused before another Docker call.
No manifest/container label/name can import or reconstruct these capabilities.

Before work, the helper checks the native parent's current inspection against
the existing fixed PostgreSQL runtime profile. The child uses the exact image ID
and the parent's container network namespace. It has no published ports or host
mounts, runs as 3322:3322 with read-only root, all capabilities dropped, no new
privileges, fixed CPU/memory/PID limits and three bounded private tmpfs slots.
Child runtime inspection checks the closed profile and exact tmpfs layout.

Cleanup uses the child's own native creation claim and deliberately permits
cleanup after parent loss. It does not grant work after loss. Ordinary cleanup
removes child before parent and the owned untagged image last; shared base images
are never removed. Unknown creation outcomes and creator/daemon/host death are
not solved by this process-local helper or its sleep/auto-remove settings.

`NativeRetainedNamespace.Tests.ps1` runs three real Docker cases: reverse cleanup,
parent removal through its creator, and an external stop/auto-removal leaving a
stale in-process parent claim. It compares kernel network namespace identities,
verifies twelve copied-claim refusals before native calls, refuses work after both
parent-loss paths, and confirms removal of six own containers and one own image.
The test builds a public image containing immudb, but does not start PostgreSQL,
immudb or Server services, restore data, generate/use credentials or read original
data/PKI/provider material. The provider CI job requires this additional test.

The [combined generated Server profiles](RetainedCombinedServer.md) now attach this
helper to the frozen four-input restore lifecycle. They add audit comparison,
configuration binding, temporary TLS/runtime authentication and actual Server
start/stop. The empty-container profile remains a separate resource-custody test.
Original sensitive work still requires concrete applicable authorization.
Phase 7 remains open.
