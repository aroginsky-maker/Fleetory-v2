# Retained PostgreSQL data-stage controller

The generated native profile `NativeServerPair.Tests.ps1 -Profile v2-retained`
connects the [four retained input readers](RetainedServiceInputs.md) to a real
PostgreSQL target. It uses generated application/signer dumps, a native audit
archive and the separate PostgreSQL event export. The source files are
replaced after capture; the target receives the frozen private-pipe packets.

`eng/pilot/historical/RetainedPostgresTarget.ps1` creates each target itself and
keeps the complete native create reply in the existing `AuditContainerCustody`
object. The same live owner, client and object identities are required for
inspection and disposal. Copied context/store dictionaries are refused. A
container ID, label, report or coordinator projection grants no resource access.
Removal is consumed before the native operation, confirmed by a separate absence
reply and refused on replay before another Docker call.

The target uses the existing pinned PostgreSQL 18.6 fixture profile: network
`none`, no host ports or mounts, UID/GID 999, read-only root, dropped capabilities,
no-new-privileges and three bounded tmpfs directories. Memory is limited to
384 MiB, CPU to one, process count to 128 and core dumps to zero. Shared base
images are inspected and retained. The controller removes only its own created
container through its live custody object.

The existing OS-fenced coordinator remains separate from the native owner.
Allocation is requested once, then the owner binds the input capture, expected
inventory, image and native container identity into the projection. The work
request must arrive within the five-second admission lease. The admitted data
substage is bounded to 90 seconds with native calls limited to 15 seconds; the
coordinator supervisor retains its existing 105-second fence and 108-second
transport cancellation. The generated exit and expiry cases occur before data
restore. Cleanup after interruption of an in-progress PostgreSQL restore still
requires a separate check.

The complete case restores the application and signer databases under their
fixed owner roles. Existing v2 readers compare full inventory, security and
supplemental role-state digests with the generated source. The observed profiles
contain 18 application tables/24 rows and four signer tables/five rows. Runtime
role catalog flags are measured; password/SCRAM authentication is not performed
by this socket-only substage. Existing completed original LOGIN evidence remains
separate.

The summary command emits metadata only. `retained_service_payload.py` is a
separate private native-owner pipe containing base64 packets and must never be
logged or uploaded. Its 16 MiB input limit is checked before artifact opening;
the underlying four-input reader retains its own 64 MiB ceiling. The event-export
packet is the canonical expected snapshot, while its artifact pin identifies the
full source export. No provider/identity artifact is read.

Native generated cases cover a full two-database restore, a coordinator exit
after acquisition, live lease expiry, copied-claim refusal and removal replay.
The two frame functions are shared with the existing historical coordinator;
their bodies were moved unchanged. Portable tests cover the four input boundary
and private transport. The existing legacy/v2 Server pair gates remain required.

This target is disposed when the substage ends. Native audit restore, combined
PostgreSQL/audit comparison, live Server admission, backend credentials/TLS and
original service/configuration/provider/PKI continuity remain required in the
same owned recovery scope. Unknown create outcomes, native creator death and
daemon/host loss are not verified here. The container's sleep/auto-remove setting
does not establish independent creator-death recovery. Untrusted dump execution
is not accepted as a complete sandbox proof.

Original retained files, source VPS and original private PKI/provider material
are not used by these tests. The substage grants no execution or new sensitive
authority and does not renew consumed one-shot permissions. Independent custody,
human/physical Agent and full RPO/RTO remain open. Phase 7 stays incomplete and
PR #2 stays draft/unmerged.

The separate [coupled audit namespace profile](RetainedAuditNamespace.md) tests
empty-container custody. The [combined generated Server profiles](RetainedCombinedServer.md)
now use that helper for PostgreSQL/audit restore and read-only Server admission.
The socket-only limitations above describe this standalone substage, not the
additional explicit Server profiles. Original recovery requirements remain open.
