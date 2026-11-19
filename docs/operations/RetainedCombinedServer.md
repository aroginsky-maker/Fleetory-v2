# Generated retained PostgreSQL, audit and Server recovery

Run the explicit `v2-retained-server` or `v2-retained-historical-server`
profile of `tests/Fleetory.Tools.Tests/NativeServerPair.Tests.ps1` with the
configured Python executable. Both profiles use generated data and temporary
credentials/TLS only. They do not authorize reading original retained inputs,
private PKI, provider material, source VPS access or production token issuance.

The four-input reader captures application/signer PostgreSQL dumps, the native
audit archive and a separate PostgreSQL event snapshot. Source paths are then
replaced; restores use the frozen captured bytes. The actual owned PostgreSQL
target and untagged audit image creator objects establish the audit child's
shared network namespace. Metadata copies cannot adopt resources. Cleanup uses
the native creation claims, removes child before parent, and disposes only the
owned untagged image. Shared base images are retained.

Before controller admission, an immutable collection freezes 27 configuration
values: 22 file contents and five credential intents. The domain-separated
configuration digest, actual PostgreSQL/audit/image IDs, compiled probe digest
and frozen input pins enter the controller projection. Raw configuration and
credential values stay in the private process/pipe. Each permitted file write
checks the frozen path/value before native dispatch; readback verifies its SHA,
mode 600, expected UID and one hard link. Modified and unknown slots are refused
before native access. The collection's setter must reject mutation.

The normal case restores both databases and audit, compares four known events
and five transactions, verifies fresh-target audit signatures, authenticates
both runtime roles over TLS/SCRAM, and checks bounded role privileges. Wrong
password and plaintext access fail for each role. A generic Server preflight
compares the separate snapshot to actual PostgreSQL rows and known audit values;
it does not require generated fixture identities. Three invalid admission
frames are refused with ports closed. The actual application starts, becomes
healthy, stops and closes its listeners. Complete database inventories and audit
signatures are checked again after shutdown. Audit access is read-only.

The historical profile explicitly preserves one null context member. Strict
writer expectations must reject it; there is no automatic fallback or writer
admission. The extra audit sorted-set entry remains unreviewed. Neither profile
claims whole-keyspace validation or authorizes an issuer.

Six lifecycle cases cover completion, controller exit after resource acquisition,
lease expiry, exit after restore, expiry after restore, and child loss at the
runtime-inspection boundary. A fixed bounded work-status exchange checks the
held child identity before and after inspection. No work dispatch follows the
tested inspection-boundary loss. It does not prove atomicity against arbitrary
in-flight operation interruption, unknown creation outcomes, native owner death,
Docker daemon failure or host loss.

Expected configuration writes are 22 in the completed Server case, 12 in each
post-restore failure case and zero in the other three cases. Every case requires
two configuration drift refusals and one immutable-collection refusal. The
standalone coupled audit profile writes eight files per restored case. Required
legacy/v2 gates remain separate regressions; all existing job deadlines and
failure semantics are preserved.

Original release/configuration/provider/PKI continuity, independent WORM/custody
and actors, human login, physical Agent and full RPO/RTO remain separate open
requirements. These generated checks do not establish production readiness or
complete Phase 7. Keep PR #2 draft and unmerged until all Baseline requirements
have actual evidence.
