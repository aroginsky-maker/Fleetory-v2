# Actual frozen-archive data restore interruption

`NativeServerPair.Tests.ps1 -Profile v2-retained-restore-inflight -Python <python>`
tests a real `pg_restore` operation, rather than relabelling the separate sleeping
SQL query profile. Inputs and targets are generated; no original retained files,
source VPS, private PKI/provider/identity material or production tokens are used.

The existing four-input reader freezes all packets and replaces source paths.
The application custom-format archive is used for a pre-data schema restore in
the owned target. Post-data constraints are deliberately excluded from this
preparation so the data-only attempt can reach the selected COPY operation.
This is one completed pre-data schema operation, not a full database restore.

A fixed, bounded psql transaction in the same owned container takes an
access-exclusive lock on `platform.audit_events`. The owner confirms its granted
relation lock and marked active backend. A real `pg_restore --data-only` then
reads the same frozen archive, under the fixed migrator role and single
transaction. The original 15-second native budget remains in force.

The observer requires the marked restore backend to be active in COPY of that
table, waiting on a lock whose blocker is the verified own lock-holder backend.
The actual launched Docker client and held coordinator must still be live.
Only this state permits the distinct projection-bound restore-interruption
frame. The SQL-sleep and restore purposes cannot use each other's frames.

The supervisor terminates only its own held coordinator fence. Its nonzero exit,
whole-fence absence, exact native-client exit and rejection of a later native
request are required. Cleanup removes the owned audit holder before PostgreSQL,
then the owned image. Removing PostgreSQL also ends the bounded lock-holder
process. No process is adopted or signalled using a backend PID from a report.

The single-case summary reports zero complete application/signer restores, one
pre-data schema operation, one interrupted data-only attempt, zero audit restores
and zero Server starts. The SQL-purpose result remains false for this case; the
separate SQL profile continues to report two complete database restores and one
audit restore. Unexecuted lifecycle cases are not promoted by either summary.

Portable tests reject mismatched purposes/projections and dead held identities.
Required native CI runs this additional case in the existing retained Linux job,
with its original 15-minute job limit. Native/work/supervisor/transport limits and
the 256-status bound are unchanged. Per-OS actual execution evidence is retained
separately; a successful Windows-parent run does not establish Linux execution.

This proves the tested COPY-stage cancellation and own-resource cleanup. It does
not prove rollback solely from client disconnect, arbitrary restore stages,
immudb restore interruption, complete recovery, native creator/daemon/host loss,
unknown-create recovery or global atomicity. Independent custody/actors,
original service/configuration/provider/PKI continuity, human/physical Agent and
full RPO/RTO remain open. Phase 7 stays incomplete and PR #2 stays draft/unmerged.
