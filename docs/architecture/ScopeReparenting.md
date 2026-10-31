# Scope hierarchy change preflight

Scope parent changes are not exposed through the HTTP Admin API. A scope ID anchors existing role assignments, and grants on an ancestor apply to every descendant. Moving a subtree can therefore add or remove access for many devices without changing any assignment row.

Before proposing such a migration, a database operator must take a consistent, read-only snapshot of the candidate impact. In a `psql` session connected to the approved Fleetory database, from the repository root:

```sql
BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;
SELECT set_config('fleetory.scope_preview.scope_id', '<moved-scope-uuid>', true);
SELECT set_config('fleetory.scope_preview.new_parent_id', '<new-parent-uuid>', true);
\i eng/preview-scope-reparent.sql
ROLLBACK;
```

Use an empty string for `new_parent_id` to preview a move to the root. The query returns one JSON report. Only `status=valid` is reviewable. `missing_scope`, `missing_parent`, `invalid_hierarchy`, `cycle` and `no_change` are not actionable. The report includes the number of scopes in the moved subtree, `candidate_access_changes` (ancestor assignment rows added or removed by the move), and `effective_access_changes` (actor, actor kind, permission and descendant scope decisions that actually flip). Global grants and grants within the subtree are unchanged and excluded from the candidate list, but they are considered when calculating effective access.

A candidate grant can be masked by another assignment. Use `effective_access_changes` to review the actual decision delta for every affected actor, permission and descendant; a child grant or a second ancestor grant may keep access unchanged. The integration test checks these results against Fleetory authorization decisions before and after a temporary move inside a rolled-back transaction. Record the report, scope IDs, proposed parent, incident/change reference, the second reviewer's approval and a rollback plan without storing credentials. Re-run the preview immediately before a controlled migration under an exclusive change window; a stale report is not approval.

The controlled mutation procedure is [reparent-scope.sql](../../eng/reparent-scope.sql). It requires an incident reference, distinct operator and approver references, and the expected current scope revision. It serializes the change, rejects missing parents, self-parenting, cycles, stale revisions and no-ops, snapshots the old and new parent versions, and writes the audit event plus export queue entry in the same transaction. Run it only after reviewing this preflight in an explicit change window; it does not replace the organization's approval record. The operator must keep all settings and the procedure in one transaction so `SET LOCAL` values remain visible:

```sql
BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE;
SELECT set_config('fleetory.scope_reparent.scope_id', '<moved-scope-uuid>', true);
SELECT set_config('fleetory.scope_reparent.new_parent_id', '<parent-uuid-or-empty-for-root>', true);
SELECT set_config('fleetory.scope_reparent.expected_revision', '<current-revision>', true);
SELECT set_config('fleetory.scope_reparent.incident_reference', '<incident-reference>', true);
SELECT set_config('fleetory.scope_reparent.operator_reference', '<operator-reference>', true);
SELECT set_config('fleetory.scope_reparent.approver_reference', '<approver-reference>', true);
\i eng/reparent-scope.sql
COMMIT;
```

Use `ROLLBACK` if the procedure raises an error. The approver and operator references identify the independently retained approval record; they are not credentials.

Actor references must be stable ASCII identifiers from the independently retained
approval record. Whitespace is rejected, and operator/approver comparison ignores
ASCII case using PostgreSQL's fixed `C` collation. For example, `operator-a` and
`OPERATOR-A` identify the same reference and cannot authorize a change together.
Different actor references keep their original spelling in audit evidence.

A rejected reference pair leaves the parent, version history, audit events and
export queue unchanged. Distinct strings cannot prove two independent people:
operators must also check immutable principal identities and approval authenticity
in the independent control plane before executing the script.
