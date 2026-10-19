# Scope hierarchy change preflight

Scope parent changes are not exposed by Fleetory. A scope ID anchors existing role assignments, and grants on an ancestor apply to every descendant. Moving a subtree can therefore add or remove access for many devices without changing any assignment row.

Before proposing such a migration, a database operator must take a consistent, read-only snapshot of the candidate impact. In a `psql` session connected to the approved Fleetory database, from the repository root:

```sql
BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;
SELECT set_config('fleetory.scope_preview.scope_id', '<moved-scope-uuid>', true);
SELECT set_config('fleetory.scope_preview.new_parent_id', '<new-parent-uuid>', true);
\i eng/preview-scope-reparent.sql
ROLLBACK;
```

Use an empty string for `new_parent_id` to preview a move to the root. The query returns one JSON report. Only `status=valid` is reviewable. `missing_scope`, `missing_parent`, `invalid_hierarchy`, `cycle` and `no_change` are not actionable. The report includes the number of scopes in the moved subtree, `candidate_access_changes` (ancestor assignment rows added or removed by the move), and `effective_access_changes` (actor, actor kind, permission and descendant scope decisions that actually flip). Global grants and grants within the subtree are unchanged and excluded from the candidate list, but they are considered when calculating effective access.

A candidate grant can be masked by another assignment. Use `effective_access_changes` to review the actual decision delta for every affected actor, permission and descendant; a child grant or a second ancestor grant may keep access unchanged. The integration test checks these results against Fleetory authorization decisions before and after a temporary move inside a rolled-back transaction. Record the report, scope IDs, proposed parent, incident/change reference, the second reviewer's approval and a rollback plan without storing credentials. Re-run the preview immediately before a controlled migration under an exclusive change window; a stale report is not approval. Any future mutation path must enforce the same cycle checks, update scope revision history, and commit its completion audit and export entry with the parent change in one transaction. No scope parent mutation script or API is provided yet.
