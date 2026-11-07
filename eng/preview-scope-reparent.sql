-- Read-only impact preview. Set fleetory.scope_preview.scope_id and
-- fleetory.scope_preview.new_parent_id (empty string means root) in this session.
-- Candidate grants may be masked by other grants; review each actor and permission.
WITH RECURSIVE
input AS (
    SELECT current_setting('fleetory.scope_preview.scope_id')::uuid AS scope_id,
           NULLIF(current_setting('fleetory.scope_preview.new_parent_id'), '')::uuid
               AS new_parent_id
),
moved AS (
    SELECT scope_id, parent_scope_id
    FROM platform.authorization_scopes
    WHERE scope_id = (SELECT scope_id FROM input)
),
subtree AS (
    SELECT scope_id, ARRAY[scope_id] AS path
    FROM moved
    UNION ALL
    SELECT child.scope_id, subtree.path || child.scope_id
    FROM platform.authorization_scopes AS child
    JOIN subtree ON child.parent_scope_id = subtree.scope_id
    WHERE NOT child.scope_id = ANY(subtree.path)
),
old_ancestors AS (
    SELECT scope_id, parent_scope_id, ARRAY[scope_id] AS path
    FROM platform.authorization_scopes
    WHERE scope_id = (SELECT parent_scope_id FROM moved)
    UNION ALL
    SELECT parent.scope_id, parent.parent_scope_id, old_ancestors.path || parent.scope_id
    FROM platform.authorization_scopes AS parent
    JOIN old_ancestors ON parent.scope_id = old_ancestors.parent_scope_id
    WHERE NOT parent.scope_id = ANY(old_ancestors.path)
),
new_ancestors AS (
    SELECT scope_id, parent_scope_id, ARRAY[scope_id] AS path
    FROM platform.authorization_scopes
    WHERE scope_id = (SELECT new_parent_id FROM input)
    UNION ALL
    SELECT parent.scope_id, parent.parent_scope_id, new_ancestors.path || parent.scope_id
    FROM platform.authorization_scopes AS parent
    JOIN new_ancestors ON parent.scope_id = new_ancestors.parent_scope_id
    WHERE NOT parent.scope_id = ANY(new_ancestors.path)
),
validation AS (
    SELECT CASE
        WHEN NOT EXISTS (SELECT 1 FROM moved) THEN 'missing_scope'
        WHEN (SELECT new_parent_id FROM input) IS NOT NULL
             AND NOT EXISTS (
                 SELECT 1 FROM platform.authorization_scopes
                 WHERE scope_id = (SELECT new_parent_id FROM input)
             ) THEN 'missing_parent'
        WHEN EXISTS (
            SELECT 1 FROM subtree AS node
            JOIN platform.authorization_scopes AS child
              ON child.parent_scope_id = node.scope_id
            WHERE child.scope_id = ANY(node.path)
        ) OR EXISTS (
            SELECT 1 FROM old_ancestors
            WHERE parent_scope_id = ANY(path)
        ) OR EXISTS (
            SELECT 1 FROM new_ancestors
            WHERE parent_scope_id = ANY(path)
        ) THEN 'invalid_hierarchy'
        WHEN EXISTS (
            SELECT 1 FROM subtree
            WHERE scope_id = (SELECT new_parent_id FROM input)
        ) THEN 'cycle'
        WHEN (SELECT new_parent_id FROM input) IS NOT DISTINCT FROM
             (SELECT parent_scope_id FROM moved) THEN 'no_change'
        ELSE 'valid'
    END AS status
),
changed_ancestors AS (
    SELECT 'lost'::text AS effect, scope_id FROM old_ancestors
    WHERE scope_id NOT IN (SELECT scope_id FROM new_ancestors)
    UNION ALL
    SELECT 'gained'::text AS effect, scope_id FROM new_ancestors
    WHERE scope_id NOT IN (SELECT scope_id FROM old_ancestors)
),
candidate_grants AS (
    SELECT changed.effect, changed.scope_id AS grant_scope_id,
           assignment.assignment_id, assignment.actor_subject_id,
           assignment.actor_kind, permission.permission
    FROM changed_ancestors AS changed
    JOIN platform.authorization_assignments AS assignment
      ON assignment.scope_id = changed.scope_id
    JOIN platform.authorization_role_permissions AS permission
      ON permission.role_id = assignment.role_id
),
subtree_ancestors AS (
    SELECT subtree.scope_id AS target_scope_id,
           scope.scope_id AS ancestor_scope_id,
           scope.parent_scope_id, ARRAY[scope.scope_id] AS path
    FROM subtree
    JOIN platform.authorization_scopes AS scope ON scope.scope_id = subtree.scope_id
    UNION ALL
    SELECT ancestor.target_scope_id, parent.scope_id,
           parent.parent_scope_id, ancestor.path || parent.scope_id
    FROM subtree_ancestors AS ancestor
    JOIN platform.authorization_scopes AS parent
      ON parent.scope_id = ancestor.parent_scope_id
    WHERE NOT parent.scope_id = ANY(ancestor.path)
),
candidate_decisions AS (
    SELECT DISTINCT subtree.scope_id AS target_scope_id,
           candidate_grant.actor_subject_id, candidate_grant.actor_kind, candidate_grant.permission
    FROM candidate_grants AS candidate_grant
    CROSS JOIN subtree
),
decision_comparison AS (
    SELECT candidate.*,
           EXISTS (
               SELECT 1
               FROM platform.authorization_assignments AS assignment
               JOIN platform.authorization_role_permissions AS permission
                 ON permission.role_id = assignment.role_id
               WHERE assignment.actor_subject_id = candidate.actor_subject_id
                 AND assignment.actor_kind = candidate.actor_kind
                 AND permission.permission = candidate.permission
                 AND (assignment.scope_id IS NULL OR assignment.scope_id IN (
                     SELECT ancestor_scope_id FROM subtree_ancestors
                     WHERE target_scope_id = candidate.target_scope_id
                 ))
           ) AS allowed_before,
           EXISTS (
               SELECT 1
               FROM platform.authorization_assignments AS assignment
               JOIN platform.authorization_role_permissions AS permission
                 ON permission.role_id = assignment.role_id
               WHERE assignment.actor_subject_id = candidate.actor_subject_id
                 AND assignment.actor_kind = candidate.actor_kind
                 AND permission.permission = candidate.permission
                 AND (assignment.scope_id IS NULL OR assignment.scope_id IN (
                     SELECT ancestor_scope_id FROM subtree_ancestors
                     WHERE target_scope_id = candidate.target_scope_id
                       AND ancestor_scope_id IN (SELECT scope_id FROM subtree)
                     UNION
                     SELECT scope_id FROM new_ancestors
                 ))
           ) AS allowed_after
    FROM candidate_decisions AS candidate
),
effective_changes AS (
    SELECT CASE WHEN allowed_after THEN 'gained' ELSE 'lost' END AS effect,
           target_scope_id, actor_subject_id, actor_kind, permission
    FROM decision_comparison
    WHERE allowed_before <> allowed_after
)
SELECT jsonb_build_object(
    'status', (SELECT status FROM validation),
    'moved_scope_id', (SELECT scope_id FROM input),
    'old_parent_scope_id', (SELECT parent_scope_id FROM moved),
    'new_parent_scope_id', (SELECT new_parent_id FROM input),
    'subtree_scope_count', (SELECT COUNT(*) FROM subtree),
    'candidate_access_changes',
       CASE WHEN (SELECT status FROM validation) = 'valid'
            THEN COALESCE((SELECT jsonb_agg(to_jsonb(candidate_grants)
                ORDER BY effect, actor_subject_id, permission, assignment_id)
                FROM candidate_grants), '[]'::jsonb)
            ELSE '[]'::jsonb END,
    'effective_access_changes',
       CASE WHEN (SELECT status FROM validation) = 'valid'
            THEN COALESCE((SELECT jsonb_agg(to_jsonb(effective_changes)
                ORDER BY effect, actor_subject_id, actor_kind, permission, target_scope_id)
                FROM effective_changes), '[]'::jsonb)
            ELSE '[]'::jsonb END
) AS scope_reparent_preview;
