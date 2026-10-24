-- Controlled scope-parent mutation. Run with ON_ERROR_STOP in an approved
-- transaction. Set LOCAL fleetory.scope_reparent.scope_id, new_parent_id
-- (empty for root), expected_revision, incident_reference, operator_reference
-- and approver_reference. Operator and approver references must be distinct.
DO $fleetory_scope_reparent$
DECLARE
    raw_scope_id text := current_setting('fleetory.scope_reparent.scope_id', true);
    raw_parent_id text := current_setting('fleetory.scope_reparent.new_parent_id', true);
    raw_revision text := current_setting('fleetory.scope_reparent.expected_revision', true);
    incident text := current_setting('fleetory.scope_reparent.incident_reference', true);
    operator_id text := current_setting('fleetory.scope_reparent.operator_reference', true);
    approver_id text := current_setting('fleetory.scope_reparent.approver_reference', true);
    moved_id uuid;
    new_parent_id uuid;
    old_parent_id uuid;
    scope_name text;
    expected_revision integer;
    current_revision integer;
    new_revision integer;
    event_id uuid := gen_random_uuid();
    now_utc timestamptz := clock_timestamp();
BEGIN
    IF raw_scope_id IS NULL OR raw_scope_id !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' OR
       raw_scope_id::uuid = '00000000-0000-0000-0000-000000000000'::uuid THEN
        RAISE EXCEPTION 'A valid moved scope UUID is required.';
    END IF;
    IF raw_parent_id IS NULL THEN
        RAISE EXCEPTION 'new_parent_id must be set; use an empty string explicitly for root.';
    END IF;
    IF NULLIF(raw_parent_id, '') IS NOT NULL AND
       raw_parent_id !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN
        RAISE EXCEPTION 'The new parent scope UUID is invalid.';
    END IF;
    IF raw_revision IS NULL OR raw_revision !~ '^[1-9][0-9]{0,8}$' THEN
        RAISE EXCEPTION 'A positive expected scope revision is required.';
    END IF;
    IF incident IS NULL OR incident !~ '^[A-Za-z0-9][A-Za-z0-9._/-]{3,127}$' OR
       operator_id IS NULL OR operator_id !~ '^[A-Za-z0-9][A-Za-z0-9._@/-]{0,127}$' OR
       approver_id IS NULL OR approver_id !~ '^[A-Za-z0-9][A-Za-z0-9._@/-]{0,127}$' OR
       operator_id = approver_id THEN
        RAISE EXCEPTION 'Incident, operator and distinct approver references are required.';
    END IF;

    moved_id := raw_scope_id::uuid;
    new_parent_id := NULLIF(raw_parent_id, '')::uuid;
    expected_revision := raw_revision::integer;
    PERFORM pg_advisory_xact_lock(2067, 4);

    SELECT parent_scope_id, name INTO old_parent_id, scope_name
    FROM platform.authorization_scopes WHERE scope_id = moved_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'The moved scope does not exist.';
    END IF;
    IF new_parent_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM platform.authorization_scopes WHERE scope_id = new_parent_id) THEN
        RAISE EXCEPTION 'The new parent scope does not exist.';
    END IF;
    IF new_parent_id IS NOT NULL AND new_parent_id = moved_id THEN
        RAISE EXCEPTION 'A scope cannot parent itself.';
    END IF;
    IF new_parent_id IS NOT NULL AND EXISTS (
        WITH RECURSIVE ancestors(scope_id, parent_scope_id, path) AS (
            SELECT scope_id, parent_scope_id, ARRAY[scope_id]
            FROM platform.authorization_scopes WHERE scope_id = new_parent_id
            UNION ALL
            SELECT parent.scope_id, parent.parent_scope_id, ancestors.path || parent.scope_id
            FROM platform.authorization_scopes AS parent
            JOIN ancestors ON parent.scope_id = ancestors.parent_scope_id
            WHERE NOT parent.scope_id = ANY(ancestors.path)
        ) SELECT 1 FROM ancestors WHERE scope_id = moved_id) THEN
        RAISE EXCEPTION 'The new parent is inside the moved scope subtree.';
    END IF;

    SELECT max(revision) INTO current_revision
    FROM platform.authorization_scope_versions WHERE scope_id = moved_id;
    IF current_revision IS NULL THEN
        current_revision := 1;
        INSERT INTO platform.authorization_scope_versions
            (scope_id, revision, parent_scope_id, name, recorded_at)
        VALUES (moved_id, current_revision, old_parent_id, scope_name, now_utc);
    END IF;
    IF current_revision <> expected_revision THEN
        RAISE EXCEPTION 'Scope revision is stale (expected %, current %).',
            expected_revision, current_revision;
    END IF;
    IF new_parent_id IS NOT DISTINCT FROM old_parent_id THEN
        RAISE EXCEPTION 'The new parent is unchanged.';
    END IF;

    UPDATE platform.authorization_scopes
    SET parent_scope_id = new_parent_id WHERE scope_id = moved_id;
    new_revision := current_revision + 1;
    INSERT INTO platform.authorization_scope_versions
        (scope_id, revision, parent_scope_id, name, recorded_at)
    VALUES (moved_id, new_revision, new_parent_id, scope_name, now_utc);

    INSERT INTO platform.audit_events
        (event_id, actor_subject_id, actor_kind, action, target_type, target_id,
         correlation_id, occurred_at, recorded_at, context_json)
    VALUES (event_id, 'system:scope-reparent-operator', 2,
        'platform.authorization.scope_reparented', 'scope', moved_id::text,
        'incident:' || event_id::text, now_utc, now_utc,
        jsonb_build_object('old_parent_scope_id', old_parent_id,
            'new_parent_scope_id', new_parent_id,
            'revision', new_revision, 'incident_reference', incident,
            'operator_reference', operator_id, 'approver_reference', approver_id));
    INSERT INTO platform.audit_export_queue (audit_event_id, enqueued_at, next_attempt_at)
    VALUES (event_id, now_utc, now_utc);
END
$fleetory_scope_reparent$;
