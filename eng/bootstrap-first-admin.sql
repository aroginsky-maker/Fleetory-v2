-- Run once in a controlled psql session after verifying the Admin client certificate.
-- Set fleetory.bootstrap.admin_person_id to its urn:fleetory:admin:<uuid> SAN UUID first.
-- The single DO statement is atomic, including the audit event and export queue entry.
DO $fleetory_bootstrap$
DECLARE
    raw_person_id text := current_setting('fleetory.bootstrap.admin_person_id', true);
    person_id uuid;
    bootstrap_role_id uuid := gen_random_uuid();
    bootstrap_assignment_id uuid := gen_random_uuid();
    bootstrap_event_id uuid := gen_random_uuid();
    timestamp_utc timestamptz := clock_timestamp();
BEGIN
    IF raw_person_id IS NULL OR
       raw_person_id !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN
        RAISE EXCEPTION 'A valid Admin certificate SAN UUID is required.';
    END IF;
    person_id := raw_person_id::uuid;
    IF person_id = '00000000-0000-0000-0000-000000000000'::uuid THEN
        RAISE EXCEPTION 'An empty Admin identity is not allowed.';
    END IF;

    -- Serialize concurrent bootstrap attempts even at the default isolation level.
    PERFORM pg_advisory_xact_lock(2067, 1);
    IF EXISTS (
        SELECT 1
        FROM platform.authorization_assignments AS assignment
        JOIN platform.authorization_role_permissions AS permission
          ON permission.role_id = assignment.role_id
        WHERE permission.permission = 'platform.authorization.manage'
          AND assignment.scope_id IS NULL
    ) THEN
        RAISE EXCEPTION 'A global authorization administrator already exists.';
    END IF;

    INSERT INTO platform.authorization_roles (role_id, name)
    VALUES (bootstrap_role_id, 'Fleetory Bootstrap Administrator');
    INSERT INTO platform.authorization_role_permissions (role_id, permission)
    VALUES (bootstrap_role_id, 'platform.authorization.manage');
    INSERT INTO platform.authorization_role_versions
        (role_id, predecessor_role_id, name, permissions, recorded_at)
    VALUES (bootstrap_role_id, NULL, 'Fleetory Bootstrap Administrator',
            ARRAY['platform.authorization.manage'], timestamp_utc);
    INSERT INTO platform.authorization_assignments
        (assignment_id, actor_subject_id, actor_kind, role_id, scope_id)
    VALUES (bootstrap_assignment_id, 'person:' || replace(person_id::text, '-', ''), 1,
            bootstrap_role_id, NULL);

    INSERT INTO platform.audit_events
        (event_id, actor_subject_id, actor_kind, action, target_type, target_id,
         correlation_id, occurred_at, recorded_at, context_json)
    VALUES
        (bootstrap_event_id, 'system:authorization-bootstrap', 2,
         'platform.authorization.bootstrap_created', 'assignment', bootstrap_assignment_id::text,
         'bootstrap:' || bootstrap_event_id::text, timestamp_utc, timestamp_utc,
         jsonb_build_object('subject_id', 'person:' || replace(person_id::text, '-', ''),
                            'role_id', bootstrap_role_id::text));
    INSERT INTO platform.audit_export_queue
        (audit_event_id, enqueued_at, next_attempt_at)
    VALUES (bootstrap_event_id, timestamp_utc, timestamp_utc);
END
$fleetory_bootstrap$;
