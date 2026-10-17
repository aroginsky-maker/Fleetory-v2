-- Controlled break-glass grant for a replacement Admin certificate identity.
-- Requires fleetory.recovery.admin_person_id and fleetory.recovery.incident_id.
-- The database operator must independently verify the replacement certificate,
-- incident approval and custody before running this script with psql.
-- This script does not remove the previous administrator's grant.
DO $fleetory_recovery$
DECLARE
    raw_person_id text := current_setting('fleetory.recovery.admin_person_id', true);
    incident_id text := current_setting('fleetory.recovery.incident_id', true);
    person_id uuid;
    replacement_subject text;
    recovery_role_id uuid := gen_random_uuid();
    recovery_assignment_id uuid := gen_random_uuid();
    recovery_event_id uuid := gen_random_uuid();
    timestamp_utc timestamptz := clock_timestamp();
BEGIN
    IF raw_person_id IS NULL OR
       raw_person_id !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN
        RAISE EXCEPTION 'A valid replacement Admin certificate SAN UUID is required.';
    END IF;
    person_id := raw_person_id::uuid;
    IF person_id = '00000000-0000-0000-0000-000000000000'::uuid THEN
        RAISE EXCEPTION 'An empty Admin identity is not allowed.';
    END IF;
    IF incident_id IS NULL OR
       incident_id !~ '^[A-Za-z0-9][A-Za-z0-9._/-]{3,127}$' THEN
        RAISE EXCEPTION 'A bounded incident reference is required.';
    END IF;
    replacement_subject := 'person:' || replace(person_id::text, '-', '');

    -- Share the bootstrap lock to serialize offline administrator grants.
    PERFORM pg_advisory_xact_lock(2067, 1);
    IF NOT EXISTS (
        SELECT 1 FROM platform.authorization_assignments AS assignment
        JOIN platform.authorization_role_permissions AS permission
          ON permission.role_id = assignment.role_id
        WHERE assignment.scope_id IS NULL
          AND permission.permission = 'platform.authorization.manage'
    ) THEN
        RAISE EXCEPTION 'No existing global administrator; use the first-admin bootstrap.';
    END IF;
    IF EXISTS (
        SELECT 1 FROM platform.authorization_assignments AS assignment
        JOIN platform.authorization_role_permissions AS permission
          ON permission.role_id = assignment.role_id
        WHERE assignment.scope_id IS NULL
          AND assignment.actor_kind = 1
          AND assignment.actor_subject_id = replacement_subject
          AND permission.permission = 'platform.authorization.manage'
    ) THEN
        RAISE EXCEPTION 'Replacement identity already has global administrator access.';
    END IF;

    INSERT INTO platform.authorization_roles (role_id, name)
    VALUES (recovery_role_id, 'Fleetory Recovery Administrator ' || person_id::text);
    INSERT INTO platform.authorization_role_permissions (role_id, permission)
    VALUES (recovery_role_id, 'platform.authorization.manage');
    INSERT INTO platform.authorization_assignments
        (assignment_id, actor_subject_id, actor_kind, role_id, scope_id)
    VALUES (recovery_assignment_id, replacement_subject, 1, recovery_role_id, NULL);

    INSERT INTO platform.audit_events
        (event_id, actor_subject_id, actor_kind, action, target_type, target_id,
         correlation_id, occurred_at, recorded_at, context_json)
    VALUES
        (recovery_event_id, 'system:authorization-recovery', 2,
         'platform.authorization.recovery_created', 'assignment',
         recovery_assignment_id::text,
         'recovery:' || recovery_event_id::text, timestamp_utc, timestamp_utc,
         jsonb_build_object('subject_id', replacement_subject,
                            'incident_id', incident_id,
                            'database_operator', session_user,
                            'role_id', recovery_role_id::text));
    INSERT INTO platform.audit_export_queue
        (audit_event_id, enqueued_at, next_attempt_at)
    VALUES (recovery_event_id, timestamp_utc, timestamp_utc);
END
$fleetory_recovery$;
