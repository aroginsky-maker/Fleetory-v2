-- Register an exact DER leaf digest for the Admin listener. Run in an approved
-- transaction with ON_ERROR_STOP and SET LOCAL fleetory.admin_register.* values.
-- Required: mode (bootstrap|rotate|recovery), person_id (SAN UUID),
-- certificate_sha256 (uppercase), incident_reference, operator_reference.
-- For rotate, also set previous_certificate_sha256 to the current leaf digest.
-- Recovery is a separately approved new-identity enrollment after the RBAC
-- recovery script in the same transaction; it leaves other identities intact.
DO $fleetory_admin_register$
DECLARE
    registration_mode text := current_setting('fleetory.admin_register.mode', true);
    person_id text := current_setting('fleetory.admin_register.person_id', true);
    fingerprint text := current_setting('fleetory.admin_register.certificate_sha256', true);
    previous_fingerprint text := nullif(current_setting(
        'fleetory.admin_register.previous_certificate_sha256', true), '');
    incident text := current_setting('fleetory.admin_register.incident_reference', true);
    operator_id text := current_setting('fleetory.admin_register.operator_reference', true);
    actor_id text;
    active_count integer;
    event_id uuid := gen_random_uuid();
    now_utc timestamptz := clock_timestamp();
BEGIN
    IF registration_mode NOT IN ('bootstrap', 'rotate', 'recovery') OR
       registration_mode IS NULL THEN
        RAISE EXCEPTION 'Admin registration mode must be bootstrap, rotate or recovery.';
    END IF;
    IF person_id IS NULL OR person_id !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN
        RAISE EXCEPTION 'A valid Admin SAN person UUID is required.';
    END IF;
    IF person_id::uuid = '00000000-0000-0000-0000-000000000000'::uuid THEN
        RAISE EXCEPTION 'An empty Admin identity is not allowed.';
    END IF;
    actor_id := 'person:' || replace(lower(person_id), '-', '');
    IF fingerprint IS NULL OR fingerprint !~ '^[0-9A-F]{64}$' OR
       (previous_fingerprint IS NOT NULL AND
        previous_fingerprint !~ '^[0-9A-F]{64}$') THEN
        RAISE EXCEPTION 'Uppercase Admin leaf SHA-256 digests are required.';
    END IF;
    IF incident IS NULL OR length(trim(incident)) = 0 OR length(incident) > 128 OR
       operator_id IS NULL OR length(trim(operator_id)) = 0 OR length(operator_id) > 128 THEN
        RAISE EXCEPTION 'Incident and operator references of 1-128 characters are required.';
    END IF;
    IF (registration_mode = 'rotate') <> (previous_fingerprint IS NOT NULL) OR
       previous_fingerprint = fingerprint THEN
        RAISE EXCEPTION 'Only rotation accepts a distinct previous certificate digest.';
    END IF;

    -- Serialize registrations across all actors, including first bootstrap.
    PERFORM pg_advisory_xact_lock(2067, 3);
    IF EXISTS (SELECT 1 FROM platform.admin_certificate_revocations
               WHERE certificate_sha256 = fingerprint) THEN
        RAISE EXCEPTION 'A revoked Admin certificate cannot be registered.';
    END IF;

    SELECT count(*) INTO active_count
    FROM platform.admin_certificate_registrations AS registration
    WHERE (registration_mode = 'bootstrap' OR registration.actor_subject_id = actor_id)
      AND (registration.overlap_ends_at IS NULL OR registration.overlap_ends_at > now_utc)
      AND NOT EXISTS (
          SELECT 1 FROM platform.admin_certificate_revocations AS revocation
          WHERE revocation.certificate_sha256 = registration.certificate_sha256);

    IF registration_mode = 'bootstrap' AND active_count <> 0 THEN
        RAISE EXCEPTION 'Initial Admin certificate requires no active registrations.';
    ELSIF registration_mode = 'recovery' AND active_count <> 0 THEN
        RAISE EXCEPTION 'Recovery identity already has an active certificate.';
    ELSIF registration_mode = 'rotate' THEN
        IF active_count <> 1 OR NOT EXISTS (
            SELECT 1 FROM platform.admin_certificate_registrations
            WHERE certificate_sha256 = previous_fingerprint
              AND actor_subject_id = actor_id
              AND (overlap_ends_at IS NULL OR overlap_ends_at > now_utc)) OR
           EXISTS (SELECT 1 FROM platform.admin_certificate_revocations
                   WHERE certificate_sha256 = previous_fingerprint) THEN
            RAISE EXCEPTION 'Rotation requires exactly one matching active prior certificate.';
        END IF;
        UPDATE platform.admin_certificate_registrations
        SET overlap_ends_at = now_utc + interval '1 hour'
        WHERE certificate_sha256 = previous_fingerprint;
    END IF;

    INSERT INTO platform.admin_certificate_registrations
        (certificate_sha256, actor_subject_id, registered_at, overlap_ends_at,
         previous_certificate_sha256, incident_reference, operator_reference)
    VALUES (fingerprint, actor_id, now_utc, NULL, previous_fingerprint,
            incident, operator_id);

    INSERT INTO platform.audit_events
        (event_id, actor_subject_id, actor_kind, action, target_type, target_id,
         correlation_id, occurred_at, recorded_at, context_json)
    VALUES (event_id, 'system:admin-certificate-operator', 2,
            'admin.certificate.' || registration_mode, 'admin_certificate', fingerprint,
            'incident:' || event_id::text, now_utc, now_utc,
            jsonb_build_object('person_id', person_id, 'incident_reference', incident,
                               'operator_reference', operator_id,
                               'previous_certificate_sha256', previous_fingerprint));
    INSERT INTO platform.audit_export_queue
        (audit_event_id, enqueued_at, next_attempt_at)
    VALUES (event_id, now_utc, now_utc);
END
$fleetory_admin_register$;
