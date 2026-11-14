-- Emergency operator action after independent approval and replacement-access check.
-- Set fleetory.admin_revoke.certificate_sha256 to uppercase SHA-256 of the exact DER leaf,
-- fleetory.admin_revoke.incident_reference and fleetory.admin_revoke.operator_reference.
-- Run with ON_ERROR_STOP enabled against the approved Fleetory database.
-- This single statement commits the revocation and its audit/export entry atomically.
DO $fleetory_admin_revoke$
DECLARE
    fingerprint text := current_setting('fleetory.admin_revoke.certificate_sha256', true);
    incident text := current_setting('fleetory.admin_revoke.incident_reference', true);
    operator_id text := current_setting('fleetory.admin_revoke.operator_reference', true);
    event_id uuid := gen_random_uuid();
    now_utc timestamptz := clock_timestamp();
BEGIN
    IF fingerprint IS NULL OR fingerprint !~ '^[0-9A-F]{64}$' THEN
        RAISE EXCEPTION 'An uppercase Admin certificate SHA-256 is required.';
    END IF;
    IF incident IS NULL OR length(trim(incident)) = 0 OR length(incident) > 128 OR
       operator_id IS NULL OR length(trim(operator_id)) = 0 OR length(operator_id) > 128 THEN
        RAISE EXCEPTION 'Incident and operator references of 1-128 characters are required.';
    END IF;

    INSERT INTO platform.admin_certificate_revocations
        (certificate_sha256, revoked_at, incident_reference, operator_reference)
    VALUES (fingerprint, now_utc, incident, operator_id);

    INSERT INTO platform.audit_events
        (event_id, actor_subject_id, actor_kind, action, target_type, target_id,
         correlation_id, occurred_at, recorded_at, context_json)
    VALUES
        (event_id, 'system:admin-certificate-operator', 2,
         'admin.certificate.revoked', 'admin_certificate', fingerprint,
         'incident:' || event_id::text, now_utc, now_utc,
         jsonb_build_object('incident_reference', incident,
                            'operator_reference', operator_id));
    INSERT INTO platform.audit_export_queue
        (audit_event_id, enqueued_at, next_attempt_at)
    VALUES (event_id, now_utc, now_utc);
END
$fleetory_admin_revoke$;
