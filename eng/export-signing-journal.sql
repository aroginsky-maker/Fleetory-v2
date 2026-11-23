-- Full bounded observation for independent evidence retention, not an incremental exporter.
-- Run with ON_ERROR_STOP in a fresh session under a dedicated SELECT-only signer login.
-- Protect and hash the exact output bytes before transfer to the independently managed archive.
BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL statement_timeout = '5s';
SET LOCAL lock_timeout = '2s';
SET LOCAL idle_in_transaction_session_timeout = '5s';
SET LOCAL TIME ZONE 'UTC';
SET LOCAL client_encoding = 'UTF8';
SET LOCAL search_path = pg_catalog;
DO $fleetory_signer_export$
DECLARE
    payload jsonb;
    rendered text;
BEGIN
    IF current_setting('transaction_read_only') <> 'on' OR current_user <> session_user OR
       pg_current_xact_id_if_assigned() IS NOT NULL THEN
        RAISE EXCEPTION 'A fresh read-only transaction and direct operator login are required.';
    END IF;
    IF current_setting('transaction_isolation') <> 'repeatable read' THEN
        RAISE EXCEPTION 'A repeatable-read snapshot is required.';
    END IF;
    IF (SELECT count(*) FROM (SELECT 1 FROM signer.signing_requests LIMIT 5001) AS bounded) > 5000 OR
       (SELECT count(*) FROM (SELECT 1 FROM signer.signing_results LIMIT 5001) AS bounded) > 5000 OR
       (SELECT count(*) FROM (SELECT 1 FROM signer.signing_rejections LIMIT 5001) AS bounded) > 5000 OR
       (SELECT count(*) FROM (SELECT 1 FROM signer.client_certificate_revocations LIMIT 5001) AS bounded) > 5000 THEN
        RAISE EXCEPTION 'Signer snapshot exceeds the 5000-row limit per table; no partial export is permitted.';
    END IF;
    payload := jsonb_build_object(
        'schema', 'fleetory.signer-journal-snapshot.v1',
        'observedAt', statement_timestamp(),
        'database', current_database(),
        'databaseOperator', session_user,
        'readOnly', true,
        'snapshotComplete', true,
        'deliveryVerified', false,
        'executionVerified', false,
        'independentCustodyVerified', false,
        'requests', COALESCE((SELECT jsonb_agg(to_jsonb(row) ORDER BY row.request_id) FROM (
            SELECT request_id, caller_id, client_certificate_sha256, target_device_id, command_type, accepted_at
            FROM signer.signing_requests) AS row), '[]'::jsonb),
        'results', COALESCE((SELECT jsonb_agg(to_jsonb(row) ORDER BY row.request_id) FROM (
            SELECT request_id, command_id, signing_key_id, envelope_sha256, recorded_at
            FROM signer.signing_results) AS row), '[]'::jsonb),
        'rejections', COALESCE((SELECT jsonb_agg(to_jsonb(row) ORDER BY row.event_id) FROM (
            SELECT event_id, client_certificate_sha256, reason, request_id, target_device_id, recorded_at
            FROM signer.signing_rejections) AS row), '[]'::jsonb),
        'revocations', COALESCE((SELECT jsonb_agg(to_jsonb(row) ORDER BY row.certificate_sha256) FROM (
            SELECT certificate_sha256, event_id, incident_reference, operator_reference, approver_reference,
                   evidence_sha256, database_operator, revoked_at
            FROM signer.client_certificate_revocations) AS row), '[]'::jsonb));
    rendered := payload::text;
    IF octet_length(convert_to(rendered, 'UTF8')) > 8388608 THEN
        RAISE EXCEPTION 'Signer snapshot exceeds the 8 MiB limit; no partial export is permitted.';
    END IF;
    -- Transaction-local memory only: no table, function, journal write or persistent database setting.
    PERFORM set_config('fleetory.signer_export.payload', rendered, true);
END
$fleetory_signer_export$;
SELECT current_setting('fleetory.signer_export.payload')::jsonb;
COMMIT;
