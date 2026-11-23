-- Read-only incident inspection in the separate signer database, using a fresh session.
-- Set fleetory.signer_reconcile.request_id to the known nonempty UUID first.
-- Run with ON_ERROR_STOP. Retain the JSON observation with independently approved evidence.
-- None of these states authorizes retry, proves delivery or recovers a signature.
BEGIN TRANSACTION READ ONLY;
SET LOCAL statement_timeout = '5s';
SET LOCAL lock_timeout = '2s';
SET LOCAL idle_in_transaction_session_timeout = '5s';
SET LOCAL TIME ZONE 'UTC';
DO $fleetory_signer_reconcile$
DECLARE
    requested_id text := current_setting('fleetory.signer_reconcile.request_id', true);
BEGIN
    IF current_setting('transaction_read_only') <> 'on' OR current_user <> session_user OR
       pg_current_xact_id_if_assigned() IS NOT NULL THEN
        RAISE EXCEPTION 'A fresh read-only transaction and direct operator login are required.';
    END IF;
    IF requested_id IS NULL OR length(requested_id) <> 36 OR
       requested_id !~ '^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$' THEN
        RAISE EXCEPTION 'A canonical nonempty signing RequestId is required.';
    END IF;
    IF requested_id::uuid = '00000000-0000-0000-0000-000000000000'::uuid THEN
        RAISE EXCEPTION 'A canonical nonempty signing RequestId is required.';
    END IF;
END
$fleetory_signer_reconcile$;

WITH requested AS (
    SELECT current_setting('fleetory.signer_reconcile.request_id')::uuid AS request_id
)
SELECT jsonb_build_object(
    'schema', 'fleetory.signing-reconciliation.v1',
    'requestId', requested.request_id,
    'status', CASE WHEN attempt.request_id IS NULL THEN 'NotFound'
                   WHEN result.request_id IS NULL THEN 'Pending' ELSE 'SigningRecorded' END,
    'observedAt', statement_timestamp(),
    'database', current_database(),
    'databaseOperator', session_user,
    'readOnly', current_setting('transaction_read_only') = 'on',
    'automaticRetryAllowed', false,
    'deliveryVerified', false,
    'executionVerified', false,
    'request', CASE WHEN attempt.request_id IS NULL THEN NULL ELSE jsonb_build_object(
        'callerId', attempt.caller_id,
        'clientCertificateSha256', attempt.client_certificate_sha256,
        'deviceId', attempt.target_device_id,
        'commandType', attempt.command_type,
        'acceptedAt', attempt.accepted_at) END,
    'result', CASE WHEN result.request_id IS NULL THEN NULL ELSE jsonb_build_object(
        'commandId', result.command_id,
        'signingKeyId', result.signing_key_id,
        'envelopeSha256', result.envelope_sha256,
        'recordedAt', result.recorded_at) END
)
FROM requested
LEFT JOIN signer.signing_requests AS attempt USING (request_id)
LEFT JOIN signer.signing_results AS result USING (request_id);
COMMIT;
