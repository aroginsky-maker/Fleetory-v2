-- Run with ON_ERROR_STOP in the independent signer database after approval.
-- Set fleetory.signer_revoke.certificate_sha256, incident_reference,
-- operator_reference, approver_reference and evidence_sha256 in this session.
-- References are evidence pointers, not proof of human authentication or approval.
-- A duplicate revocation fails without replacing the original evidence.
DO $fleetory_signer_revoke$
DECLARE
    fingerprint text := current_setting('fleetory.signer_revoke.certificate_sha256', true);
    incident text := current_setting('fleetory.signer_revoke.incident_reference', true);
    operator_id text := current_setting('fleetory.signer_revoke.operator_reference', true);
    approver_id text := current_setting('fleetory.signer_revoke.approver_reference', true);
    evidence text := current_setting('fleetory.signer_revoke.evidence_sha256', true);
BEGIN
    IF fingerprint IS NULL OR fingerprint !~ '^[0-9A-F]{64}$' OR
       evidence IS NULL OR evidence !~ '^[0-9A-F]{64}$' THEN
        RAISE EXCEPTION 'Uppercase certificate and evidence SHA-256 values are required.';
    END IF;
    IF incident IS NULL OR length(btrim(incident)) NOT BETWEEN 1 AND 128 OR incident ~ '[[:cntrl:]]' OR
       operator_id IS NULL OR length(btrim(operator_id)) NOT BETWEEN 1 AND 128 OR operator_id ~ '[[:cntrl:]]' OR
       approver_id IS NULL OR length(btrim(approver_id)) NOT BETWEEN 1 AND 128 OR approver_id ~ '[[:cntrl:]]' OR
       lower(btrim(operator_id)) = lower(btrim(approver_id)) THEN
        RAISE EXCEPTION 'Bounded incident and distinct operator/approver references are required.';
    END IF;
    PERFORM set_config('synchronous_commit', 'on', true);
    INSERT INTO signer.client_certificate_revocations
        (certificate_sha256, incident_reference, operator_reference, approver_reference, evidence_sha256)
    VALUES (fingerprint, btrim(incident), btrim(operator_id), btrim(approver_id), evidence);
END
$fleetory_signer_revoke$;
