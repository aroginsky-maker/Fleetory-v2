-- Signer journal schema v3. Run as deployment owner in the separate signer database.
-- The runtime role needs USAGE on signer and SELECT, INSERT on these three tables.
-- Keep UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER, schema CREATE and ownership away from that role.
-- Grant only SELECT on client_certificate_revocations; an independent operator writes revocations.
-- Limit operator INSERT to the five evidence/input columns; database-generated metadata is protected.
BEGIN;
CREATE SCHEMA IF NOT EXISTS signer;
REVOKE ALL ON SCHEMA signer FROM PUBLIC;
CREATE TABLE IF NOT EXISTS signer.signing_requests (
    request_id uuid PRIMARY KEY CHECK (request_id <> '00000000-0000-0000-0000-000000000000'),
    caller_id varchar(96) NOT NULL CHECK (caller_id ~ '^[a-z0-9_-]+$'),
    client_certificate_sha256 char(64) NOT NULL CHECK (client_certificate_sha256 ~ '^[0-9A-F]{64}$'),
    target_device_id uuid NOT NULL CHECK (target_device_id <> '00000000-0000-0000-0000-000000000000'),
    command_type text NOT NULL DEFAULT 'Inventory.Refresh' CHECK (command_type = 'Inventory.Refresh'),
    accepted_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE IF NOT EXISTS signer.signing_results (
    request_id uuid PRIMARY KEY REFERENCES signer.signing_requests(request_id),
    command_id uuid NOT NULL UNIQUE CHECK (command_id <> '00000000-0000-0000-0000-000000000000'),
    signing_key_id varchar(128) NOT NULL CHECK (signing_key_id ~ '^[a-zA-Z0-9-]+$'),
    envelope_sha256 char(64) NOT NULL CHECK (envelope_sha256 ~ '^[0-9A-F]{64}$'),
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
REVOKE ALL ON signer.signing_requests, signer.signing_results FROM PUBLIC;
CREATE TABLE IF NOT EXISTS signer.signing_rejections (
    event_id uuid PRIMARY KEY,
    client_certificate_sha256 char(64) NOT NULL CHECK (client_certificate_sha256 ~ '^[0-9A-F]{64}$'),
    reason text NOT NULL CHECK (reason IN ('InvalidRequest','Forbidden','Duplicate','RateLimited','Unavailable','Cancelled')),
    request_id uuid NULL,
    target_device_id uuid NULL,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
REVOKE ALL ON signer.signing_rejections FROM PUBLIC;
CREATE TABLE IF NOT EXISTS signer.client_certificate_revocations (
    certificate_sha256 char(64) PRIMARY KEY CHECK (certificate_sha256 ~ '^[0-9A-F]{64}$'),
    event_id uuid NOT NULL UNIQUE DEFAULT gen_random_uuid(),
    incident_reference varchar(128) NOT NULL CHECK (length(btrim(incident_reference)) > 0),
    operator_reference varchar(128) NOT NULL CHECK (length(btrim(operator_reference)) > 0),
    approver_reference varchar(128) NOT NULL CHECK (length(btrim(approver_reference)) > 0),
    evidence_sha256 char(64) NOT NULL CHECK (evidence_sha256 ~ '^[0-9A-F]{64}$'),
    database_operator name NOT NULL DEFAULT session_user,
    revoked_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK (lower(btrim(operator_reference)) <> lower(btrim(approver_reference)))
);
REVOKE ALL ON signer.client_certificate_revocations FROM PUBLIC;
COMMIT;
