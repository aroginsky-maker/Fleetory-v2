-- Signer request journal schema v1. Run as deployment owner in the separate signer database.
-- The runtime role needs USAGE on signer and SELECT, INSERT on these two tables.
-- Keep UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER, schema CREATE and ownership away from that role.
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
COMMIT;
