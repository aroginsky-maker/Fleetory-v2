BEGIN;
SET LOCAL ROLE fleetory_signer_owner;
INSERT INTO signer.signing_requests(request_id,caller_id,client_certificate_sha256,target_device_id,accepted_at)
 VALUES('00000000-0000-4000-8000-000000000003','fixture',repeat('B',64),gen_random_uuid(),'1970-01-01Z');
INSERT INTO signer.signing_results(request_id,command_id,signing_key_id,envelope_sha256,recorded_at)
 VALUES('00000000-0000-4000-8000-000000000003',gen_random_uuid(),'fixture-v2',repeat('C',64),'1970-01-01Z');
INSERT INTO signer.signing_rejections(event_id,client_certificate_sha256,reason,recorded_at)
 SELECT gen_random_uuid(),repeat('D',64),'Forbidden','1970-01-01Z' FROM generate_series(1,3);
ALTER DEFAULT PRIVILEGES IN SCHEMA signer GRANT SELECT ON TABLES TO fleetory_signer;
RESET ROLE;
GRANT USAGE ON SCHEMA signer TO fleetory_signer;
GRANT SELECT,INSERT ON signer.signing_requests,signer.signing_results,signer.signing_rejections TO fleetory_signer;
GRANT SELECT ON signer.client_certificate_revocations TO fleetory_signer;
COMMIT;
