-- Generated fixture records only. No certificate/key/identity/approval authority.
BEGIN;
SET LOCAL standard_conforming_strings=on;
SET LOCAL timezone='UTC';
SET LOCAL ROLE fleetory_migrator;
INSERT INTO platform.admin_certificate_registrations
 (certificate_sha256,actor_subject_id,registered_at,incident_reference,operator_reference)
 VALUES(repeat('A',64),'person:00000000000040008000000000000001','1970-01-01Z','fixture-v2','fixture-only');
INSERT INTO platform.authorization_roles(role_id,name)
 VALUES('00000000-0000-4000-8000-000000000002','Generated v2 role');
INSERT INTO platform.authorization_role_permissions(role_id,permission)
 VALUES('00000000-0000-4000-8000-000000000002','Fixture.Read');
INSERT INTO platform.authorization_role_versions(role_id,name,permissions,recorded_at)
 VALUES('00000000-0000-4000-8000-000000000002','Generated v2 role',ARRAY['Fixture.Read'],'1970-01-01Z');
INSERT INTO platform.authorization_assignments(assignment_id,actor_subject_id,actor_kind,role_id)
 VALUES(gen_random_uuid(),'person:00000000000040008000000000000001',1,'00000000-0000-4000-8000-000000000002');
INSERT INTO platform.audit_events(event_id,actor_subject_id,actor_kind,action,correlation_id,occurred_at,recorded_at,context_json)
 SELECT gen_random_uuid(),'fixture:v2',1,'Fixture.V2.Read.'||n,'fixture-'||n,'1970-01-01Z','1970-01-02Z',
 CASE WHEN n=1 THEN NULL ELSE jsonb_build_object('fixture','v2','note','generated '' UTF8 Ω') END
 FROM generate_series(1,4) n;
ALTER DEFAULT PRIVILEGES IN SCHEMA core,platform GRANT SELECT ON TABLES TO fleetory_server;
RESET ROLE;
GRANT USAGE ON SCHEMA core,platform TO fleetory_server;
GRANT SELECT ON ALL TABLES IN SCHEMA core,platform TO fleetory_server;
GRANT SELECT(display_name) ON core.devices TO fleetory_server;
GRANT INSERT ON platform.audit_events TO fleetory_server;
COMMIT;
