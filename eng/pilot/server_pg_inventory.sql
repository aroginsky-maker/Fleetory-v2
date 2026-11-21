\set ON_ERROR_STOP on
BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL timezone='UTC';
SET LOCAL search_path=pg_catalog;
SET LOCAL statement_timeout='5s';
SET LOCAL lock_timeout='2s';
SELECT jsonb_build_object('kind','profile','database',current_database(),
 'tables',(SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname IN ('core','platform') AND c.relkind='r'),
 'unsupported',(SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
   WHERE n.nspname IN ('core','platform','public') AND (n.nspname='public' OR c.relkind NOT IN ('r','i') OR c.relrowsecurity OR c.relforcerowsecurity)),
 'extraSchemas',(SELECT count(*) FROM pg_namespace WHERE nspname NOT IN ('core','platform','public','information_schema') AND nspname NOT LIKE 'pg\_%' ESCAPE '\'),
 'extraExtensions',(SELECT count(*) FROM pg_extension WHERE extname<>'plpgsql'))::text;
WITH app_rel AS (
 SELECT c.*,n.nspname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname IN ('core','platform') AND c.relkind='r'
), objects AS (
 SELECT 'database' AS kind, d.datname::text AS name,COALESCE(d.datacl,acldefault('d',d.datdba)) AS acl FROM pg_database d WHERE d.datname=current_database()
 UNION ALL SELECT 'schema',nspname,COALESCE(nspacl,acldefault('n',nspowner)) FROM pg_namespace WHERE nspname IN ('core','platform','public')
 UNION ALL SELECT 'table',nspname||'.'||relname,COALESCE(relacl,acldefault('r',relowner)) FROM app_rel
 UNION ALL SELECT 'column',c.nspname||'.'||c.relname||'.'||a.attname,a.attacl FROM app_rel c JOIN pg_attribute a ON a.attrelid=c.oid WHERE a.attnum>0 AND NOT a.attisdropped AND a.attacl IS NOT NULL
 UNION ALL SELECT 'function',n.nspname||'.'||p.proname||'('||pg_get_function_identity_arguments(p.oid)||')',COALESCE(p.proacl,acldefault('f',p.proowner)) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname IN ('core','platform')
 UNION ALL SELECT 'default',pg_get_userbyid(d.defaclrole)||':'||COALESCE(n.nspname,'*')||':'||d.defaclobjtype::text,d.defaclacl FROM pg_default_acl d LEFT JOIN pg_namespace n ON n.oid=d.defaclnamespace WHERE n.nspname IN ('core','platform') OR d.defaclnamespace=0
), rights AS (
 SELECT o.kind,o.name,pg_get_userbyid(a.grantor) AS grantor,CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee)::text END AS grantee,a.privilege_type,a.is_grantable
 FROM objects o CROSS JOIN LATERAL aclexplode(o.acl) a
)
SELECT jsonb_build_object('kind','catalog',
 'database',(SELECT jsonb_build_array(datname,pg_get_userbyid(datdba),pg_encoding_to_char(encoding),datcollate,datctype) FROM pg_database WHERE datname=current_database()),
 'schemas',(SELECT jsonb_agg(jsonb_build_array(nspname,pg_get_userbyid(nspowner)) ORDER BY nspname COLLATE "C") FROM pg_namespace WHERE nspname IN ('core','platform','public')),
 'relations',(SELECT jsonb_agg(jsonb_build_array(nspname,relname,pg_get_userbyid(relowner),relpersistence,relreplident,relrowsecurity,relforcerowsecurity) ORDER BY nspname COLLATE "C",relname COLLATE "C") FROM app_rel),
 'columns',(SELECT jsonb_agg(jsonb_build_array(c.nspname,c.relname,a.attname,format_type(a.atttypid,a.atttypmod),a.attnotnull,pg_get_expr(d.adbin,d.adrelid),a.attidentity,a.attgenerated,CASE WHEN a.attcollation=0 THEN NULL ELSE a.attcollation::regcollation::text END) ORDER BY c.nspname COLLATE "C",c.relname COLLATE "C",a.attnum) FROM app_rel c JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON d.adrelid=c.oid AND d.adnum=a.attnum WHERE a.attnum>0 AND NOT a.attisdropped),
 'constraints',(SELECT jsonb_agg(jsonb_build_array(c.nspname,c.relname,k.conname,pg_get_constraintdef(k.oid,true)) ORDER BY c.nspname COLLATE "C",c.relname COLLATE "C",k.conname COLLATE "C") FROM app_rel c JOIN pg_constraint k ON k.conrelid=c.oid),
 'indexes',(SELECT jsonb_agg(jsonb_build_array(c.nspname,c.relname,pg_get_indexdef(i.indexrelid)) ORDER BY c.nspname COLLATE "C",c.relname COLLATE "C",pg_get_indexdef(i.indexrelid) COLLATE "C") FROM app_rel c JOIN pg_index i ON i.indrelid=c.oid),
 'functions',(SELECT jsonb_agg(jsonb_build_array(n.nspname,p.proname,pg_get_userbyid(p.proowner),p.prosecdef,p.proconfig,pg_get_functiondef(p.oid)) ORDER BY n.nspname COLLATE "C",p.proname COLLATE "C",p.oid::regprocedure::text COLLATE "C") FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname IN ('core','platform')),
 'triggers',(SELECT jsonb_agg(jsonb_build_array(c.nspname,c.relname,t.tgname,t.tgenabled,pg_get_triggerdef(t.oid)) ORDER BY c.nspname COLLATE "C",c.relname COLLATE "C",t.tgname COLLATE "C") FROM app_rel c JOIN pg_trigger t ON t.tgrelid=c.oid WHERE NOT t.tgisinternal),
 'rules',(SELECT jsonb_agg(jsonb_build_array(c.nspname,c.relname,r.rulename,pg_get_ruledef(r.oid)) ORDER BY c.nspname COLLATE "C",c.relname COLLATE "C",r.rulename COLLATE "C") FROM app_rel c JOIN pg_rewrite r ON r.ev_class=c.oid),
 'rights',(SELECT jsonb_agg(jsonb_build_array(kind,name,grantor,grantee,privilege_type,is_grantable) ORDER BY kind COLLATE "C",name COLLATE "C",grantor COLLATE "C",grantee COLLATE "C",privilege_type COLLATE "C",is_grantable) FROM rights),
 'roles',(SELECT jsonb_agg(jsonb_build_array(rolname,rolsuper,rolinherit,rolcreaterole,rolcreatedb,rolcanlogin,rolreplication,rolbypassrls,rolconnlimit,rolconfig) ORDER BY rolname COLLATE "C") FROM pg_roles WHERE rolname IN ('fleetory_migrator','fleetory_server')),
 'memberships',(SELECT jsonb_agg(jsonb_build_array(pg_get_userbyid(roleid),pg_get_userbyid(member),pg_get_userbyid(grantor),admin_option,inherit_option,set_option) ORDER BY roleid::regrole::text COLLATE "C",member::regrole::text COLLATE "C") FROM pg_auth_members WHERE roleid IN ('fleetory_migrator'::regrole,'fleetory_server'::regrole) OR member IN ('fleetory_migrator'::regrole,'fleetory_server'::regrole)))::text;
SELECT format('SELECT jsonb_build_object(''kind'',''table'',''name'',%L,''rows'',count(*),''sha256'',encode(sha256(convert_to(COALESCE(string_agg(h,E''\n'' ORDER BY h COLLATE "C"),''''),''UTF8'')),''hex''))::text FROM (SELECT encode(sha256(convert_to(to_jsonb(t)::text,''UTF8'')),''hex'') h FROM %I.%I t) rows;',n.nspname||'.'||c.relname,n.nspname,c.relname)
FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname IN ('core','platform') AND c.relkind='r' ORDER BY n.nspname COLLATE "C",c.relname COLLATE "C"
\gexec
COMMIT;
