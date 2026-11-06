"""Read-only, fixed-profile PostgreSQL v2 transcript encoder. No file/restore/connection API."""
import argparse
import hashlib
import json
import re
import sys

import audit_archive as audit
import fresh_server_pair as packet
from identity_backup import literal
from retained_pair_review import APPLICATION_COUNTS, SIGNER_COUNTS

ALGORITHM = 'fleetory.application-signer-recovery.v2'
SCHEMA = 'fleetory.pg-v2-transcript.v1'
MAX_PACKET = 8 * 1024 * 1024
ROLES = ('fleetory_migrator', 'fleetory_server', 'fleetory_signer_owner', 'fleetory_signer')
DATABASES = {'fleetory': ('core', 'platform'), 'fleetory_signer': ('signer',)}


def require(condition):
    audit.require(condition)


def quote(value):
    require(type(value) is str and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,62}', value))
    return '"' + value + '"'


def acl(expression, kind, owner):
    return "(SELECT coalesce(jsonb_agg(jsonb_build_array(pg_get_userbyid(x.grantor),CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END,x.privilege_type,x.is_grantable) ORDER BY x.grantor::regrole::text COLLATE \"C\",x.grantee::regrole::text COLLATE \"C\",x.privilege_type COLLATE \"C\",x.is_grantable),'[]'::jsonb) FROM aclexplode(coalesce(" + expression + ",acldefault('" + kind + "'," + owner + "))) x)"


def tables(database):
    require(database in DATABASES)
    return sorted(APPLICATION_COUNTS if database == 'fleetory' else SIGNER_COUNTS)


def queries(database):
    """The legacy v2 query results are hashed as text, without JSON normalization."""
    require(database in DATABASES)
    roles = ','.join(literal(role) for role in ROLES)
    result = [
        ('database', "SELECT jsonb_build_object('database',datname,'owner',pg_get_userbyid(datdba),'encoding',pg_encoding_to_char(encoding),'collation',datcollate,'ctype',datctype,'acl'," + acl('datacl','d','datdba') + ")::text FROM pg_database WHERE datname=current_database();"),
        ('roles', "SELECT jsonb_agg(jsonb_build_array(rolname,rolsuper,rolinherit,rolcreaterole,rolcreatedb,rolreplication,rolbypassrls) ORDER BY rolname COLLATE \"C\")::text FROM pg_roles WHERE rolname IN (" + roles + ');'),
        ('memberships', "SELECT coalesce(jsonb_agg(jsonb_build_array(pg_get_userbyid(roleid),pg_get_userbyid(member),admin_option,inherit_option,set_option) ORDER BY roleid::regrole::text COLLATE \"C\",member::regrole::text COLLATE \"C\"),'[]'::jsonb)::text FROM pg_auth_members WHERE member IN (SELECT oid FROM pg_roles WHERE rolname IN (" + roles + '));'),
        ('defaults', "SELECT coalesce(jsonb_agg(jsonb_build_array(pg_get_userbyid(d.defaclrole),CASE WHEN d.defaclnamespace=0 THEN NULL ELSE d.defaclnamespace::regnamespace::text END,d.defaclobjtype," + acl('d.defaclacl','r','d.defaclrole') + ") ORDER BY d.defaclrole::regrole::text COLLATE \"C\",d.defaclnamespace::regnamespace::text COLLATE \"C\",d.defaclobjtype),'[]'::jsonb)::text FROM pg_default_acl d;"),
    ]
    for schema in ('public', *DATABASES[database]):
        result.append(('schema:' + schema, "SELECT jsonb_build_array(nspname,pg_get_userbyid(nspowner)," + acl('nspacl','n','nspowner') + ')::text FROM pg_namespace WHERE nspname=' + literal(schema) + ';'))
    for name in tables(database):
        schema, table = name.split('.')
        qualified = quote(schema) + '.' + quote(table)
        relation = literal(qualified) + '::regclass'
        definition = "SELECT jsonb_build_object('name'," + literal(qualified) + ",'owner',pg_get_userbyid(c.relowner),'acl'," + acl('c.relacl','r','c.relowner') + ",'rls',c.relrowsecurity,'forceRls',c.relforcerowsecurity,'columns',"
        definition += "(SELECT jsonb_agg(jsonb_build_array(a.attname,format_type(a.atttypid,a.atttypmod),a.attnotnull,pg_get_expr(d.adbin,d.adrelid),a.attidentity,a.attgenerated,CASE WHEN a.attcollation=0 THEN NULL ELSE a.attcollation::regcollation::text END," + acl('a.attacl','c','c.relowner') + ") ORDER BY a.attnum) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped),"
        definition += "'constraints',(SELECT jsonb_agg(jsonb_build_array(conname,pg_get_constraintdef(oid,true)) ORDER BY conname COLLATE \"C\") FROM pg_constraint WHERE conrelid=c.oid),"
        definition += "'indexes',(SELECT jsonb_agg(jsonb_build_array(indexrelid::regclass::text,pg_get_indexdef(indexrelid)) ORDER BY indexrelid::regclass::text COLLATE \"C\") FROM pg_index WHERE indrelid=c.oid))::text FROM pg_class c WHERE c.oid=" + relation + ';'
        result.extend([('table:' + name, definition),
                       ('rows:' + name, "SELECT h FROM (SELECT encode(sha256(convert_to(to_jsonb(t)::text,'UTF8')),'hex') h FROM " + qualified + ' t) x ORDER BY h COLLATE "C";')])
    if database == 'fleetory':
        select = 'SELECT json_build_object(' + audit.SQL.split('SELECT json_build_object(', 1)[1].split('COMMIT;', 1)[0]
        result.append(('audit', 'SELECT (' + select.strip().removesuffix(';') + ')::jsonb::text;'))
    return result


def profile_sql(database):
    allowed = ','.join(literal(value) for value in ('public', *DATABASES[database]))
    return "SELECT jsonb_build_object('schema'," + literal(SCHEMA) + ",'database',current_database(),'version',current_setting('server_version_num')::int,'readOnly',current_setting('transaction_read_only'),'tables'," + table_list_sql(allowed) + ", 'unsupported',jsonb_build_array("


def table_list_sql(allowed):
    return "(SELECT coalesce(jsonb_agg(n.nspname||'.'||c.relname ORDER BY n.nspname COLLATE \"C\",c.relname COLLATE \"C\"),'[]'::jsonb) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname IN (" + allowed + ") AND c.relkind='r')"


def build_sql(database):
    require(database in DATABASES)
    allowed = ','.join(literal(value) for value in ('public', *DATABASES[database]))
    counts = [
        "SELECT count(*) FROM pg_namespace WHERE nspname NOT IN (" + allowed + ",'information_schema') AND nspname NOT LIKE 'pg\\_%' ESCAPE '\\'",
        'SELECT count(*) FROM pg_largeobject_metadata',
        "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname IN (" + allowed + ") AND c.relkind NOT IN ('r','i')",
        "SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname IN (" + allowed + ')',
        "SELECT count(*) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname IN (" + allowed + ') AND NOT t.tgisinternal',
        "SELECT count(*) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname IN (" + allowed + ')',
        "SELECT count(*) FROM pg_extension WHERE extname<>'plpgsql'",
    ]
    begin = "\\set ON_ERROR_STOP on\nBEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;SET LOCAL statement_timeout='5s';SET LOCAL lock_timeout='2s';SET LOCAL timezone='UTC';SET LOCAL datestyle='ISO,YMD';SET LOCAL extra_float_digits=3;SET LOCAL bytea_output='hex';SET LOCAL search_path=pg_catalog;\n"
    sql = begin + profile_sql(database) + ','.join('(' + query + ')' for query in counts) + '))::text;\n'
    safe = ['(' + query + ')=0' for query in counts]
    safe.extend([table_list_sql(allowed) + '=' + literal(json.dumps(tables(database))) + '::jsonb',
                 'current_database()=' + literal(database), "current_setting('transaction_read_only')='on'",
                 "current_setting('server_version_num')::int BETWEEN 180000 AND 189999"])
    # Refuse unsupported objects inside the read-only native session before any
    # table value/output function is evaluated. The decoder alone is too late.
    sql += 'SELECT (' + ' AND '.join(safe) + ') AS fleetory_v2_safe\n\\gset\n\\if :fleetory_v2_safe\n\\else\nSELECT 1/0;\n\\endif\n'
    for label, query in queries(database):
        # Store scalar raw text in a one-element array; row queries may return no
        # records. Both remain unnormalized strings in the transcript.
        sql += "SELECT jsonb_build_object('label'," + literal(label) + ",'values',coalesce(jsonb_agg(v),'[]'::jsonb))::text FROM (" + query.removesuffix(';') + ') AS q(v);\n'
    roles = ','.join(literal(role) for role in ROLES)
    sql += "SELECT jsonb_build_object('label','additional','roles',(SELECT jsonb_agg(jsonb_build_array(rolname,rolsuper,rolinherit,rolcreaterole,rolcreatedb,rolreplication,rolbypassrls,rolcanlogin,rolconnlimit,rolconfig) ORDER BY rolname COLLATE \"C\") FROM pg_roles WHERE rolname IN (" + roles + ")),'memberships',(SELECT coalesce(jsonb_agg(jsonb_build_array(pg_get_userbyid(roleid),pg_get_userbyid(member),pg_get_userbyid(grantor),admin_option,inherit_option,set_option) ORDER BY roleid::regrole::text COLLATE \"C\",member::regrole::text COLLATE \"C\",grantor::regrole::text COLLATE \"C\"),'[]'::jsonb) FROM pg_auth_members WHERE roleid IN (SELECT oid FROM pg_roles WHERE rolname IN (" + roles + ")) OR member IN (SELECT oid FROM pg_roles WHERE rolname IN (" + roles + "))),'settings',(SELECT coalesce(jsonb_agg(jsonb_build_array(CASE WHEN setdatabase=0 THEN '*' ELSE (SELECT datname FROM pg_database WHERE oid=setdatabase) END,CASE WHEN setrole=0 THEN '*' ELSE pg_get_userbyid(setrole) END,setconfig) ORDER BY setdatabase,setrole),'[]'::jsonb) FROM pg_db_role_setting WHERE setrole=0 OR setrole IN (SELECT oid FROM pg_roles WHERE rolname IN (" + roles + '))))::text;\n'
    return sql + "SELECT jsonb_build_object('label','end','tables'," + table_list_sql(allowed) + ")::text;\nCOMMIT;\n"


class LegacyV2Digest:
    def __init__(self, database):
        self.digest = hashlib.sha256((ALGORITHM + '\n' + database + '\n').encode())
        self.security = hashlib.sha256()
        self.total, self.counts, self.audit_snapshot = 0, {}, None

    def add(self, text, secure=True):
        require(type(text) is str)
        value = text.encode('utf-8')
        framed = len(value).to_bytes(8, 'big') + value
        self.digest.update(framed)
        if secure:
            self.security.update(framed)

    def consume(self, label, values):
        require(type(values) is list and all(type(value) is str for value in values))
        if label.startswith('rows:'):
            require(values == sorted(values) and all(re.fullmatch('[0-9a-f]{64}', value) for value in values))
            for value in values:
                self.digest.update(bytes.fromhex(value))
            self.add(str(len(values)), False)
            self.counts[label[5:]] = len(values)
            self.total += len(values)
            require(self.total <= 1000000)
        else:
            require(len(values) == 1)
            if label == 'audit':
                snapshot = audit.parse(values[0].encode(), audit.MAX_SNAPSHOT)
                audit.event_map(snapshot)
                require(snapshot['pendingExportCount'] == 0)
                self.audit_snapshot = dict(snapshotSha256=audit.digest(snapshot), events=len(snapshot['events']), pendingExportCount=0)
            else:
                packet.strict_json(values[0].encode('utf-8'), MAX_PACKET)
                if label == 'roles':
                    require(len(json.loads(values[0])) == 4)
                self.add(values[0])


def readback(data, database):
    require(type(data) is bytes and 0 < len(data) <= MAX_PACKET)
    require(database in DATABASES)
    records = [packet.strict_json(line, MAX_PACKET) for line in data.splitlines()]
    expected_queries = queries(database)
    require(len(records) == len(expected_queries) + 3)
    profile = records[0]
    packet.keys(profile, 'schema database version readOnly tables unsupported')
    require(profile['schema'] == SCHEMA and profile['database'] == database and profile['readOnly'] == 'on')
    require(type(profile['version']) is int and 180000 <= profile['version'] < 190000)
    require(profile['tables'] == tables(database) and audit.canonical(profile['unsupported']) == b'[0,0,0,0,0,0,0]')
    legacy = LegacyV2Digest(database)
    for record, (label, _) in zip(records[1:-2], expected_queries, strict=True):
        packet.keys(record, 'label values')
        require(record['label'] == label)
        legacy.consume(label, record['values'])
    extra, end = records[-2:]
    packet.keys(extra, 'label roles memberships settings')
    packet.keys(end, 'label tables')
    require(extra['label'] == 'additional' and end['label'] == 'end' and end['tables'] == profile['tables'])
    expected_roles = [[role, False, True, False, False, False, False, role in ('fleetory_server', 'fleetory_signer'), -1, None] for role in sorted(ROLES)]
    accepted = audit.canonical(extra['roles']) == audit.canonical(expected_roles) and extra['memberships'] == [] and extra['settings'] == []
    return dict(schema='fleetory.native-pg-v2-readback.v1', inventory=dict(algorithm=ALGORITHM, database=database,
        inventorySha256=legacy.digest.hexdigest(), securitySha256=legacy.security.hexdigest(), tableCount=len(legacy.counts), totalRows=legacy.total,
        sequenceCount=0, tableCounts=legacy.counts, audit=legacy.audit_snapshot, rolePasswordsAndLoginRecoveryVerified=False,
        globalAtomicSnapshotClaimed=False), additionalSecuritySha256=hashlib.sha256(
            b'fleetory.pg-v2-role-state.v1\n' + audit.canonical(extra)).hexdigest(),
        generatedRolePolicyAccepted=accepted, nativeMeasurementAuthenticated=False,
        originalInputsVerified=False, executionAuthorized=False, fullSystemRecoveryVerified=False)


def run():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('sql', 'readback'))
    parser.add_argument('--database', choices=tuple(DATABASES), required=True)
    arguments = parser.parse_args()
    if arguments.mode == 'sql':
        return build_sql(arguments.database)
    return json.dumps(readback(sys.stdin.buffer.read(MAX_PACKET + 1), arguments.database), sort_keys=True)


if __name__ == '__main__':
    try:
        result = run()
    except Exception:
        print('PostgreSQL v2 transcript refused; no contents logged.', file=sys.stderr)
        sys.exit(1)
    print(result)
