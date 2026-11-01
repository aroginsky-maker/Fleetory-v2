#!/usr/bin/env python3
"""Private Keycloak snapshot capture/inventory. Never prints database rows or SQL errors."""
import argparse
import ctypes
import csv
import hashlib
import json
import os
from pathlib import Path
import queue
import re
import stat
import subprocess
import sys
import threading
import time
import uuid

ALGORITHM = 'fleetory.keycloak-inventory.v1'
EXCLUSIONS = ['roles', 'ACLs', 'nonMVCCSequences', 'externalHSM', 'postRestoreHumanLogin']
MAX_DUMP = 64 * 1024 * 1024
MAX_ROWS = 1_000_000
IDENTIFIER = re.compile(r'[a-z_][a-z0-9_]{0,62}\Z')


def fail():
    raise RuntimeError('Identity backup verification failed.')


def literal(value):
    return "'" + value.replace("'", "''") + "'"


def identifier(value):
    if not IDENTIFIER.fullmatch(value):
        fail()
    return '"' + value + '"'


def protect_windows_directory(path):
    advapi = ctypes.WinDLL('advapi32', use_last_error=True)
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    descriptor = ctypes.c_void_p()
    convert = advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW
    convert.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
    convert.restype = ctypes.c_int
    apply = advapi.SetFileSecurityW
    apply.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_void_p]
    apply.restype = ctypes.c_int
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    system_directory = ctypes.create_unicode_buffer(32768)
    kernel.GetSystemDirectoryW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32]
    kernel.GetSystemDirectoryW.restype = ctypes.c_uint32
    length = kernel.GetSystemDirectoryW(system_directory, len(system_directory))
    if not 0 < length < len(system_directory):
        fail()
    identity = subprocess.run([str(Path(system_directory.value) / 'whoami.exe'), '/user', '/fo', 'csv', '/nh'],
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=True, timeout=10)
    rows = list(csv.reader(identity.stdout.decode('utf-8', errors='replace').splitlines()))
    if len(rows) != 1 or len(rows[0]) != 2 or not re.fullmatch(r'S-1-5-\d+(?:-\d+)+', rows[0][1]):
        fail()
    sid = rows[0][1]
    sddl = 'O:' + sid + 'D:P(A;OICI;FA;;;' + sid + ')(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'
    if not convert(sddl, 1, ctypes.byref(descriptor), None):
        fail()
    try:
        if not apply(str(path), 0x80000005, descriptor):
            fail()
    finally:
        kernel.LocalFree(descriptor)


def private_directory(value):
    path = Path(value)
    if not path.is_absolute() or path.exists() or path.is_symlink():
        fail()
    for ancestor in [path, *path.parents]:
        if (ancestor / '.git').exists():
            fail()
        if ancestor.exists():
            info = ancestor.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
                fail()
    path.mkdir(mode=0o700)
    if os.name == 'nt':
        protect_windows_directory(path)
    else:
        os.chmod(path, 0o700)
    return path


class Session:
    def __init__(self, args, deadline):
        self.deadline = deadline
        self.process = subprocess.Popen(
            ['docker', 'exec', '-i', '-e', 'PGCONNECT_TIMEOUT=10', '-u', 'postgres', args.container, 'psql', '-XqAt',
             '-v', 'ON_ERROR_STOP=1', '-U', args.db_user, '-d', args.database],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        self.lines = queue.Queue(maxsize=256)
        self.stopping = threading.Event()
        self.reader = threading.Thread(target=self.read, daemon=True)
        self.reader.start()

    def read(self):
        try:
            while not self.stopping.is_set():
                line = self.process.stdout.readline(1_048_577)
                if not line or len(line) > 1_048_576:
                    break
                while not self.stopping.is_set():
                    try:
                        self.lines.put(line, timeout=0.1)
                        break
                    except queue.Full:
                        pass
        finally:
            while not self.stopping.is_set():
                try:
                    self.lines.put(None, timeout=0.1)
                    break
                except queue.Full:
                    pass

    def query(self, sql):
        marker = 'end_' + uuid.uuid4().hex
        self.process.stdin.write((sql + '\nSELECT ' + literal(marker) + ';\n').encode('utf-8'))
        self.process.stdin.flush()
        query_end = min(self.deadline, time.monotonic() + 30)
        while True:
            remaining = query_end - time.monotonic()
            if remaining <= 0:
                fail()
            try:
                line = self.lines.get(timeout=remaining)
            except queue.Empty:
                fail()
            if line is None:
                fail()
            value = line.decode('utf-8', errors='strict').rstrip('\r\n')
            if value == marker:
                return
            yield value

    def one(self, sql):
        result = list(self.query(sql))
        if len(result) != 1:
            fail()
        return result[0]

    def command(self, sql):
        if list(self.query(sql)):
            fail()

    def close(self):
        self.stopping.set()
        # Docker exec is noninteractive; closing stdin ends the owned remote psql session.
        if self.process.stdin:
            self.process.stdin.close()
        try:
            self.process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=3)
        if self.process.stdout:
            self.process.stdout.close()
        self.reader.join(timeout=1)


def inventory(session, args):
    if session.one("SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
                   "WHERE n.nspname='public' AND c.relkind IN ('p','f','m');") != '0':
        fail()
    if session.one("SELECT count(*) FROM pg_namespace WHERE nspname NOT IN ('public','information_schema') "
                   "AND nspname NOT LIKE 'pg\\_%' ESCAPE '\\';") != '0':
        fail()
    tables = list(session.query("SELECT c.relname AS tablename FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' "
                                "AND c.relkind='r' "
                                'ORDER BY c.relname COLLATE "C";'))
    if not 1 <= len(tables) <= 512 or len(set(tables)) != len(tables):
        fail()
    required = {'realm', 'user_entity', 'credential', 'component', 'component_config', 'client',
                'user_required_action', 'client_attributes', 'redirect_uris', 'web_origins', 'protocol_mapper', 'protocol_mapper_config'}
    if not required.issubset(tables):
        fail()
    digest = hashlib.sha256((ALGORITHM + '\n').encode('ascii'))
    total = 0
    for table in tables:
        quoted = identifier(table)
        relation = literal('public.' + quoted) + '::regclass'
        schema = session.one("SELECT jsonb_build_object('table'," + literal(table) + ", 'columns',"
            "(SELECT jsonb_agg(jsonb_build_array(a.attname,format_type(a.atttypid,a.atttypmod),"
            "a.attnotnull,pg_get_expr(d.adbin,d.adrelid),a.attidentity,a.attgenerated,"
            "CASE WHEN a.attcollation=0 THEN NULL ELSE a.attcollation::regcollation::text END) ORDER BY a.attnum) "
            "FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum "
            "WHERE a.attrelid=" + relation + " AND a.attnum>0 AND NOT a.attisdropped), 'constraints',"
            "(SELECT jsonb_agg(jsonb_build_array(conname,pg_get_constraintdef(oid,true)) ORDER BY conname COLLATE \"C\") "
            "FROM pg_constraint WHERE conrelid=" + relation + "), 'indexes',"
            "(SELECT jsonb_agg(jsonb_build_array(indexrelid::regclass::text,pg_get_indexdef(indexrelid)) "
            "ORDER BY indexrelid::regclass::text COLLATE \"C\") FROM pg_index WHERE indrelid=" + relation + "))::text;")
        encoded = schema.encode('utf-8')
        digest.update(len(encoded).to_bytes(8, 'big'))
        digest.update(encoded)
        count = 0
        for row_hash in session.query("SELECT h FROM (SELECT encode(sha256(convert_to(to_jsonb(t)::text,'UTF8')),'hex') h "
                                      'FROM public.' + quoted + ' t) hashes ORDER BY h COLLATE "C";'):
            if not re.fullmatch('[0-9a-f]{64}', row_hash):
                fail()
            count += 1
            total += 1
            if total > MAX_ROWS:
                fail()
            digest.update(bytes.fromhex(row_hash))
        digest.update(count.to_bytes(8, 'big'))
    # Inventory consistency guard within the held snapshot; not an outside-DDL detector.
    final_tables = list(session.query("SELECT c.relname AS tablename FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' "
                                      "AND c.relkind='r' "
                                      'ORDER BY c.relname COLLATE "C";'))
    if tables != final_tables:
        fail()
    r = literal(args.realm)
    u = literal(args.owner)
    realm = '(SELECT id FROM public.realm WHERE name=' + r + ')'
    owner = 'id=' + u + ' AND realm_id=' + realm
    client = "(SELECT id FROM public.client WHERE realm_id=" + realm + " AND client_id='fleetory-pilot')"
    invariants = json.loads(session.one("SELECT jsonb_build_object("
        "'ownerEnabled',(SELECT count(*)=1 AND bool_and(enabled) FROM public.user_entity WHERE " + owner + "),"
        "'ownerRequiredActionsClear',NOT EXISTS(SELECT 1 FROM public.user_required_action WHERE user_id=" + u + "),"
        "'passwordCredentialPresent',EXISTS(SELECT 1 FROM public.credential WHERE user_id=" + u + " AND type='password'),"
        "'webauthnCredentialPresent',EXISTS(SELECT 1 FROM public.credential WHERE user_id=" + u + " AND type IN ('webauthn','webauthn-passwordless')),"
        "'realmSigningPrivateKeyPresent',EXISTS(SELECT 1 FROM public.component c JOIN public.component_config cfg ON cfg.component_id=c.id "
        "WHERE c.realm_id=" + realm + " AND c.provider_type='org.keycloak.keys.KeyProvider' AND c.provider_id='rsa-generated' "
        "AND cfg.name='privateKey' AND length(cfg.value)>0),"
        "'clientConfigurationValid',(SELECT count(*)=1 AND bool_and(enabled AND public_client AND standard_flow_enabled "
        "AND NOT direct_access_grants_enabled AND NOT implicit_flow_enabled AND NOT service_accounts_enabled) FROM public.client WHERE id=" + client + ") "
        "AND NOT EXISTS(SELECT 1 FROM public.web_origins WHERE client_id=" + client + ") "
        "AND EXISTS(SELECT 1 FROM public.client_attributes WHERE client_id=" + client + " AND name='pkce.code.challenge.method' AND value='S256') "
        "AND (SELECT count(*)=1 AND bool_and(value='http://127.0.0.1:48329/auth/callback') FROM public.redirect_uris WHERE client_id=" + client + "),"
        "'tokenMappersPresent',EXISTS(SELECT 1 FROM public.protocol_mapper pm JOIN public.protocol_mapper_config cfg ON cfg.protocol_mapper_id=pm.id "
        "WHERE pm.client_id=" + client + " AND pm.protocol_mapper_name='oidc-audience-mapper' AND cfg.name='included.custom.audience' AND cfg.value='fleetory-admin-api' AND EXISTS(SELECT 1 FROM public.protocol_mapper_config ac WHERE ac.protocol_mapper_id=pm.id AND ac.name='access.token.claim' AND ac.value='true')) "
        "AND EXISTS(SELECT 1 FROM public.protocol_mapper WHERE client_id=" + client + " AND protocol_mapper_name='oidc-amr-mapper' AND EXISTS(SELECT 1 FROM public.protocol_mapper_config ac WHERE ac.protocol_mapper_id=protocol_mapper.id AND ac.name='access.token.claim' AND ac.value='true')))::text;"))
    if len(invariants) != 7 or any(value is not True for value in invariants.values()):
        fail()
    return dict(schema=ALGORITHM, inventoryAlgorithm=ALGORITHM, realm=args.realm, owner=args.owner,
                postgresMajor=18, inventorySha256=digest.hexdigest(), tableCount=len(tables), totalRows=total,
                invariants=invariants, exclusions=EXCLUSIONS)


def save_dump(output, dump, dump_digest, deadline, dump_error):
    try:
        fd = os.open(output / 'database.dump', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            size = 0
            while True:
                chunk = dump.stdout.read(65536)
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_DUMP or time.monotonic() > deadline:
                    fail()
                stream.write(chunk)
                dump_digest.update(chunk)
            if size == 0:
                fail()
    except Exception:
        dump_error.append(True)
        dump.kill()


def run(args):
    deadline = time.monotonic() + 300
    output = private_directory(args.output_directory) if args.command == 'capture' else None
    session = Session(args, deadline)
    dump = None
    dump_thread = None
    dump_error = []
    try:
        version = int(session.one('SHOW server_version_num;'))
        if not 180000 <= version < 190000:
            fail()
        session.command("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY; SET LOCAL statement_timeout='30s'; "
                        "SET LOCAL timezone='UTC'; SET LOCAL datestyle='ISO,YMD'; SET LOCAL extra_float_digits=3; "
                        "SET LOCAL bytea_output='hex'; SET LOCAL search_path=pg_catalog,public;")
        snapshot = session.one('SELECT pg_export_snapshot();')
        if not re.fullmatch('[0-9A-Fa-f-]{1,128}', snapshot):
            fail()
        dump_digest = hashlib.sha256()
        if output:
            dump = subprocess.Popen(['docker', 'exec', '-e', 'PGCONNECT_TIMEOUT=10', '-e', 'PGOPTIONS=-c statement_timeout=30000',
                '-u', 'postgres', args.container, 'timeout', '300', 'pg_dump', '-Fc', '--lock-wait-timeout=30s',
                '--snapshot=' + snapshot, '--no-owner', '--no-privileges', '-U', args.db_user, '-d', args.database],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            dump_thread = threading.Thread(target=save_dump, args=(output, dump, dump_digest, deadline, dump_error), daemon=True)
            dump_thread.start()
        result = inventory(session, args)
        if dump:
            dump_thread.join(timeout=max(0, deadline-time.monotonic()))
            if dump_thread.is_alive() or dump_error or dump.wait(timeout=max(0.01, deadline-time.monotonic())) != 0:
                fail()
        session.command('COMMIT;')
        if output:
            result['schema'] = 'fleetory.keycloak-backup.v1'
            result['dumpSha256'] = dump_digest.hexdigest()
            manifest = (json.dumps(result, sort_keys=True, separators=(',', ':'), ensure_ascii=True) + '\n').encode('ascii')
            fd = os.open(output / 'manifest.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(manifest)
            result = {key: result[key] for key in ('dumpSha256','inventorySha256','tableCount','totalRows','invariants')}
            result['manifestSha256'] = hashlib.sha256(manifest).hexdigest()
        print(json.dumps(result, sort_keys=True, separators=(',', ':')))
    finally:
        if dump:
            if dump.poll() is None:
                dump.kill()
            dump.wait(timeout=3)
            if dump.stdout:
                dump.stdout.close()
        if dump_thread:
            dump_thread.join(timeout=3)
        session.close()


def main():
    if sys.version_info < (3, 11):
        fail()
    parser = argparse.ArgumentParser(description='Private Keycloak snapshot capture and restore inventory.')
    commands = parser.add_subparsers(dest='command', required=True)
    for name in ('capture', 'inventory'):
        sub = commands.add_parser(name)
        sub.add_argument('--container', required=True)
        sub.add_argument('--database', required=True)
        sub.add_argument('--realm', required=True)
        sub.add_argument('--owner', required=True)
        sub.add_argument('--db-user', default='postgres')
        if name == 'capture':
            sub.add_argument('--output-directory', required=True)
    args = parser.parse_args()
    if not re.fullmatch('[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}', args.container):
        fail()
    identifier(args.database)
    identifier(args.db_user)
    if not re.fullmatch('[a-zA-Z0-9_-]{1,64}', args.realm) or str(uuid.UUID(args.owner)) != args.owner or uuid.UUID(args.owner).int == 0:
        fail()
    run(args)


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('Identity backup verification failed; partial private output may remain.', file=sys.stderr)
        sys.exit(1)
