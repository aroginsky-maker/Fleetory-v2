"""Leaf-only TLS recovery contract. Original-key use needs a separately approved operation."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import socket
import ssl
import subprocess
import sys
import threading

import audit_archive as archive
import recovery_files as files

ROLES = {
    'postgres': ('infrastructure', 'postgres', 'postgres/ca.crt', 'postgres/server.crt', 'postgres/server.key'),
    'openbao': ('infrastructure', 'openbao', 'openbao/ca.crt', 'openbao/server.crt', 'openbao/server.key'),
    'audit-store': ('infrastructure', 'audit-store', 'immudb/infrastructure-ca', 'immudb/server.crt', 'immudb/server.key'),
    'audit-gateway': ('infrastructure', 'immudb', 'audit-gateway/infrastructure-ca', 'audit-gateway/server.crt', 'audit-gateway/server.key'),
    'agent-gateway': ('agent', 'localhost', 'server/agent-gateway-root-ca', 'server/agent-gateway-server-cert', 'server/agent-gateway-server-key'),
    'admin-gateway': ('admin', 'localhost', 'server/admin-gateway-root-ca', 'server/admin-gateway-server-cert', 'server/admin-gateway-server-key'),
    'signer': ('infrastructure', 'command-signer', 'signer/signer-server-ca', 'signer/signer-server-cert', 'signer/signer-server-key'),
}
ROOTS = {'infrastructure', 'agent', 'admin'}
MAX_FILE = 16 * 1024
PYTHON = 'python:3.12-slim@sha256:aa943ce411423c7582288f18707ff66eddcbaeb510502d747a72aeb34f30d159'
LABEL = 'fleetory.recovery.leaf.session'


def plan(roots):
    result = {'schema': 'fleetory.leaf-tls-plan.v1', 'roots': roots,
              'roles': {name: {'root': entry[0], 'serverName': entry[1],
                              'files': dict(zip(('ca', 'cert', 'key'), entry[2:]))}
                        for name, entry in ROLES.items()}}
    validate_plan(result)
    return result


def validate_plan(record):
    archive.fields(record, ('schema', 'roots', 'roles'))
    archive.require(record['schema'] == 'fleetory.leaf-tls-plan.v1')
    archive.fields(record['roots'], ROOTS)
    archive.require(all(type(value) is str and re.fullmatch(r'[0-9A-F]{64}', value)
                        for value in record['roots'].values()))
    archive.require(len(set(record['roots'].values())) == 3)
    archive.fields(record['roles'], ROLES)
    for name, entry in ROLES.items():
        expected = {'root': entry[0], 'serverName': entry[1], 'files': dict(zip(('ca', 'cert', 'key'), entry[2:]))}
        archive.require(record['roles'][name] == expected)


def root_digest(packet):
    text = packet.decode('ascii')
    archive.require(len(packet) <= MAX_FILE and re.fullmatch(
        r'\s*-----BEGIN CERTIFICATE-----\r?\n[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----\s*', text))
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(text)).hexdigest().upper()


def stage(source, destination, record):
    """Call only for generated fixture files or an explicitly authorized 21-file scope."""
    validate_plan(record)
    destination = Path(destination).absolute()
    archive.require(not destination.exists())
    for parent in (destination.parent, *destination.parent.parents):
        files.ordinary_directory(parent)
        archive.require(not (parent / '.git').exists())
    destination.mkdir(mode=0o700)
    if os.name == 'nt':
        from identity_backup import protect_windows_directory
        protect_windows_directory(destination)
    with files.rooted(source) as (root, descriptor):
        for name, entry in record['roles'].items():
            output = destination / name
            output.mkdir(mode=0o700)
            for kind in ('ca', 'cert', 'key'):
                _, _, packet = files.inspect_file(root, descriptor, entry['files'][kind], MAX_FILE, retain=True)
                validate_packet(kind, packet, record['roots'][entry['root']])
                with (output / (kind + '.pem')).open('xb') as writer:
                    writer.write(packet)
                if os.name == 'posix':
                    os.chmod(output / (kind + '.pem'), 0o600)
    with (destination / 'plan.json').open('x', encoding='utf-8') as writer:
        json.dump(record, writer, sort_keys=True)
    if os.name == 'posix':
        os.chmod(destination / 'plan.json', 0o600)


def validate_packet(kind, packet, expected):
    if kind == 'ca':
        archive.require(root_digest(packet) == expected)
    elif kind == 'cert':
        root_digest(packet)
    else:
        archive.require(kind == 'key' and packet.count(b'PRIVATE KEY-----') == 2 and b'CERTIFICATE' not in packet)


def handshake(context, ca, hostname, should_succeed):
    errors = []
    listener = socket.socket()
    listener.settimeout(3)
    listener.bind(('127.0.0.1', 0))
    listener.listen(1)
    def serve():
        try:
            connection, _ = listener.accept()
            with connection:
                connection.settimeout(3)
                with context.wrap_socket(connection, server_side=True) as secure:
                    secure.sendall(b'leaf-recovery-proof')
        except (OSError, ssl.SSLError):
            errors.append(True)
        finally:
            listener.close()
    worker = threading.Thread(target=serve, daemon=True)
    port = listener.getsockname()[1]
    worker.start()
    client = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(ca))
    client.minimum_version = ssl.TLSVersion.TLSv1_2
    failed = False
    fingerprint = version = None
    try:
        with socket.create_connection(('127.0.0.1', port), timeout=3) as connection:
            with client.wrap_socket(connection, server_hostname=hostname) as secure:
                archive.require(secure.recv(64) == b'leaf-recovery-proof')
                fingerprint = hashlib.sha256(secure.getpeercert(binary_form=True)).hexdigest()
                version = secure.version()
    except ssl.SSLCertVerificationError:
        failed = True
    finally:
        worker.join(timeout=4)
        listener.close()
    archive.require(not worker.is_alive())
    archive.require((failed and not should_succeed) or (not failed and should_succeed and not errors))
    return fingerprint, version


def probe(directory):
    directory = Path(directory)
    with (directory / 'plan.json').open('rb') as reader:
        record = archive.parse(reader.read(MAX_FILE + 1), MAX_FILE)
    validate_plan(record)
    results = {}
    for name, entry in record['roles'].items():
        folder = directory / name
        with (folder / 'ca.pem').open('rb') as reader:
            archive.require(root_digest(reader.read(MAX_FILE + 1)) == record['roots'][entry['root']])
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(str(folder / 'cert.pem'), str(folder / 'key.pem'))
        fingerprint, version = handshake(context, folder / 'ca.pem', entry['serverName'], True)
        archive.require(version in ('TLSv1.2', 'TLSv1.3'))
        handshake(context, folder / 'ca.pem', 'wrong.recovery.invalid', False)
        other = 'admin-gateway' if name != 'admin-gateway' else 'agent-gateway'
        if entry['root'] == 'admin':
            other = 'agent-gateway'
        handshake(context, directory / other / 'ca.pem', entry['serverName'], False)
        try:
            mismatch = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            mismatch.load_cert_chain(str(folder / 'cert.pem'), str(directory / other / 'key.pem'))
        except ssl.SSLError:
            pass
        else:
            raise archive.ArchiveError('Mismatched TLS key was accepted.')
        results[name] = {'certificateSha256': fingerprint, 'version': version, 'rootPinMatched': True,
                         'wrongNameDenied': True, 'wrongCaDenied': True, 'wrongKeyDenied': True}
    return {'schema': 'fleetory.leaf-tls-proof.v1', 'roles': results, 'positiveHandshakes': 7,
            'wrongNameDenials': 7, 'wrongCaDenials': 7, 'mismatchedKeyDenials': 7,
            'applicationsOrIssuerStarted': False, 'mtlsClientAuthorizationVerified': False,
            'postgresProtocolVerified': False, 'originalMaterialApprovalInferred': False,
            'fullSystemRecoveryVerified': False, 'phase7Complete': False}


def local_docker():
    archive.require(not os.environ.get('DOCKER_HOST') and not os.environ.get('DOCKER_CONTEXT'))
    def call(arguments):
        result = subprocess.run(['docker', *arguments], capture_output=True, timeout=30)
        archive.require(result.returncode == 0)
        return result.stdout.decode().strip()
    context = call(['context', 'show'])
    archive.require(context in ('default', 'desktop-linux'))
    endpoint = call(['context', 'inspect', context, '--format', '{{.Endpoints.docker.Host}}'])
    archive.require(endpoint in ('unix:///var/run/docker.sock', 'npipe:////./pipe/dockerDesktopLinuxEngine',
                                'npipe:////./pipe/docker_engine'))
    return context


def sandbox(staging):
    """Local, single-use network-none worker; caller owns the protected minimal staging."""
    context = local_docker()
    name = 'fleetory-leaf-' + secrets.token_hex(16)
    identity = name.removeprefix('fleetory-leaf-')
    def call(arguments, check=True):
        result = subprocess.run(['docker', '--context', context, *arguments], capture_output=True, timeout=120)
        archive.require(len(result.stdout) <= 65536 and len(result.stderr) <= 65536)
        archive.require(not check or result.returncode == 0)
        return result
    archive.require(call(['info', '--format', '{{.OSType}}']).stdout.strip() == b'linux')
    call(['image', 'inspect', PYTHON, '--format', '{{.Id}}'])
    archive.require(call(['container', 'inspect', name], False).returncode != 0)
    user = str(os.geteuid()) + ':' + str(os.getegid()) if os.name == 'posix' else '65534:65534'
    archive.require(not user.startswith('0:'))
    mounts = [str(Path(staging).resolve(strict=True)), str(Path(__file__).resolve().parent)]
    archive.require(all(',' not in path for path in mounts))
    created = False
    def owned():
        template = '{"label":{{json (index .Config.Labels "' + LABEL + '")}},"image":{{json .Config.Image}},"user":{{json .Config.User}},"host":{{json .HostConfig}},"mounts":{{json .Mounts}}}'
        value = json.loads(call(['container', 'inspect', name, '--format', template]).stdout)
        host = value['host']
        archive.require(value['label'] == identity and value['image'] == PYTHON and value['user'] == user)
        archive.require(host['NetworkMode'] == 'none' and host['ReadonlyRootfs'] and not host['Privileged'] and
                        not host['PortBindings'] and host['CapDrop'] == ['ALL'] and not host['CapAdd'] and
                        'no-new-privileges' in host['SecurityOpt'][0] and host['Memory'] == 134217728 and
                        host['PidsLimit'] == 64 and host['NanoCpus'] == 1000000000)
        actual = value['mounts']
        archive.require(len(actual) == 2 and all(item['Type'] == 'bind' and not item['RW'] for item in actual))
        archive.require({item['Destination'] for item in actual} == {'/material', '/tool'})
    try:
        call(['create', '--name', name, '--label', LABEL + '=' + identity, '--network', 'none', '--read-only',
              '--user', user, '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--memory', '128m',
              '--cpus', '1', '--pids-limit', '64', '--mount', 'type=bind,src=' + mounts[0] + ',dst=/material,readonly',
              '--mount', 'type=bind,src=' + mounts[1] + ',dst=/tool,readonly', PYTHON,
              'python', '-B', '/tool/recovery_tls.py', '--probe'])
        created = True
        owned()
        result = archive.parse(call(['start', '--attach', name]).stdout, 16384)
        archive.require(result['schema'] == 'fleetory.leaf-tls-proof.v1' and
                        result['positiveHandshakes'] == result['wrongNameDenials'] ==
                        result['wrongCaDenials'] == result['mismatchedKeyDenials'] == 7)
        owned()
        return result
    finally:
        if created:
            owned()
            call(['rm', '-f', name])
            archive.require(call(['container', 'inspect', name], False).returncode != 0)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--probe', action='store_true', help='Internal Linux worker: only fixed /material staging.')
    args = parser.parse_args()
    try:
        archive.require(args.probe and os.name == 'posix')
        result = probe('/material')
    except Exception:
        print('Leaf TLS proof refused; no certificate/key contents logged.', file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
