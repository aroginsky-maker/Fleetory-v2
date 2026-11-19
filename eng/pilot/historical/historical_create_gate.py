"""Bounded policy for one generated, unstarted historical create; no generic Docker proxy."""
import hmac
import json
import re
import uuid

HEADER_LIMIT = 8192
BODY_LIMIT = 16384
TMPFS = {
    '/data': 'rw,noexec,nosuid,nodev,size=256m,uid=3322,gid=3322,mode=0700',
    '/run/fleetory-native-create': 'rw,noexec,nosuid,nodev,size=32m,uid=3322,gid=3322,mode=0700',
}
CONFIG_DEFAULTS = frozenset(('Hostname', 'Domainname', 'AttachStdin', 'Tty', 'OpenStdin',
                             'StdinOnce', 'Env', 'Volumes', 'WorkingDir'))
HOST_DEFAULTS = frozenset('Binds ContainerIDFile PortBindings VolumeDriver VolumesFrom CapAdd CgroupnsMode '
    'Dns DnsOptions DnsSearch ExtraHosts GroupAdd IpcMode Cgroup Links OomScoreAdj PidMode Privileged '
    'PublishAllPorts UTSMode UsernsMode ShmSize Isolation CpuShares CgroupParent BlkioWeight '
    'BlkioWeightDevice BlkioDeviceReadBps BlkioDeviceWriteBps BlkioDeviceReadIOps BlkioDeviceWriteIOps '
    'CpuPeriod CpuQuota CpuRealtimePeriod CpuRealtimeRuntime CpusetCpus CpusetMems Devices '
    'DeviceCgroupRules DeviceRequests MemoryReservation MemorySwap OomKillDisable CpuCount CpuPercent '
    'IOMaximumIOps IOMaximumBandwidth MaskedPaths ReadonlyPaths Init StorageOpt Sysctls Runtime'.split())


REFUSAL_CODES = frozenset('policy profile-required profile-optional profile-extra request-auth request-target '
    'request-framing response-status response-header response-chunk response-length response-json response-fields response-id '
    'response-warnings response-deadline native-exit native-stderr native-stderr-close native-stderr-sudo native-trailing'.split())


class GateRefusal(ValueError):
    """Only a fixed category crosses the native diagnostic boundary."""


def require(value, code='policy'):
    if not value:
        category = code if code in REFUSAL_CODES else 'policy'
        raise GateRefusal('Historical create gate refused: ' + category + '.')


def _unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def document(raw):
    require(type(raw) is bytes and 0 < len(raw) <= BODY_LIMIT)
    value = json.loads(raw, object_pairs_hook=_unique,
                      parse_constant=lambda _: require(False))
    require(type(value) is dict)
    return value


def _empty(value):
    return value is None or value is False or (
        type(value) in (int, str, list, dict) and value in (0, '', [], {}))


def _profile(actual, expected, optional, defaults):
    require(type(actual) is dict)
    for key, value in expected.items():
        require(key in actual and _same(actual[key], value), 'profile-required')
    for key, value in actual.items():
        if key not in expected:
            if key in optional:
                require(any(_same(value, v) for v in optional[key]), 'profile-optional')
            else:
                require(key in defaults and _empty(value), 'profile-extra')


def _same(first, second):
    return type(first) is type(second) and json.dumps(first, sort_keys=True, allow_nan=False) == json.dumps(second, sort_keys=True, allow_nan=False)


def validate_create(raw, image, nonce):
    value = document(raw)
    expected = {'Image': image, 'User': '3322:3322', 'Entrypoint': ['/bin/sh'],
                'Cmd': ['-c', 'exec /bin/sleep 660'],
                'Labels': {'fleetory.immu-data.session': nonce}}
    host = value.pop('HostConfig', None)
    _profile(value, expected, {'AttachStdout': (True, False), 'AttachStderr': (True, False),
                             'NetworkingConfig': ({'EndpointsConfig': {}},), 'OnBuild': (None,)}, CONFIG_DEFAULTS)
    expected_host = {'NetworkMode': 'none', 'ReadonlyRootfs': True, 'AutoRemove': True,
                     'CapDrop': ['ALL'], 'SecurityOpt': ['no-new-privileges'],
                     'Memory': 402653184, 'NanoCpus': 1000000000, 'PidsLimit': 128,
                     'Ulimits': [{'Name': 'core', 'Hard': 0, 'Soft': 0}], 'Tmpfs': TMPFS}
    _profile(host, expected_host, {
        'ConsoleSize': ([0, 0],),
        'LogConfig': ({'Type': '', 'Config': {}},),
        'RestartPolicy': ({'Name': 'no', 'MaximumRetryCount': 0},),
        'MemorySwappiness': (-1,),
    }, HOST_DEFAULTS)


def _read_headers(stream, first, code):
    require(first.endswith(b'\r\n') and len(first) <= HEADER_LIMIT, code)
    wire = bytearray(first)
    headers = {}
    while True:
        line = stream.readline(HEADER_LIMIT + 1)
        wire.extend(line)
        require(line.endswith(b'\r\n') and len(wire) <= HEADER_LIMIT, code)
        if line == b'\r\n':
            break
        require(b':' in line, code)
        name, value = line[:-2].split(b':', 1)
        require(re.fullmatch(rb'[A-Za-z0-9-]+', name) is not None, code)
        name = name.decode('ascii').lower()
        require(name not in headers, code)
        headers[name] = value.strip().decode('ascii')
    return wire, headers


def read_request(stream):
    first = stream.readline(HEADER_LIMIT + 1)
    require(first.endswith(b'\r\n'))
    parts = first[:-2].decode('ascii').split(' ')
    require(len(parts) == 3 and parts[2] == 'HTTP/1.1')
    _, headers = _read_headers(stream, first, 'request-framing')
    require('transfer-encoding' not in headers and 'upgrade' not in headers and
            'expect' not in headers and 'authorization' not in headers)
    length = headers.get('content-length', '0')
    require(re.fullmatch(r'0|[1-9][0-9]{0,4}', length) is not None)
    length = int(length)
    require(length <= BODY_LIMIT)
    body = stream.read(length)
    require(len(body) == length)
    return parts[0], parts[1], headers, body


def select_api_version(server, client):
    for value in (server, client):
        require(type(value) is str and re.fullmatch(r'1\.[0-9]{2}', value) is not None and int(value[2:]) >= 48)
    return min((server, client), key=lambda value: int(value[2:]))


class CreateGatePolicy:
    """An invalid mutation consumes this instance too; it can never be repaired or retried."""
    def __init__(self, image, nonce, token, version):
        require(type(image) is str and re.fullmatch(r'sha256:[a-f0-9]{64}', image) is not None)
        require(type(nonce) is str and str(uuid.UUID(nonce)) == nonce and uuid.UUID(nonce).int != 0)
        require(type(token) is str and re.fullmatch(r'[a-f0-9]{64}', token) is not None)
        require(type(version) is str and re.fullmatch(r'1\.[0-9]{2}', version) is not None)
        self.image, self.nonce, self.token, self.version = image, nonce, token, version
        self.name = 'fleetory-immu-store-' + nonce.replace('-', '')
        self.attempted = False
        self.pings = 0

    def authorize(self, method, target, headers, body):
        require(not self.attempted)
        if method != 'HEAD' or target != '/_ping':
            self.attempted = True
        supplied = headers.get('x-fleetory-create-nonce', '')
        require(hmac.compare_digest(supplied.encode('ascii'), self.token.encode('ascii')), 'request-auth')
        if method == 'HEAD' and target == '/_ping':
            require(not body and self.pings < 2)
            self.pings += 1
            return 'ping'
        require(method == 'POST' and
                target == '/v' + self.version + '/containers/create?name=' + self.name, 'request-target')
        require(headers.get('content-type') == 'application/json')
        validate_create(body, self.image, self.nonce)
        return 'create'


def _read_chunks(stream):
    wire, body = bytearray(), bytearray()
    for _ in range(64):
        line = stream.readline(16)
        require(re.fullmatch(rb'[a-fA-F0-9]{1,4}\r\n', line) is not None, 'response-chunk')
        count = int(line[:-2], 16)
        require(count <= 4096 - len(body), 'response-chunk')
        chunk = stream.read(count)
        ending = stream.read(2)
        require(len(chunk) == count and ending == b'\r\n', 'response-chunk')
        wire.extend(line + chunk + ending)
        body.extend(chunk)
        require(len(wire) <= 8192, 'response-chunk')
        if count == 0:
            return bytes(wire), bytes(body)
    require(False, 'response-chunk')


def read_response(stream, method):
    first = stream.readline(HEADER_LIMIT + 1)
    require(first in (b'HTTP/1.1 200 OK\r\n', b'HTTP/1.1 201 Created\r\n'), 'response-status')
    wire, headers = _read_headers(stream, first, 'response-header')
    if method == 'HEAD':
        require(first == b'HTTP/1.1 200 OK\r\n' and 'transfer-encoding' not in headers and
                re.fullmatch(r'1\.[0-9]{2}', headers.get('api-version', '')) is not None)
    else:
        require(first == b'HTTP/1.1 201 Created\r\n', 'response-status')
        if 'transfer-encoding' in headers:
            require(headers['transfer-encoding'] == 'chunked' and 'content-length' not in headers, 'response-header')
            chunks, body = _read_chunks(stream)
            wire.extend(chunks)
        else:
            length = headers.get('content-length', '')
            require(re.fullmatch(r'[1-9][0-9]{0,3}', length) is not None and int(length) <= 4096, 'response-length')
            body = stream.read(int(length))
            require(len(body) == int(length), 'response-length')
            wire.extend(body)
        result = document(body)
        require(set(result) == {'Id', 'Warnings'}, 'response-fields')
        require(type(result['Id']) is str and re.fullmatch(r'[a-f0-9]{64}', result['Id']) is not None, 'response-id')
        require(result['Warnings'] in (None, []), 'response-warnings')
    return bytes(wire), headers


def daemon_exchange(command, environment, method, target, body):
    """One original native daemon stream, kept duplex until the complete bounded reply."""
    import subprocess
    import threading
    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, env=environment)
    result = {}

    def receive():
        try:
            headers = (method + ' ' + target + ' HTTP/1.1\r\nHost: docker\r\nConnection: close\r\n'
                       'Content-Type: application/json\r\nContent-Length: ' + str(len(body)) + '\r\n\r\n')
            process.stdin.write(headers.encode('ascii') + body)
            process.stdin.flush()
            result['reply'] = read_response(process.stdout, method)
        except (OSError, ValueError) as error:
            result['error'] = error

    reader = threading.Thread(target=receive, daemon=True)
    try:
        reader.start()
        reader.join(12)
        require(not reader.is_alive(), 'response-deadline')
        if 'error' in result:
            error = result['error']
            if isinstance(error, GateRefusal):
                raise error
            require(False, 'response-json')
        require('reply' in result, 'response-length')
        # Connection: close ends the daemon side of this duplex stream. Keep
        # client stdin open until that exit; closing it here races the Docker
        # copier's CloseWrite with the daemon's own connection shutdown.
        process.wait(timeout=3)
        require(process.returncode == 0, 'native-exit')
        native_error = process.stderr.read(1025)
        category = 'native-stderr'
        if b'error while CloseRead (' in native_error or b'error while CloseWrite (' in native_error:
            category = 'native-stderr-close'
        elif native_error.startswith(b'sudo:'):
            category = 'native-stderr-sudo'
        require(not native_error, category)  # All nonempty stderr remains refused; no contents escape.
        require(not process.stdout.read(1), 'native-trailing')
        return result['reply']
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=3)
        reader.join(2)
        for stream in (process.stdin, process.stdout, process.stderr):
            stream.close()


def serve_gate(policy, exchange, source, sink):
    import hashlib
    import os
    import socket
    from historical_audit_observation import _creator_read, _creator_write

    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        listener.settimeout(25)
        _creator_write(sink, json.dumps({'stage': 'bound', 'pid': os.getpid(),
            'port': listener.getsockname()[1], 'version': policy.version}).encode('ascii'))
        for _ in range(3):
            peer, address = listener.accept()
            with peer:
                require(address[0] == '127.0.0.1')
                peer.settimeout(20)
                with peer.makefile('rb') as stream:
                    method, target, headers, body = read_request(stream)
                    kind = policy.authorize(method, target, headers, body)
                    response, _ = exchange(method, target, body)
                    if kind == 'create':
                        listener.close()
                        _creator_write(sink, json.dumps({'stage': 'held', 'pid': os.getpid(),
                            'responseSha256': hashlib.sha256(response).hexdigest(), 'nativeDaemonStreamExited': True}).encode('ascii'))
                        release = _creator_read(source, 96)
                        require(release == ('release:' + policy.nonce).encode('ascii') and not source.read(1))
                    peer.sendall(response)
                    if kind == 'create':
                        return
        require(False)


def run_gate(raw, expected):
    import hashlib
    import os
    from pathlib import Path
    import shutil
    import sys
    import tempfile

    require(hashlib.sha256(raw).hexdigest() == expected)
    request = document(raw)
    require(set(request) == {'image', 'nonce', 'token', 'docker', 'dockerSha256', 'clientApiVersion'})
    docker = Path(request['docker'])
    require(docker.is_absolute() and not docker.is_symlink() and docker.is_file() and
            hashlib.sha256(docker.read_bytes()).hexdigest() == request['dockerSha256'])
    allowed = ('PATH', 'SystemRoot', 'WINDIR', 'HOME', 'USERPROFILE', 'APPDATA', 'LOCALAPPDATA',
               'ProgramData', 'TEMP', 'TMP', 'TMPDIR')
    allowed = frozenset(key.upper() if os.name == 'nt' else key for key in allowed)
    environment = {key: value for key, value in os.environ.items()
                   if (key.upper() if os.name == 'nt' else key) in allowed}
    with tempfile.TemporaryDirectory(prefix='fleetory-generated-create-gate-') as directory:
        endpoint = 'npipe:////./pipe/dockerDesktopLinuxEngine' if os.name == 'nt' else 'unix:///var/run/docker.sock'
        command = [str(docker), '--config', directory, '--host', endpoint, 'system', 'dial-stdio']
        if os.name != 'nt':
            sudo = shutil.which('sudo')
            require(sudo is not None and Path(sudo).is_absolute())
            command = [sudo, '-n'] + command
        _, response_headers = daemon_exchange(command, environment, 'HEAD', '/_ping', b'')
        require(response_headers.get('ostype') == 'linux')
        version = select_api_version(response_headers['api-version'], request['clientApiVersion'])
        policy = CreateGatePolicy(request['image'], request['nonce'], request['token'], version)
        def exchange(method, target, body):
            return daemon_exchange(command, environment, method, target, body)
        serve_gate(policy, exchange, sys.stdin.buffer, sys.stdout.buffer)


if __name__ == '__main__':
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from historical_audit_observation import _creator_read
    require(len(sys.argv) == 3 and sys.argv[1] == '--request-sha256' and
            re.fullmatch(r'[a-f0-9]{64}', sys.argv[2]) is not None)
    run_gate(_creator_read(sys.stdin.buffer, 4096), sys.argv[2])
