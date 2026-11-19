"""Prevent a generated reply gate from becoming an arbitrary Docker mutation endpoint."""
import copy
import io
import json
import unittest

import audit_probe_image_tests  # Installs the fixed eng/pilot import path.
from historical import historical_create_gate as gate

IMAGE = 'sha256:' + 'a' * 64
NONCE = '5ad88fc0-8a83-40d3-b5b3-da80e89dc064'
TOKEN = 'b' * 64


def body():
    return {'Image': IMAGE, 'User': '3322:3322', 'Entrypoint': ['/bin/sh'],
            'Cmd': ['-c', 'exec /bin/sleep 660'],
            'Labels': {'fleetory.immu-data.session': NONCE},
            'HostConfig': {'NetworkMode': 'none', 'ReadonlyRootfs': True, 'AutoRemove': True,
                           'CapDrop': ['ALL'], 'SecurityOpt': ['no-new-privileges'],
                           'Memory': 402653184, 'NanoCpus': 1000000000, 'PidsLimit': 128,
                           'Ulimits': [{'Name': 'core', 'Hard': 0, 'Soft': 0}], 'Tmpfs': gate.TMPFS.copy()}}


def raw(value):
    return json.dumps(value, separators=(',', ':')).encode('ascii')


def policy():
    return gate.CreateGatePolicy(IMAGE, NONCE, TOKEN, '1.56')


def headers():
    return {'x-fleetory-create-nonce': TOKEN, 'content-type': 'application/json'}


def create(p, value=None):
    return p.authorize('POST', '/v1.56/containers/create?name=' + p.name,
                       headers(), raw(body() if value is None else value))


class PolicyTests(unittest.TestCase):
    def test_docker28_empty_legacy_onbuild_has_no_instructions(self):
        value = body()
        value['OnBuild'] = None
        self.assertEqual(create(policy(), value), 'create')
        for instructions in ([], ['RUN id'], '', False, 0, {'RUN': 'id'}):
            value['OnBuild'] = instructions
            with self.subTest(instructions=instructions), self.assertRaises(ValueError):
                create(policy(), value)

    def test_api_version_matches_the_same_client_and_server(self):
        self.assertEqual(gate.select_api_version('1.56', '1.48'), '1.48')
        self.assertEqual(gate.select_api_version('1.48', '1.56'), '1.48')
        self.assertEqual(gate.select_api_version('1.56', '1.56'), '1.56')
        for value in ('1.47', '1.0', '2.48', '1.48/containers', None, 1.48):
            with self.subTest(value=value), self.assertRaises(ValueError):
                gate.select_api_version('1.56', value)

    def test_native_negotiation_is_bounded(self):
        p = policy()
        for _ in range(2):
            self.assertEqual(p.authorize('HEAD', '/_ping', headers(), b''), 'ping')
        with self.assertRaises(ValueError):
            p.authorize('HEAD', '/_ping', headers(), b'')

    def test_one_create_after_one_authenticated_ping(self):
        p = policy()
        self.assertEqual(p.authorize('HEAD', '/_ping', headers(), b''), 'ping')
        self.assertEqual(create(p), 'create')
        with self.assertRaises(ValueError):
            create(p)
        with self.assertRaises(ValueError):
            p.authorize('HEAD', '/_ping', headers(), b'')

    def test_failed_authentication_cannot_be_repaired(self):
        p = policy()
        with self.assertRaises(ValueError):
            p.authorize('POST', '/v1.56/containers/create?name=' + p.name, {}, raw(body()))
        with self.assertRaises(ValueError):
            create(p)

    def test_no_other_daemon_operation_or_query(self):
        for method, target in [('GET', '/containers/json'), ('POST', '/containers/x/start'),
                               ('DELETE', '/containers/x'), ('POST', '/build'),
                               ('POST', '/v1.56/containers/create?name=x'),
                               ('POST', '/v1.56/containers/create?name=' + policy().name + '&platform=linux'),
                               ('POST', '/v1.55/containers/create?name=' + policy().name)]:
            with self.subTest(method=method, target=target):
                p = policy()
                with self.assertRaises(ValueError):
                    p.authorize(method, target, headers(), raw(body()))
                with self.assertRaises(ValueError):
                    create(p)

    def test_cannot_inject_image_command_identity_or_runtime_privilege(self):
        top = [('Image', 'ubuntu'), ('User', '0'), ('Entrypoint', ['/bin/bash']),
               ('Cmd', ['-c', 'id']), ('Labels', {}), ('Env', ['TOKEN=secret']),
               ('Volumes', {'/host': {}}), ('UnknownFutureSwitch', True), ('UnknownFutureSwitch', False),
               ('NetworkingConfig', {'EndpointsConfig': {'host': {}}})]
        host = [('NetworkMode', 'host'), ('ReadonlyRootfs', False), ('AutoRemove', False),
                ('CapDrop', []), ('CapAdd', ['ALL']), ('SecurityOpt', []),
                ('Memory', 0), ('NanoCpus', 0), ('PidsLimit', 0), ('Privileged', True),
                ('Binds', ['/:/host']), ('PortBindings', {'22/tcp': [{'HostPort': '22'}]}),
                ('Devices', [{'PathOnHost': '/dev/kvm'}]), ('PidMode', 'host'),
                ('Tmpfs', {'/data': 'rw,exec,size=1g'}),
                ('Ulimits', [{'Name': 'core', 'Hard': False, 'Soft': False}])]
        for location, fields in [('top', top), ('host', host)]:
            for key, value in fields:
                with self.subTest(location=location, field=key):
                    b = body()
                    target = b if location == 'top' else b['HostConfig']
                    target[key] = value
                    with self.assertRaises(ValueError):
                        create(policy(), b)

    def test_duplicate_json_key_and_nonfinite_value_refused(self):
        for value in [b'{"Image":"x","Image":"y"}', b'{"HostConfig":{"Privileged":false,"Privileged":true}}',
                      b'{"x":NaN}', b'{"x":Infinity}', b'[]', b'\xff', b'[' * 200]:
            with self.subTest(value=value[:30]), self.assertRaises(ValueError):
                gate.document(value)

    def test_required_safety_properties_cannot_be_omitted(self):
        b = body()
        for location in ['top', 'host']:
            for key in list(b if location == 'top' else b['HostConfig']):
                changed = copy.deepcopy(b)
                del (changed if location == 'top' else changed['HostConfig'])[key]
                with self.subTest(location=location, key=key), self.assertRaises(ValueError):
                    create(policy(), changed)


class HttpTests(unittest.TestCase):
    def test_exact_body_is_read_without_consuming_next_frame(self):
        payload = raw(body())
        wire = b'POST /v1.56/containers/create HTTP/1.1\r\nContent-Length: ' + str(len(payload)).encode() + b'\r\n\r\n' + payload + b'NEXT'
        stream = io.BytesIO(wire)
        method, target, _, actual = gate.read_request(stream)
        self.assertEqual((method, target, actual), ('POST', '/v1.56/containers/create', payload))
        self.assertEqual(stream.read(), b'NEXT')

    def test_ambiguous_or_unbounded_http_never_reaches_policy(self):
        values = [b'POST / HTTP/1.1\r\nContent-Length: 0\r\ncontent-length: 1\r\n\r\nx',
                  b'POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n',
                  b'GET / HTTP/1.1\r\nUpgrade: websocket\r\n\r\n',
                  b'POST / HTTP/1.1\r\nExpect: 100-continue\r\n\r\n',
                  b'POST / HTTP/1.1\r\nContent-Length: 99999\r\n\r\n',
                  b'POST / HTTP/1.1\r\nContent-Length: 2\r\n\r\nx',
                  b'POST / HTTP/1.1\r\nContent-Length: 01\r\n\r\nx',
                  b'HEAD /_ping HTTP/1.1\n\n', b'GET / HTTP/1.1\r\nX: ' + b'x' * 8192]
        for value in values:
            with self.subTest(value=value[:50]), self.assertRaises(ValueError):
                gate.read_request(io.BytesIO(value))




class ResponseTests(unittest.TestCase):
    def test_chunked_create_preserves_original_wire_bytes(self):
        payload = raw({'Id': 'c' * 64, 'Warnings': []})
        chunks = format(len(payload[:20]), 'x').encode() + b'\r\n' + payload[:20] + b'\r\n'
        chunks += format(len(payload[20:]), 'x').encode() + b'\r\n' + payload[20:] + b'\r\n0\r\n\r\n'
        original = b'HTTP/1.1 201 Created\r\nTransfer-Encoding: chunked\r\n\r\n' + chunks
        response, _ = gate.read_response(io.BytesIO(original), 'POST')
        self.assertEqual(response, original)

    def test_chunk_bounds_and_ambiguous_framing_refused(self):
        head = b'HTTP/1.1 201 Created\r\nTransfer-Encoding: chunked\r\n\r\n'
        for chunks in [b'1;extension=x\r\nx\r\n0\r\n\r\n', b'1001\r\n',
                       b'2\r\nx', b'0\r\nTrailer: bad\r\n\r\n', b'1\r\nx\r\n' * 65]:
            with self.subTest(chunks=chunks[:30]), self.assertRaises(ValueError):
                gate.read_response(io.BytesIO(head + chunks), 'POST')
        with self.assertRaises(ValueError):
            gate.read_response(io.BytesIO(head.replace(b'\r\n\r\n', b'\r\nContent-Length: 2\r\n\r\n') + b'{}'), 'POST')


    def test_complete_original_create_response_retained(self):
        payload = raw({'Id': 'c' * 64, 'Warnings': []})
        response = b'HTTP/1.1 201 Created\r\nContent-Length: ' + str(len(payload)).encode() + b'\r\n\r\n' + payload
        captured, _ = gate.read_response(io.BytesIO(response), 'POST')
        self.assertEqual(captured, response)

    def test_bad_upstream_response_never_becomes_ownership(self):
        for response in [b'HTTP/1.1 500 Internal Server Error\r\n\r\n',
                         b'HTTP/1.1 201 Created\r\nTransfer-Encoding: chunked\r\n\r\n',
                         b'HTTP/1.1 201 Created\r\nContent-Length: 10\r\n\r\nx',
                         b'HTTP/1.1 201 Created\r\nContent-Length: 2\r\ncontent-length: 2\r\n\r\n{}',
                         b'HTTP/1.1 201 Created\r\nContent-Length: 2\r\n\r\n{}']:
            with self.subTest(response=response[:70]), self.assertRaises(ValueError):
                gate.read_response(io.BytesIO(response), 'POST')


class LiveGateTests(unittest.TestCase):
    def exercise(self, release, bad_auth=False):
        import os
        import queue
        import socket
        import threading
        from historical_audit_observation import _creator_frame
        frames = queue.Queue()
        calls, errors = [], []
        payload = raw({'Id': 'c' * 64, 'Warnings': []})
        original = b'HTTP/1.1 201 Created\r\nContent-Length: ' + str(len(payload)).encode() + b'\r\n\r\n' + payload

        class Sink:
            def write(self, value):
                self_test.assertEqual(int.from_bytes(value[:4], 'big'), len(value) - 4)
                frames.put(json.loads(value[4:]))

            def flush(self):
                pass

        def exchange(method, target, sent):
            calls.append((method, target, sent))
            return original, {}

        read_fd, write_fd = os.pipe()
        source, writer = os.fdopen(read_fd, 'rb'), os.fdopen(write_fd, 'wb')
        self_test = self

        def serve():
            try:
                gate.serve_gate(policy(), exchange, source, Sink())
            except ValueError as error:
                errors.append(error)

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        bound = frames.get(timeout=5)
        self.assertEqual(bound['stage'], 'bound')
        client = socket.create_connection(('127.0.0.1', bound['port']), timeout=2)
        client.settimeout(0.1)
        wire = ('POST /v1.56/containers/create?name=' + policy().name + ' HTTP/1.1\r\n'
                'Content-Type: application/json\r\nX-Fleetory-Create-Nonce: ' + ('0' * 64 if bad_auth else TOKEN) +
                '\r\nContent-Length: ' + str(len(raw(body()))) + '\r\n\r\n').encode() + raw(body())
        try:
            client.sendall(wire)
            if bad_auth:
                self.assertEqual(client.recv(1), b'')
                self.assertFalse(calls)
            else:
                held = frames.get(timeout=5)
                self.assertEqual(held['stage'], 'held')
                self.assertEqual(len(calls), 1)
                with self.assertRaises(TimeoutError):
                    client.recv(1)
                if release is not None:
                    writer.write(_creator_frame(release));writer.flush()
                writer.close()
                client.settimeout(3)
                actual = bytearray()
                while True:
                    chunk = client.recv(4096)
                    if not chunk:
                        break
                    actual.extend(chunk)
                self.assertEqual(bytes(actual), original if release == ('release:' + NONCE).encode() else b'')
            thread.join(3)
            self.assertFalse(thread.is_alive())
            self.assertEqual(bool(errors), bad_auth or release != ('release:' + NONCE).encode())
        finally:
            writer.close();client.close();thread.join(3);source.close()

    def test_live_tcp_response_withheld_until_private_release(self):
        self.exercise(('release:' + NONCE).encode())

    def test_other_private_nonce_cannot_release_response(self):
        self.exercise(b'release:00000000-0000-0000-0000-000000000001')

    def test_private_eof_does_not_release_response(self):
        self.exercise(None)

    def test_unauthenticated_local_peer_cannot_reach_daemon(self):
        self.exercise(None, bad_auth=True)


if __name__ == '__main__':
    unittest.main(verbosity=2)
