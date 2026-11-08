"""One fixed native-owned public sleep container; no publisher, build, backend or cleanup API."""
import base64
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import threading
import time

import audit_native_probe_runtime as base

payload, prep, packet, process, runtime = base.payload, base.prep, base.packet, base.process, base.runtime
SOURCES = (*base.SOURCES, 'eng/pilot/audit_native_probe_create.py')
SCHEMA = 'fleetory.native-probe-create-header.v1'
CREATE_SCHEMA = 'fleetory.native-probe-create-offer.v1'
CREATED_SCHEMA = 'fleetory.native-probe-created.v1'
MAX_CREATE = 16384
FIELDS = dict(id='.Id', name='.Name', imageId='.Image', created='.Created', labels='.Config.Labels',
    configImage='.Config.Image', user='.Config.User', entrypoint='.Config.Entrypoint', command='.Config.Cmd',
    running='.State.Running', paused='.State.Paused', restarting='.State.Restarting', dead='.State.Dead',
    networkMode='.HostConfig.NetworkMode', networks='.NetworkSettings.Networks', readonly='.HostConfig.ReadonlyRootfs',
    privileged='.HostConfig.Privileged', capDrop='.HostConfig.CapDrop', capAdd='(index .HostConfig "CapAdd")',
    securityOpt='.HostConfig.SecurityOpt', memory='.HostConfig.Memory', nanoCpus='.HostConfig.NanoCpus',
    pidsLimit='.HostConfig.PidsLimit', mounts='.Mounts', ports='(index .NetworkSettings "Ports")',
    portBindings='(index .HostConfig "PortBindings")', binds='(index .HostConfig "Binds")', tmpfs='(index .HostConfig "Tmpfs")',
    volumesFrom='(index .HostConfig "VolumesFrom")', devices='(index .HostConfig "Devices")', deviceRequests='(index .HostConfig "DeviceRequests")',
    pidMode='.HostConfig.PidMode', ipcMode='.HostConfig.IpcMode', utsMode='.HostConfig.UTSMode', usernsMode='.HostConfig.UsernsMode',
    restart='.HostConfig.RestartPolicy', autoRemove='.HostConfig.AutoRemove', publishAllPorts='.HostConfig.PublishAllPorts',
    environment='.Config.Env', ulimits='.HostConfig.Ulimits')
FORMAT = '{"schema":"' + runtime.OBSERVATION_SCHEMA + '",' + ','.join(json.dumps(k)+':{{json '+v+'}}' for k,v in FIELDS.items()) + '}'


def _header_value(data):
    value = packet.strict_json(data, prep.MAX_HEADER)
    packet.keys(value, 'schema nonce controlSha256 planBase64 gitSha256 controlDirectorySha256 selectedSourcesSha256 dockerSha256 runtimeIntentSha256')
    packet.require(value['schema'] == SCHEMA)
    for key in ('dockerSha256', 'runtimeIntentSha256'):packet.hex_value(value[key])
    return value


def header(data, native_pin):
    value = _header_value(data)
    old = {k:v for k,v in value.items() if k not in ('dockerSha256', 'runtimeIntentSha256')}
    old['schema'] = payload.SCHEMA
    info = payload.header(prep.canonical(old), native_pin)
    info['headerSha256'] = packet.digest(data)
    return info


def reservation(data, native_pin):
    info, value = header(data, native_pin), _header_value(data)
    return dict(schema='fleetory.audit-payload-reservation.v1', nonce=info['nonce'], controlSha256=info['controlSha256'],
        controlDirectorySha256=value['controlDirectorySha256'], bundleSha256=value['selectedSourcesSha256'])


def runtime_intent(raw, expected, info):
    packet.require(packet.digest(raw) == expected)
    value = packet.strict_json(raw, runtime.container.MAX_INTENT)
    packet.keys(value, 'schema purpose nonce revision controlSha256 image name labels openedNs expiresNs ' + ' '.join(runtime.SOURCE_FIELDS))
    packet.require(value['schema'] == runtime.SCHEMA and value['purpose'] == runtime.PURPOSE and
        value['nonce'] == info['nonce'] and value['revision'] == info['revision'] and value['controlSha256'] == info['controlSha256'] and
        value['sourceCodeSha256'] == info['codeSha256'] and value['name'] == runtime.name(info['nonce']) and
        value['runtimeProfileSha256'] == runtime.PROFILE_SHA256 and value['image'] == value['imageId'])
    runtime.container.image_id(value['imageId'])
    for key in runtime.SOURCE_FIELDS[1:]:packet.hex_value(value[key])
    packet.require(type(value['openedNs']) is int and type(value['expiresNs']) is int and
        value['openedNs'] <= time.time_ns() < value['expiresNs'] and 0 < value['expiresNs'] - value['openedNs'] <= runtime.container.WINDOW_NS)
    labels = value['labels']
    packet.require(type(labels) is dict and 6 <= len(labels) <= 22)
    for key, text in labels.items():
        packet.require(type(key) is str and re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}', key) and
            type(text) is str and len(text) <= 1024 and all(ord(c) >= 32 for c in text))
    expected_labels = {'fleetory.audit.control.nonce':value['nonce'], 'fleetory.audit.control.reservation':value['controlSha256'],
        'fleetory.audit.control.profile':runtime.PURPOSE, 'fleetory.audit.control.probe.bundle':value['bundleManifestSha256'],
        'fleetory.audit.control.image.binding':value['imageBindingSha256'], 'fleetory.audit.control.runtime.profile':runtime.PROFILE_SHA256}
    packet.require({k:v for k,v in labels.items() if k.startswith('fleetory.audit.control.')} == expected_labels)
    packet.require(runtime.runtime_profile() == runtime.PROFILE)
    return value


def create_offer(info, ready_pin, ready, intent_bytes):
    return dict(schema=CREATE_SCHEMA, nonce=info['nonce'], headerSha256=info['headerSha256'], readySha256=ready_pin,
        ownerSha256=ready['ownerSha256'], payloadDirectorySha256=ready['payloadDirectorySha256'], intentSha256=ready['intentSha256'],
        runtimeIntentBase64=base64.b64encode(intent_bytes).decode('ascii'), decision='create-fixed-public-sleep')


def created(info, ready_pin, ready, intent_pin, identifier, native_pid):
    packet.require(type(identifier) is str and re.fullmatch('[a-f0-9]{64}', identifier))
    packet.require(type(native_pid) is int and 0 < native_pid <= 0xffffffff)
    return dict(schema=CREATED_SCHEMA, nonce=info['nonce'], headerSha256=info['headerSha256'], readySha256=ready_pin,
        ownerSha256=ready['ownerSha256'], payloadDirectorySha256=ready['payloadDirectorySha256'], runtimeIntentSha256=intent_pin,
        containerId=identifier, pid=native_pid, privateInputsAccepted=False, backendServiceStarted=False)


def _arguments(value):
    args = ['run', '-d', '--pull=never', '--name', value['name'], '--rm', '--network=none', '--read-only',
        '--user=3322:3322', '--cap-drop=ALL', '--security-opt=no-new-privileges:true', '--memory=384m',
        '--cpus=1', '--pids-limit=128', '--restart=no', '--ulimit=core=0:0', '--entrypoint=/bin/sh']
    for path, options in runtime.TMPFS.items():args.extend(['--tmpfs', path+':'+options])
    for key, text in value['labels'].items():args.extend(['--label', key+'='+text])
    return args + [value['imageId'], *runtime.COMMAND]


class _Docker:
    """Pinned trusted-host CLI, fixed local context and bounded pipes. No wire endpoint."""
    def __init__(self, pinned):
        packet.require(type(pinned) is process.PinnedFile and pinned.path.name.lower() in ('docker', 'docker.exe'))
        self.pinned = pinned
        self.context = 'desktop-linux' if os.name == 'nt' else 'default'
        raw = self._call(['context', 'inspect', self.context, '--format', '{{.Endpoints.docker.Host}}']).decode('ascii').strip()
        packet.require(raw == ('npipe:////./pipe/dockerDesktopLinuxEngine' if os.name == 'nt' else 'unix:///var/run/docker.sock'))
        version = self._call(['version', '--format', '{{.Server.Os}}:{{.Server.Version}}']).decode('ascii').strip()
        packet.require(re.fullmatch(r'linux:[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9_.-]+)?', version) and int(version.split(':')[1].split('.')[0]) >= 28)

    def _call(self, args):
        self.pinned.check()
        env = dict(process.environment(self.pinned))
        env.update(DOCKER_API_VERSION='1.48', COMPOSE_DISABLE_ENV_FILE='1')
        with subprocess.Popen([str(self.pinned.path), '--context', self.context, *args], stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0, env=env, shell=False) as child:
            pumps = process._Pumps(child, b'');pumps.start()
            try:
                child.wait(timeout=8)
            finally:
                if child.poll() is None:child.kill();child.wait(timeout=3)
                pumps.finish()
            packet.require(child.returncode == 0 and not pumps.errors)
            result = bytes(pumps.stdout)
        self.pinned.check()
        return result

    def create(self, value):
        existing = self._call(['container', 'ls', '-a', '--no-trunc', '--filter', 'name=^/'+value['name']+'$', '--format', '{{.ID}}'])
        packet.require(not existing.strip())
        # Name lookup is a separate bounded RPC; admission may expire while it waits.
        packet.require(0 < value['expiresNs'] - time.time_ns() <= runtime.container.WINDOW_NS)
        identifier = self._call(_arguments(value)).decode('ascii').strip()
        packet.require(re.fullmatch('[a-f0-9]{64}', identifier))
        return identifier

    def observe(self, identifier):
        packet.require(type(identifier) is str and re.fullmatch('[a-f0-9]{64}', identifier))
        return self._call(['container', 'inspect', '--format', FORMAT, identifier])


def native_create(data, native_pin, ready_pin, native_pid):
    packet.require(type(native_pid) is int and native_pid == os.getppid())
    value = packet.strict_json(data, payload.MAX_ACTION)
    packet.keys(value, 'schema headerBase64 frameBase64 ownerSha256 payloadDirectorySha256 intentSha256')
    packet.require(value['schema'] == 'fleetory.native-empty-payload-action.v1')
    raw = packet.decode(value['headerBase64'], prep.MAX_HEADER)
    info, pins = header(raw, native_pin), _header_value(raw)
    frame = packet.strict_json(packet.decode(value['frameBase64'], MAX_CREATE), MAX_CREATE)
    packet.keys(frame, 'schema nonce headerSha256 readySha256 ownerSha256 payloadDirectorySha256 intentSha256 runtimeIntentBase64 decision')
    intent_bytes = packet.decode(frame['runtimeIntentBase64'], runtime.container.MAX_INTENT)
    intent = runtime_intent(intent_bytes, pins['runtimeIntentSha256'], info)
    packet.require(frame == create_offer(info, ready_pin, value, intent_bytes))
    repository = Path(__file__).resolve().parents[2]
    with payload._RecordedEmpty(repository, reservation(raw, native_pin), value, native_pid) as owned:
        owned.check()
        docker = Path(shutil.which('docker') or '').resolve(strict=True)
        with process.PinnedFile(docker, pins['dockerSha256'], True) as pinned:
            client = _Docker(pinned)
            runtime_intent(intent_bytes, pins['runtimeIntentSha256'], info)
            identifier = client.create(intent)
            owned.check()
            return created(info, ready_pin, value, pins['runtimeIntentSha256'], identifier, native_pid)


def _unbound_pair(session, pair):
    packet.require(type(pair) is tuple and len(pair) == 2)
    source, target = pair
    packet.require(type(source) is runtime.probe.ProbeImageBinding and type(target) is runtime.ProbeRuntimeBinding and
        source.session is target.session is session and target._source is source and target._bound is None and not target._attempted)
    runtime.anchor(session, source);target._check()
    return target._intent_bytes


class _NativeCreatePumps(base._NativeProbePumps):
    source_names = SOURCES
    profile, switch = 'native-probe-create', '-ProbeRuntimeCreationOnly'
    refusal_schema = 'fleetory.native-probe-create-refused.v1'
    decode_header, decode_reservation = staticmethod(header), staticmethod(reservation)
    max_frames, _ack_index = 5, 3

    @classmethod
    def make_header(cls, *args, docker_sha256, runtime_intent_sha256):
        value = super().make_header(*args)
        value.update(schema=SCHEMA, dockerSha256=docker_sha256, runtimeIntentSha256=runtime_intent_sha256)
        return value

    def __init__(self, *args):
        payload._NativePayloadPumps.__init__(self, *args)
        self.pair = self.command.linked_pair
        self.intent_bytes = _unbound_pair(self.session, self.pair)
        self.pins = _header_value(self.data[:-1])
        runtime_intent(self.intent_bytes, self.pins['runtimeIntentSha256'], self.info)
        packet.require(self.command.docker.digest == self.pins['dockerSha256'])
        self.resource_ack, self.created_event = threading.Event(), threading.Event()
        self.resource_intent_pin, self.ack_pin, self.receipt, self.create_pin = None, None, None, None

    def _accept_refusal(self, value):
        packet.keys(value, 'schema stage privateInputsAccepted emptyPayloadState backendCreated')
        packet.require(value['stage'] in ('header', 'git', 'code', 'reserve', 'create', 'resources', 'remove') and
            value['emptyPayloadState'] in ('not-attempted', 'unknown', 'reserved') and
            value['privateInputsAccepted'] is False and value['backendCreated'] is False)
        self.refusal_stage = value['stage'];self.errors.append('native-public-create-refused')

    def _after_payload_bound(self):
        self.command.check();self.bound.check();_unbound_pair(self.session, self.pair)
        owner = self.fence.identity(self.process, self.command.executable)
        self.session._write_once('native-probe-create-intent.json', dict(schema='fleetory.native-probe-create-intent.v1',
            nonce=self.info['nonce'], headerSha256=self.info['headerSha256'], actualOwnedProcess=owner,
            runtimeIntentSha256=self.pins['runtimeIntentSha256'], dockerSha256=self.pins['dockerSha256'], privateInputsAccepted=False))
        self.create_pin = packet.digest(self.session._records['native-probe-create-intent.json'][1])
        self._send_frame(create_offer(self.info, self.ready_pin, self.frames[1], self.intent_bytes))
        self._wait(self.created_event)
        super()._after_payload_bound()

    def _accept_frame(self, value, raw):
        if len(self.frames) != 2:
            packet.require(value.get('schema') != CREATED_SCHEMA)
            return super()._accept_frame(value, raw)
        packet.keys(value, 'schema nonce headerSha256 readySha256 ownerSha256 payloadDirectorySha256 runtimeIntentSha256 containerId pid privateInputsAccepted backendServiceStarted')
        packet.require(self.create_pin is not None and not self.created_event.is_set() and
            value == created(self.info, self.ready_pin, self.frames[1], self.pins['runtimeIntentSha256'], value['containerId'], self.process.pid) and
            type(value['pid']) is int and value['privateInputsAccepted'] is False and value['backendServiceStarted'] is False)
        self.command.check();self.bound.check()
        owner = self.fence.identity(self.process, self.command.executable)
        _unbound_pair(self.session, self.pair)
        self.pair[1].bind(_Docker(self.command.docker).observe(value['containerId']), value['containerId'])
        self.receipt = self._pair_receipt(self.session, self.pair)
        self.session._write_once('native-probe-create-binding.json', dict(schema='fleetory.native-probe-create-binding.v1',
            nonce=self.info['nonce'], actualOwnedProcess=owner, createIntentSha256=self.create_pin,
            receipt=value, receiptSha256=packet.digest(raw), backendBindingSha256=self.receipt['containerBindingSha256']))
        self.fence.identity(self.process, self.command.executable);self._check_pair()
        self.frames.append(value);self.created_event.set()

    def finalize_binding(self, child, ended, failed):
        try:
            super().finalize_binding(child, ended, failed)
            packet.require(self.created_event.is_set() and self.create_pin is not None and
                packet.digest(self.session._records['native-probe-create-intent.json'][1]) == self.create_pin)
            self.resource_metadata['actualNativeContainerCreateVerified'] = True
        finally:
            self.resource_metadata.update(generatedReceiptMetadataOnly=False, actualNativeContainerCreateVerified=self.resource_metadata.get('actualNativeContainerCreateVerified', False),
                nativePublicationBuildVerified=False, nativeCreatePreReceiptCrashGapVerified=False, controllerDeathCleanupVerified=False)


def create_owner(repository, powershell, python, git, native_plan, source_pins, session, pair, *, git_sha256, docker, docker_sha256):
    raw = _unbound_pair(session, pair)
    return prep._prepare_owner(repository, powershell, python, git, native_plan, source_pins, session, git_sha256,
        _NativeCreatePumps, linked_pair=pair, creation=(docker, docker_sha256, packet.digest(raw)))


def measure_sources(repository):
    return prep._measure_sources(repository, SOURCES)


if __name__ == '__main__':
    try:
        if len(sys.argv) == 3 and sys.argv[1] == 'header':result = header(sys.stdin.buffer.read(prep.MAX_HEADER+1), sys.argv[2])
        else:
            packet.require(len(sys.argv) == 5 and sys.argv[1] in ('reserve', 'remove', 'create', 'acknowledge'))
            raw = sys.stdin.buffer.read(payload.MAX_ACTION+1)
            if sys.argv[1] in ('reserve', 'remove'):
                result = payload._native_action(raw, sys.argv[2], sys.argv[3], int(sys.argv[4]), sys.argv[1], header, reservation)
            elif sys.argv[1] == 'create':result = native_create(raw, sys.argv[2], sys.argv[3], int(sys.argv[4]))
            else:
                result = base.base._native_acknowledge(raw, sys.argv[2], sys.argv[3], int(sys.argv[4]), base.ACTION_SCHEMA,
                    base.offer, base.acknowledgement, base.receipt, header, reservation)
        print(prep.canonical(result).decode('ascii'))
    except Exception:
        print('Native fixed public container creation refused.', file=sys.stderr);sys.exit(1)
