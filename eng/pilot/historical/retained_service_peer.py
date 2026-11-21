"""Fixed private parent-consumer channel; four packets, no Docker, signal or permission API."""
import argparse
from contextlib import ExitStack
import base64
import ctypes
import os
from pathlib import Path
import queue
import sys
import threading

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from historical import retained_service_use as use
from historical import retained_code_catalog as code_catalog

packet, C, H, identity = use.packet, use.C, use.H, use.identity
HEADER = 'fleetory.retained-service-peer-header.v1'
MAX_CONTROL, MAX_PRIVATE = 184320, 25165824
EXTRA = ('historical/retained_service_peer.py', 'historical/RetainedServiceUseTransport.ps1')
REPO = Path(__file__).resolve().parents[3]


class PreparationRefused(ValueError):
    def __init__(self, stage):
        packet.require(stage in ('metadata', 'parent-runtime', 'parent-identity'))
        self.stage = stage
        super().__init__('Fixed preparation refused')


def _parent_path():
    if os.name == 'posix':
        return (Path('/proc') / str(os.getppid()) / 'exe').resolve(strict=True)
    from ctypes import wintypes as w
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    opened = kernel.OpenProcess
    opened.argtypes, opened.restype = [w.DWORD, w.BOOL, w.DWORD], w.HANDLE
    handle = opened(0x1000, False, os.getppid())
    packet.require(handle)
    try:
        query = kernel.QueryFullProcessImageNameW
        query.argtypes, query.restype = [w.HANDLE, w.DWORD, w.LPWSTR, ctypes.POINTER(w.DWORD)], w.BOOL
        text, size = ctypes.create_unicode_buffer(32768), w.DWORD(32768)
        packet.require(query(handle, 0, text, ctypes.byref(size)))
        return Path(text.value).resolve(strict=True)
    finally:
        close = kernel.CloseHandle
        close.argtypes, close.restype = [w.HANDLE], w.BOOL
        packet.require(close(handle))


def _parent_identity(pinned):
    peer = (identity._WindowsPeer if os.name == 'nt' else identity._LinuxPeer)(os.getppid(), pinned)
    try:
        return peer.live_identity()
    finally:
        peer.close()


def _mode(value):
    packet.require(value in ('normal', 'exit-after-release', 'exit-on-request', 'expire-after-restore'))
    if value != 'normal':
        root = Path.cwd().resolve(strict=True)
        packet.require(root.name == 'retained-inputs' and root.parent.parent == REPO/'artifacts'
                       and root.parent.name.startswith('native-pair-'))
        packet.identity(root.parent.name[len('native-pair-'):])
    return value


def prepare(raw):
    value = packet.strict_json(raw, MAX_CONTROL)
    packet.keys(value, 'metadata nonce revision imageId probeSha256 configurationSha256 mode codePlan codePlanSha256')
    packet.keys(value['metadata'], 'selection manifest checkpoint ci local')
    metadata = {n: packet.decode(v, 524288) for n, v in value['metadata'].items()}
    code_plan = packet.decode(value['codePlan'], code_catalog.lease.MAX_PLAN)
    code_info = code_catalog.lease._plan(code_plan, value['codePlanSha256'], code_catalog.names(REPO))
    packet.require(code_info[1] == value['nonce'])
    root = Path.cwd().resolve(strict=True)
    plan = dict(schema=use.SCHEMA, purpose=use.PURPOSE, nonce=value['nonce'], revision=value['revision'],
                root=str(root), pins={n:H(v) for n,v in metadata.items()},
                sourcePins={n:H((REPO/'eng/pilot'/n).read_bytes()) for n in use.SOURCES},
                pythonSha256=H(Path(sys.executable).resolve().read_bytes()),
                **{n:value[n] for n in ('imageId','probeSha256','configurationSha256')})
    frozen = C(plan)
    try:
        use._admit(frozen, H(frozen), metadata, root)  # Metadata only; no original artifacts opened.
    except Exception:
        raise PreparationRefused('metadata') from None
    try:
        parent_path = _parent_path()
        pinned = identity.process.PinnedFile(parent_path, H(parent_path.read_bytes()), True)
    except Exception:
        raise PreparationRefused('parent-runtime') from None
    with pinned:
        try:
            parent = _parent_identity(pinned)
        except Exception:
            raise PreparationRefused('parent-identity') from None
    header = dict(schema=HEADER, plan=base64.b64encode(frozen).decode('ascii'), planSha256=H(frozen),
                  metadata=value['metadata'], parent=parent, mode=_mode(value['mode']),
                  sources={n:H((REPO/'eng/pilot'/n).read_bytes()) for n in EXTRA},
                  codePlan=value['codePlan'], codePlanSha256=value['codePlanSha256'])
    data = C(header)
    packet.require(len(data) <= MAX_CONTROL)
    return dict(header=base64.b64encode(data).decode('ascii'), sha256=H(data), nonce=plan['nonce'], parent=parent)


def _exact(fd, count):
    result = bytearray()
    while len(result) < count:
        block = os.read(fd, count-len(result))
        packet.require(block)
        result.extend(block)
    return bytes(result)


def _receive():
    size = int.from_bytes(_exact(0, 4), 'big')
    packet.require(0 < size <= MAX_CONTROL)
    return _exact(0, size)


def _send(raw):
    packet.require(type(raw) is bytes and 0 < len(raw) <= MAX_PRIVATE)
    for part in (len(raw).to_bytes(4, 'big'), raw):
        view = memoryview(part)
        while view:
            written = os.write(1, view)
            packet.require(written > 0)
            view = view[written:]


class _Reader:
    def __init__(self):
        self.values = queue.Queue(maxsize=4)
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self):
        try:
            while True:
                self.values.put(_receive())
        except Exception:
            self.values.put(None)

    def next(self, check):
        while True:
            check()
            try:
                raw = self.values.get(timeout=0.05)
            except queue.Empty:
                continue
            packet.require(raw is not None)
            return raw


def run(expected):
    raw = _receive()
    packet.require(H(raw) == packet.hex_value(expected))
    header = packet.strict_json(raw, MAX_CONTROL)
    packet.keys(header, 'schema plan planSha256 metadata parent mode sources codePlan codePlanSha256')
    packet.require(header['schema'] == HEADER)
    mode = _mode(header['mode'])
    packet.keys(header['metadata'], 'selection manifest checkpoint ci local')
    metadata = {n:packet.decode(v, 524288) for n,v in header['metadata'].items()}
    plan = packet.decode(header['plan'], use.MAX_PLAN)
    declared = packet.strict_json(plan, use.MAX_PLAN)
    packet.keys(header['sources'], ' '.join(EXTRA))
    with ExitStack() as held:
        code_names = code_catalog.names(REPO)
        code_lease = held.enter_context(code_catalog.lease.hold(REPO,
            packet.decode(header['codePlan'], code_catalog.lease.MAX_PLAN), header['codePlanSha256'], code_names))
        code_report = code_lease.report()
        packet.require(code_report['nonce'] == declared['nonce'])
        pinned = held.enter_context(identity.process.PinnedFile(_parent_path(), header['parent']['executableSha256'], True))
        parent = held.enter_context(identity.HeldLocalPeer('parent', pinned, header['parent']))
        extra = [held.enter_context(identity.process.PinnedFile(
            REPO/'eng/pilot'/name, header['sources'][name])) for name in EXTRA]
        reader = _Reader()
        count = 0
        def check():
            try:
                packet.require(code_catalog.names(REPO) == code_names)
                code_lease.check()
            except Exception:
                _send(C(dict(kind='code-refused',nonce=declared['nonce'],codePlanSha256=header['codePlanSha256'])))
                raise
            packet.require(parent.snapshot()['state'] == 'live')
            for source in extra:
                source.check()
            current.report()
        def consume(payload):
            nonlocal count
            check()
            _send(C(dict(kind='payload',nonce=declared['nonce'],planSha256=H(plan),
                         payloadSha256=H(payload),payloadBytes=len(payload),consumer=parent.snapshot()['identity'])))
            _send(payload)
            if mode == 'exit-after-release':
                os._exit(37)
            while True:
                message = packet.strict_json(reader.next(check), MAX_CONTROL)
                packet.require(message.get('nonce') == declared['nonce'])
                if mode == 'exit-on-request' and message.get('kind') == 'generated-fault-exit':
                    packet.keys(message, 'kind nonce payloadSha256')
                    packet.require(message['payloadSha256'] == H(payload))
                    os._exit(37)
                if message.get('kind') == 'status':
                    packet.keys(message, 'kind nonce sequence payloadSha256')
                    count += 1
                    packet.require(count <= 256 and type(message['sequence']) is int and message['sequence'] == count
                                   and message['payloadSha256'] == H(payload))
                    _send(C(dict(kind='live',nonce=declared['nonce'],sequence=count,payloadSha256=H(payload))))
                else:
                    packet.keys(message, 'kind nonce resultSha256')
                    packet.require(message['kind'] == 'result')
                    result = reader.next(check)
                    packet.require(H(result) == packet.hex_value(message['resultSha256']))
                    return result
        with use.use(Path.cwd().resolve().parent/'operator', Path.cwd().resolve(), REPO,
                     plan, header['planSha256'], metadata, consume) as current:
            _send(C(dict(kind='bound',nonce=declared['nonce'],headerSha256=H(raw),
                         planSha256=H(plan),consumer=parent.snapshot()['identity'],owner=current.report()['heldProcessIdentity'],
                         codePlanSha256=header['codePlanSha256'],codeFiles=code_report['files'])))
            start = packet.strict_json(reader.next(check), 512)
            packet.keys(start, 'kind nonce')
            packet.require(start == dict(kind='capture',nonce=declared['nonce']))
            current.capture()
            result = current.dispatch()
            _send(C(dict(kind='receipt',nonce=declared['nonce'],resultSha256=H(result),
                         planSha256=H(plan),statusChecks=count,actualParentIdentityBound=True,
                         nativeResultAuthenticated=False,executionAuthorized=False,phase7Complete=False,
                         codePlanSha256=header['codePlanSha256'],codeFiles=code_report['files'])))
            stop = packet.strict_json(reader.next(check), 512)
            packet.require(stop == dict(kind='close',nonce=declared['nonce']))
        _send(C(dict(kind='closed',nonce=declared['nonce'],phase7Complete=False)))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(allow_abbrev=False)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--prepare', action='store_true')
    group.add_argument('--header-sha256')
    args = parser.parse_args()
    try:
        if args.prepare:
            raw = sys.stdin.buffer.read(MAX_CONTROL+1)
            print(C(prepare(raw)).decode('utf-8'))
        else:
            run(args.header_sha256)
    except PreparationRefused as refusal:
        os.write(2, ('Retained service preparation refused at '+refusal.stage+'; no input contents logged.\n').encode('ascii'))
        sys.exit(1)
    except Exception:
        os.write(2,b'Retained service peer refused; no input contents logged.\n')
        sys.exit(1)
