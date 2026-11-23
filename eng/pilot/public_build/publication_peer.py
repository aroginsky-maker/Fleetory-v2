"""Private public-byte publication peer. No Docker, original-data, secrets or native custody API."""
import hashlib
import os
from pathlib import Path
import queue
import re
import struct
import threading
import time
import uuid

import audit_publication_namespace as ns
from public_build import output

LIFETIME = 60
MAX_PLAN = 8192
MAX_CONTEXT = 16 * 1024 * 1024
MAX_MANIFEST = 98304


def require(value):
    if not value:
        raise ValueError('SDK publication peer refused')


class Pipe:
    def __init__(self, incoming, outgoing):
        self.incoming, self.outgoing = incoming, outgoing
        self.started = time.monotonic()
        self.messages = queue.Queue(maxsize=2)
        self.pending = bytearray()
        threading.Thread(target=self._reader, daemon=True).start()

    def remaining(self):
        seconds = LIFETIME - (time.monotonic() - self.started)
        require(0 < seconds <= LIFETIME)
        return seconds

    def _reader(self):
        try:
            while True:
                data = os.read(self.incoming, 65536)
                self.messages.put(data)
                if not data:
                    return
        except OSError:
            self.messages.put(None)

    def read(self, length):
        require(type(length) is int and 0 < length <= output.MAX_ARCHIVE)
        result = bytearray()
        while len(result) < length:
            self.remaining()
            if not self.pending:
                data = self.messages.get(timeout=self.remaining())
                require(data is not None and bool(data))
                self.pending.extend(data)
            count = min(length - len(result), len(self.pending))
            result.extend(self.pending[:count]);del self.pending[:count]
        return bytes(result)

    def write(self, data):
        require(type(data) is bytes and 0 < len(data) <= MAX_CONTEXT + 4096)
        done = threading.Event();errors = []
        def send():
            try:
                view = memoryview(data)
                while view:
                    self.remaining()
                    count = os.write(self.outgoing, view[:65536])
                    require(0 < count <= min(65536, len(view)))
                    view = view[count:]
            except Exception as error:
                errors.append(type(error).__name__)
            finally:
                done.set()
        threading.Thread(target=send, daemon=True).start()
        require(done.wait(self.remaining()) and not errors)

    def frame(self, magic, nonce, source_pin, data):
        require(len(magic) == 8 and len(nonce) == 32 and len(source_pin) == 32)
        self.write(magic + nonce + source_pin + struct.pack('!I', len(data)) + hashlib.sha256(data).digest() + data)

    def finish(self):
        require(not self.pending)
        require(self.messages.get(timeout=self.remaining()) == b'')


def serve(root, nonce, incoming=0, outgoing=1):
    require(type(nonce) is str and re.fullmatch('[a-f0-9]{32}', nonce))
    root = Path(root).absolute()
    require(root.name == 'fleetory-sdk-publication-' + nonce and root.resolve() == root)
    if os.name == 'nt':
        require(re.fullmatch('[A-Za-z]:', root.drive))
    require(set(os.listdir(root)) == {'repository', 'controls'})
    nonce_bytes = nonce.encode('ascii')
    pipe = Pipe(incoming, outgoing)
    pipe.write(b'FLTSRD01' + nonce_bytes)
    header = pipe.read(112)
    require(header[:8] == b'FLTSIN01' and header[8:40] == nonce_bytes)
    size, plan_size = struct.unpack('!II', header[40:48])
    require(0 < size <= output.MAX_ARCHIVE and 0 < plan_size <= MAX_PLAN)
    source_pin, plan_pin = header[48:80], header[80:112]
    raw, plan = pipe.read(size), pipe.read(plan_size)
    require(hashlib.sha256(raw).digest() == source_pin and hashlib.sha256(plan).digest() == plan_pin)
    content = output.inspect(raw, source_pin.hex())
    manifest = ns.bundle.manifest_from_files(content)
    require(len(manifest) <= MAX_MANIFEST)
    value, _ = ns.control.admit(plan, plan_pin.hex())
    require(value['nonce'] == str(uuid.UUID(hex=nonce)))
    pipe.remaining()
    with ns.control.claim(root/'controls', plan, plan_pin.hex()) as session:
        intent = ns.prepare(session, ns.packet.digest(manifest), value['codeSha256'])
        with ns.OwnedPublication(root/'repository', intent, ns.packet.digest(intent)) as publication:
            publication.publish_sdk(raw, source_pin.hex())
            pipe.frame(b'FLTSOUT1', nonce_bytes, source_pin, manifest)
            used = False
            while True:
                command = pipe.read(1)
                if command == b'R':
                    pipe.finish()
                    break
                require(command == b'C' and not used)
                used = True
                size = struct.unpack('!I', pipe.read(4))[0]
                require(0 < size <= 4096)
                request_pin, recipe = pipe.read(32), pipe.read(size)
                require(hashlib.sha256(recipe).digest() == request_pin)
                context = publication.published.context(recipe)
                require(0 < len(context) <= MAX_CONTEXT)
                pipe.frame(b'FLTSCTX1', nonce_bytes, source_pin, request_pin + hashlib.sha256(manifest).digest() + context)
    pipe.frame(b'FLTSEND1', nonce_bytes, source_pin, b'')


if __name__ == '__main__':
    import sys
    try:
        require(len(sys.argv) == 3)
        serve(sys.argv[1], sys.argv[2])
    except Exception:
        os.write(2, b'SDK publication peer refused; no input contents logged.\n')
        raise SystemExit(37)
