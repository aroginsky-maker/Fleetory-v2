"""Source-only private-pipe protocol; no native resource operations.

The trusted parent must bound pipe I/O and own the source-only child process.
On transport timeout it may stop this child, never the resource-owning worker.
"""
import hashlib
import os
import queue
import struct
import threading
import uuid

from . import context, intake

MAGIC=b'FLTPUB01'
HEADER=struct.Struct('!8sI32s16s')
REQUEST=b'S'
PERMIT=b'\x01'


def _write(captured,descriptor,data):
    view=memoryview(data);offset=0
    while offset<len(view):
        captured._state()
        written=os.write(descriptor,view[offset:offset+65536])
        intake.require(type(written) is int and 0<written<=min(65536,len(view)-offset))
        offset+=written


def _commands(descriptor,messages,overflow):
    try:
        while True:
            raw=os.read(descriptor,1)
            try:messages.put_nowait(raw)
            except queue.Full:overflow.set();return
            if not raw:return
    except OSError:
        overflow.set()


def serve_capture(captured,command_descriptor,output_descriptor):
    intake.require(type(captured) is intake.CapturedPublicInputs)
    intake.require(type(command_descriptor) is int and type(output_descriptor) is int
                   and command_descriptor>=0 and output_descriptor>=0 and command_descriptor!=output_descriptor)
    # The attempt is consumed before the first output byte. No report/ID import.
    raw=captured.take()
    intake.require(type(raw) is bytes and 0<len(raw)<=context.MAX_CONTEXT)
    nonce=uuid.uuid4().bytes
    _write(captured,output_descriptor,HEADER.pack(MAGIC,len(raw),hashlib.sha256(raw).digest(),nonce))
    _write(captured,output_descriptor,raw)
    messages=queue.Queue(maxsize=2);overflow=threading.Event()
    reader=threading.Thread(target=_commands,args=(command_descriptor,messages,overflow),daemon=True)
    reader.start();permitted=False
    while True:
        captured._state();intake.require(not overflow.is_set())
        try:command=messages.get(timeout=0.05)
        except queue.Empty:continue
        intake.require(not overflow.is_set())
        if command==b'':return
        intake.require(command==REQUEST and not permitted)
        permitted=True
        captured.check_before_sdk()
        _write(captured,output_descriptor,PERMIT)
