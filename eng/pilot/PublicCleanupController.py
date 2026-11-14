"""Fixed idle test controller: parent-owned stdin EOF is its only release."""
from contextlib import ExitStack
from pathlib import Path
import sys

sys.path.insert(0,str(Path(__file__).resolve().parent))
import audit_supervisor_identity as identity


def run():
    packet=identity.packet
    packet.require(len(sys.argv)==1)
    raw=sys.stdin.buffer.readline(4097)
    packet.require(raw.endswith(b'\n') and len(raw)<=4096)
    value=packet.strict_json(raw,4096)
    packet.keys(value,'schema nonce parent controller pythonSha256')
    packet.require(value['schema']=='fleetory.fixed-idle-controller.v1')
    packet.identity(value['nonce'])
    with ExitStack() as held:
        executable=held.enter_context(identity.process.PinnedFile(Path(sys.executable),value['pythonSha256'],True))
        parent=held.enter_context(identity.HeldLocalPeer('parent',executable,value['parent']))
        own=held.enter_context(identity.HeldLocalPeer('self',executable,value['controller']))
        packet.require(parent.snapshot()['state']==own.snapshot()['state']=='live')
        print(identity.protocol.C(dict(schema='fleetory.fixed-idle-ready.v1',nonce=value['nonce'],
            parent=value['parent'],controller=value['controller'])).decode('ascii'),flush=True)
        # The guardian retains the sole writer. Its death closes the pipe on both OSes.
        packet.require(sys.stdin.buffer.read(1)==b'')


if __name__=='__main__':
    try:run()
    except Exception:
        print('Fixed idle controller refused.',file=sys.stderr);raise SystemExit(1)
