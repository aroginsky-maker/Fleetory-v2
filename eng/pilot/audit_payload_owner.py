"""Fixed metadata-only reservation owner. No archive, backend, key or arbitrary path input."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import audit_launch_bundle as bundle
import audit_payload_binding as binding
import fresh_server_pair as packet


def run():
    packet.require(len(sys.argv) == 2)
    value = binding.header(binding.read_frame(sys.stdin.buffer), sys.argv[1])
    repository = Path(__file__).resolve().parents[2]
    with binding.OwnedPayload(repository, value) as owned:
        ready = dict(schema='fleetory.audit-payload-ready.v1', nonce=value['nonce'],
            ownerSha256=owned.record_sha, payloadDirectorySha256=owned.directory_sha)
        sys.stdout.buffer.write(bundle.canonical(ready) + b'\n')
        sys.stdout.buffer.flush()
        release = packet.strict_json(binding.read_frame(sys.stdin.buffer), binding.MAX_FRAME)
        packet.keys(release, 'schema nonce ownerSha256 releaseSha256')
        packet.require(release['schema'] == 'fleetory.audit-payload-finish.v1' and release['nonce'] == value['nonce'])
        packet.require(release['ownerSha256'] == owned.record_sha)
        packet.hex_value(release['releaseSha256'])
        packet.require(sys.stdin.buffer.read(1) == b'')
        owned.remove()
    return dict(schema='fleetory.audit-payload-closed.v1', nonce=value['nonce'], releaseRequested=True)


if __name__ == '__main__':
    try:
        result = run()
    except Exception:
        print('Payload reservation refused; no packet contents or paths logged.', file=sys.stderr)
        sys.exit(1)
    sys.stdout.buffer.write(bundle.canonical(result) + b'\n')
    sys.stdout.buffer.flush()
