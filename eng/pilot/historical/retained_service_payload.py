"""Private native-owner pipe only: four frozen packets. Never send this output to logs."""
import base64
import json
from pathlib import Path
import sys

if __name__ == '__main__':
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from historical import retained_service_inputs as inputs

MAX_INPUT = 16 * 1024 * 1024


def payload(captured):
    inputs.packet.require(type(captured) is inputs.CapturedServiceInputs and captured.input_bytes <= MAX_INPUT)
    blobs = {kind: captured.packet(kind) for kind in inputs.KINDS}
    return dict(schema='fleetory.retained-service-private-payload.v1', capture=captured.report(),
        packetSha256={kind: inputs.packet.digest(data) for kind, data in blobs.items()},
        packets={kind: base64.b64encode(data).decode('ascii') for kind, data in blobs.items()},
        nativeRestorePerformed=False, executionAuthorized=False)


if __name__ == '__main__':
    try:
        result = payload(inputs.read_capture(maximum_input=MAX_INPUT))
    except Exception:
        print('Private retained payload refused; no paths or contents logged.', file=sys.stderr)
        sys.exit(1)
    # Only the invoking native owner may consume this private pipe. The summary CLI stays separate.
    print(json.dumps(result, sort_keys=True))
