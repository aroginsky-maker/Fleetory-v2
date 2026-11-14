"""Generated record writer for a forced-death contract; no backend or cleanup API."""
import hashlib
import json
import os
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'eng/pilot'))
import audit_control_identity as policy


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in ('reservation', 'binding'):
        return 1
    data = sys.stdin.buffer.read(policy.MAX_RECORD + 1)
    with policy.claim(Path.cwd(), data, hashlib.sha256(data).hexdigest()) as session:
        if sys.argv[1] == 'binding':
            session.bind_assertion(os.getpid(), time.time_ns(), json.loads(data)['runtimes']['powershell'])
        print('BINDING_READY' if sys.argv[1] == 'binding' else 'RESERVATION_READY', flush=True)
        time.sleep(15)
    return 0


if __name__ == '__main__':
    sys.exit(main())
