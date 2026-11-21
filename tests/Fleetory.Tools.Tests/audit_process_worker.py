"""Generated blocked-input worker and same-fence descendant; no backend or original paths."""
import json
import os
from pathlib import Path
import subprocess
import sys
import time


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in ('echo', 'sleep', 'child', 'owner-dies', 'stdout', 'stderr', 'no-read', 'env', 'leaf'):
        return 1
    mode = sys.argv[1]
    if mode in ('leaf', 'no-read'):
        time.sleep(20)
        return 0
    data = sys.stdin.buffer.read(131073)
    if mode == 'echo':
        sys.stdout.buffer.write(data)
    elif mode == 'sleep':
        time.sleep(20)
    elif mode in ('child', 'owner-dies'):
        child = subprocess.Popen([sys.executable, '-B', __file__, 'leaf'], stdin=subprocess.DEVNULL)
        Path('generated-descendant.pid').write_text(str(child.pid), encoding='ascii')
        print(json.dumps(dict(child=child.pid)), flush=True)
        if mode == 'owner-dies':
            os._exit(17)
        time.sleep(20)
    elif mode == 'stdout':
        sys.stdout.buffer.write(b'x' * 270000)
        sys.stdout.buffer.flush()
    elif mode == 'stderr':
        sys.stderr.buffer.write(b'x' * 6000)
        sys.stderr.buffer.flush()
    elif mode == 'env':
        print(json.dumps({name: name in os.environ for name in ('PYTHONPATH', 'DOCKER_HOST', 'SONAR_TOKEN', 'FLEETORY_PRIVATE_CANARY')}))
    return 0


if __name__ == '__main__':
    sys.exit(main())
