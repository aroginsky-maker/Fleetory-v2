"""Fixed generated guardian entrypoint; one UUID, no host path or command input."""
from pathlib import Path
import shutil
import sys

sys.path.insert(0,str(Path(__file__).resolve().parent))
import audit_public_cleanup_guard as guard


def run():
    guard.packet.require(len(sys.argv)==2)
    nonce=guard.packet.identity(sys.argv[1])
    repository=Path(__file__).resolve().parents[2]
    root=repository/'artifacts'/('public-cleanup-'+nonce)
    root.mkdir(mode=0o700,parents=False,exist_ok=False)
    python=Path(sys.executable).resolve(strict=True)
    docker=Path(shutil.which('docker') or '').resolve(strict=True)
    pins={name:guard.H((repository/name).read_bytes()) for name in guard.SOURCES}
    with guard.PublicCleanupGuard(repository,root,nonce,python,guard.H(python.read_bytes()),docker,guard.H(docker.read_bytes()),pins) as owner:
        print(guard.C(owner.create()).decode('ascii'),flush=True)
        print(guard.C(owner.cleanup()).decode('ascii'),flush=True)


if __name__=='__main__':
    try:run()
    except Exception:
        print('Fixed public guardian refused; any lost result remains consumed.',file=sys.stderr);raise SystemExit(1)
