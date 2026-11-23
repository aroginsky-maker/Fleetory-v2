"""Fixed public operator source namespace; no original inputs or native commands."""
import os
from pathlib import Path
import sys

if __name__ == '__main__':
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from historical import retained_code_lease as lease

packet, C, H = lease.packet, lease.prep.canonical, lease.packet.digest
HELPERS = ('PilotNativeProcess.ps1', 'PilotDisposableTls.ps1', 'NativeSignerFixture.ps1',
           'NativeJournalFixture.ps1', 'NativeAuditFixture.ps1', 'NativeStoreFixture.ps1',
           'NativeWorkerRuntime.ps1', 'NativePairFixture.ps1', 'NativeAuditDataFixture.ps1', 'NativeRetainedMaterial.ps1')
SKIP = frozenset(('obj', 'bin', '__pycache__'))
REPO = Path(__file__).resolve().parents[3]


def names(repository):
    """Enumerate metadata only; an unlisted public-code file cannot silently enter the plan."""
    root = Path(repository).absolute()
    found = set(lease.prep.ROOTS)
    found.update('tests/Fleetory.Tools.Tests/' + n for n in HELPERS)
    for prefix in ('eng', 'src'):
        for directory, children, filenames in os.walk(root/prefix, followlinks=False):
            for name in children:
                if name not in SKIP:
                    info = (Path(directory)/name).lstat()
                    packet.require(not (Path(directory)/name).is_symlink()
                                   and not getattr(info, 'st_file_attributes', 0) & 0x400)
            children[:] = [n for n in children if n not in SKIP]
            for filename in filenames:
                relative = (Path(directory)/filename).relative_to(root).as_posix()
                found.add(lease._name(relative))
    packet.require(0 < len(found) <= lease.MAX_FILES)
    return tuple(sorted(found))


def build(repository, snapshot, nonce):
    packet.require(type(snapshot) is dict and snapshot.get('schema') == 'fleetory.historical-code-snapshot.v2')
    packet.identity(nonce)
    selected = names(repository)
    available = snapshot['sourcePins']
    packet.require(type(available) is dict and all(name in available for name in selected))
    # Unknown filesystem names were refused above. The existing Git snapshot supplies
    # all pins; this layer never opens file contents or authenticates that snapshot.
    plan = C(dict(schema=lease.SCHEMA, revision=snapshot['revision'], nonce=nonce,
                  sourcePins={name:available[name] for name in selected}))
    lease._plan(plan, H(plan), selected)
    return plan


if __name__ == '__main__':
    import base64
    try:
        packet.require(len(sys.argv) == 1)
        request = packet.strict_json(sys.stdin.buffer.read(262145), 262144)
        packet.keys(request, 'snapshot nonce')
        result = build(REPO, request['snapshot'], request['nonce'])
        print(C(dict(plan=base64.b64encode(result).decode('ascii'), sha256=H(result),
                     files=len(names(REPO)))).decode('ascii'))
    except Exception:
        print('Retained public code catalog refused; no contents logged.', file=sys.stderr)
        sys.exit(1)
