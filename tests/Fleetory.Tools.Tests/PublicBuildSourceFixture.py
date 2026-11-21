"""Generated-only source child for protocol tests; no SDK/Docker or original reader."""
from pathlib import Path
import datetime as dt
import json
import os
import sys

repo=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(repo/'eng/pilot'))
from public_build import intake
from public_build.peer import serve_capture

assert len(sys.argv)==3 and sys.argv[2] in ('normal','expiry')
root=Path(sys.argv[1]).absolute()
assert root.name.startswith('fleetory-public-intake-model-') and root.resolve()==root
metadata=(root/'peer-fixture.json').read_bytes();assert len(metadata)<=65536
value=json.loads(metadata);assert value.keys()=={'sources','packages','crls'}
crls=value['crls']
for pin in crls.values():
    for name in ('thisUpdate','nextUpdate'):pin[name]=dt.datetime.fromisoformat(pin[name])
if sys.argv[2]=='expiry':intake.LIFETIME=1  # Shortened generated-only fixture, not a product option.
try:
    captured=intake.capture(tuple(root/n for n in ('source','packages','crls')),value['sources'],value['packages'],crls)
    serve_capture(captured,0,1)
except Exception:
    os.write(2,b'Public input fixture refused; no contents logged.\n')
    raise SystemExit(37)
