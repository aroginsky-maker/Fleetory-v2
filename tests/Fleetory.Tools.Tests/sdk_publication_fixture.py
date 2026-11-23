"""Generated public fixture only; these computed pins are not production source commitments."""
import base64
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from sdk_publication_code_tests import code_frame
import public_build_output_tests as output
import audit_probe_image_tests as legacy
import audit_publication_namespace as ns

frame, _ = code_frame()
plan = ns.bundle.prep.canonical(legacy.control_plan('00000000-0000-0000-0000-000000000001'))
value = dict(archive=base64.b64encode(output.make()).decode(), codeFrame=base64.b64encode(frame).decode(), planTemplate=plan.decode())
sys.stdout.write(json.dumps(value, separators=(',', ':')))
