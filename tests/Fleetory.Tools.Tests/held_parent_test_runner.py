"""Run generated peer suites under an actual Python parent, never the CI shell."""
from pathlib import Path
import subprocess
import sys


def main():
    suite = Path(sys.argv[0]).resolve(strict=True)
    result = subprocess.run([sys.executable, '-B', '-m', 'unittest', suite.stem],
                            cwd=suite.parent, timeout=45, check=False)
    raise SystemExit(result.returncode)
