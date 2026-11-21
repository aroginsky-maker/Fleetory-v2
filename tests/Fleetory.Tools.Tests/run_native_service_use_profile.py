"""Public private PowerShell fixture; actual child owns all of its native replies/resources."""
import argparse
from pathlib import Path
import subprocess
import sys
import tempfile

from private_runtime_fixture import private_powershell


def main():
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument('--powershell', required=True)
    parser.add_argument('--profile', required=True, choices=(
        'v2-retained-service-use','v2-retained-service-use-loss','v2-retained-service-use-expiry'))
    parser.add_argument('--failure-point', required=True, choices=('none','after-stores'))
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    with tempfile.TemporaryDirectory(prefix='fleetory-public-runtime-') as temporary:
        runtime = private_powershell(args.powershell, Path(temporary))
        result = subprocess.run([str(runtime), '-NoLogo','-NoProfile','-NonInteractive','-File',
            str(Path(__file__).with_name('NativeServerPair.Tests.ps1')), '-Python',sys.executable,
            '-Profile',args.profile,'-FailurePoint',args.failure_point,'-PrivateRuntimeChild'], cwd=repo,
            check=False)
        return result.returncode


if __name__ == '__main__':
    sys.exit(main())
