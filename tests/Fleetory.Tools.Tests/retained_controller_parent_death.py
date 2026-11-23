from pathlib import Path
import argparse,json,os,subprocess,sys
parser=argparse.ArgumentParser(allow_abbrev=False)
parser.add_argument('--repository',required=True)
parser.add_argument('--powershell',required=True)
parser.add_argument('--parent',action='store_true')
args=parser.parse_args()
if args.parent:
    child=subprocess.Popen([args.powershell,'-NoProfile','-NonInteractive','-File',str(Path(__file__).with_name('RetainedControllerParentProbe.ps1')),
        '-Repository',args.repository,'-Python',str(Path(sys.executable).resolve())],stdin=subprocess.PIPE)
    # Root kills this actual process; owner stdout remains connected directly to root.
    sys.stdin.buffer.read(1)
    raise RuntimeError('Unexpected live parent input')
parent=subprocess.Popen([sys.executable,str(Path(__file__).resolve()),'--parent','--repository',args.repository,'--powershell',args.powershell],
    stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
try:
    arm=json.loads(parent.stdout.readline())
    assert arm['controllerPid']==parent.pid and arm['ownerPid']!=parent.pid
    assert parent.poll() is None
    parent.kill();parent.wait(timeout=5)
    assert parent.returncode!=0
    result=json.loads(parent.stdout.readline())
    assert result['schema']=='fleetory.parent-death-observation-diagnostic.v1'
    assert result['early']['lossObserved'] and result['late']['lossObserved']
    assert result['heldParentWaitReturned'] and result['late']['parentExited']
    assert result['early']['lossKind']==result['late']['lossKind']
    assert not result['nativeResourcesCreated']
    print(json.dumps(dict(actualParentExitCode=parent.returncode,diagnostic=result)))
    assert not parent.stderr.read(), 'Unexpected child diagnostics'
finally:
    if parent.poll() is None:parent.kill();parent.wait(timeout=5)
    parent.stdin.close();parent.stdout.close();parent.stderr.close()
