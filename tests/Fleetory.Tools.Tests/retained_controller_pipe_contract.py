from pathlib import Path
import argparse, hashlib, json, os, subprocess, sys, threading, queue

parser=argparse.ArgumentParser(allow_abbrev=False)
parser.add_argument('--repository',required=True)
parser.add_argument('--powershell',required=True)
args=parser.parse_args()
repo=Path(args.repository).resolve()
probe=Path(__file__).with_name('RetainedControllerPipeProbe.ps1')
helper=repo/'eng/pilot/historical/RetainedControllerPipe.ps1'
pin=hashlib.sha256(helper.read_bytes()).hexdigest()
environment={key:value for key,value in os.environ.items() if key.upper() in (
    'PATH','SYSTEMROOT','WINDIR','HOME','USERPROFILE','APPDATA','LOCALAPPDATA','PROGRAMDATA','TEMP','TMP','TMPDIR',
    'XDG_CONFIG_HOME','XDG_CACHE_HOME','XDG_DATA_HOME')}
results=[]
for case in ('alive','eof','byte'):
    process=subprocess.Popen([args.powershell,'-NoLogo','-NoProfile','-NonInteractive','-File',str(probe),
        '-Repository',str(repo),'-Python',str(Path(sys.executable).resolve()),'-Case',case],
        stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=environment)
    lines=queue.Queue()
    reader=threading.Thread(target=lambda:lines.put(process.stdout.readline()),daemon=True)
    reader.start()
    try:
        first=lines.get(timeout=20)
        if not first:
            process.wait(timeout=5)
            raise RuntimeError('Owner probe ended before arm: '+process.stderr.read(4096).decode(errors='replace'))
        arm=json.loads(first)
        assert arm['schema']=='fleetory.native-owner-controller-arm.v1'
        assert arm['controllerPid']==os.getpid() and arm['ownerPid']==process.pid and not arm['cleanupAuthorized']
        assert arm['faultPoint']=='after-targets' and arm['nativeClientPid']==0 and arm['nativeClientBirth'] is None
        assert arm['controllerImageSha256']==hashlib.sha256(Path(sys.executable).resolve().read_bytes()).hexdigest()
        if case=='eof':
            process.stdin.close();process.stdin=None
        elif case=='byte':
            process.stdin.write(b'x');process.stdin.flush()
        # Do not close stdin for alive: owner shutdown itself must complete while the controller remains live.
        process.wait(timeout=10)
        output=process.stdout.read();errors=process.stderr.read()
        assert process.returncode==0 and not errors,(process.returncode,errors.decode(errors='replace')[:1200])
        result=json.loads(output)
        snapshot=result['snapshot']
        assert result['schema']=='fleetory.controller-pipe-contract.v1' and result['refusals']==7
        assert not snapshot['parentExited'] and not snapshot['controllerOriginAuthenticated']
        assert not snapshot['cleanupAuthorized'] and not snapshot['controllerDeathCleanupVerified']
        assert not result['nativeResourcesCreated'] and not result['cleanupVerified']
        assert snapshot['lossObserved']==(case!='alive')
        assert snapshot['lossKind']=={'alive':None,'eof':'input-closed','byte':'unexpected-input'}[case]
        results.append(result)
    finally:
        if process.poll() is None:
            process.kill();process.wait(timeout=5)
        if process.stdin is not None:process.stdin.close()
        process.stdout.close();process.stderr.close()
assert hashlib.sha256(helper.read_bytes()).hexdigest()==pin
print(json.dumps(dict(schema='fleetory.controller-pipe-contract-results.v1',cases=len(results),refusals=21,
    helperSha256=pin,nativeResourcesCreated=False,controllerDeathCleanupVerified=False)))
