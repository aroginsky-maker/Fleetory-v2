"""Three actual private-peer cases on generated inputs; no native recovery or originals."""
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile

from private_runtime_fixture import private_powershell
from run_retained_service_peer_prototype import main as run_case


def exercise(runtime):
    proofs=[]
    for options in ({},{'fault':True},{'code_drift':True}):
        output=io.StringIO()
        with contextlib.redirect_stdout(output):
            result=run_case(str(runtime),original=True,**options)
        if result:
            sys.stderr.write(output.getvalue()[-4096:])
            return result
        proof=json.loads(output.getvalue())
        assert proof['verified'] and proof['actualChildExitVerified']
        assert not proof['nativeTargetInvoked'] and not proof['originalInputsRead']
        proofs.append(proof)
    assert proofs[0]['packets']==4 and proofs[0]['statusChecks']==2
    assert proofs[0]['originalPurpose'] and proofs[0]['copiedOrReplacedPeersRejected']==3
    assert proofs[1]['originalPurpose'] and proofs[1]['childExitCode']==37 and proofs[1]['deadPeerRejected']
    assert proofs[2]['typedCodeRefusalBeforeNativeTarget']
    print(json.dumps(dict(schema='fleetory.generated-original-four-private-peer.v1',verified=True,cases=proofs,
        nativeTargetInvoked=False,originalInputsRead=False,executionAuthorized=False,phase7Complete=False)))
    return 0


def main():
    assert len(sys.argv)==2
    if sys.platform=='linux':
        with tempfile.TemporaryDirectory(prefix='fleetory-original-peer-runtime-') as temporary:
            return exercise(private_powershell(sys.argv[1],Path(temporary)))
    return exercise(sys.argv[1])


if __name__=='__main__':sys.exit(main())
