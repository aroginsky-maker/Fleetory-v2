"""Generated four-file fixture and actual PowerShell parent; transport stage, not native recovery."""
import base64
import json
from pathlib import Path
import shutil
import subprocess
import sys
import uuid

import retained_service_use_tests as fixture


def main(powershell, fault=False, code_drift=False, original=False):
    test = fixture.ServiceUseTests('runTest')
    test.setUp()
    generated = None
    try:
        if fault:
            artifacts = Path(__file__).resolve().parents[2]/'artifacts'
            artifacts.mkdir(exist_ok=True)
            generated = artifacts/('native-pair-'+str(uuid.uuid4()))
            generated.mkdir(mode=0o700)
        offline = generated/'retained-inputs' if fault else test.root/'offline'
        offline.mkdir(mode=0o700)
        references = [entry['path'] for entry in test.fixture.record['selected']] + [test.fixture.source.relative]
        for relative in references:
            target = offline/relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(test.root/relative, target)
        source = test.fixture.source
        source.root, source.path = offline, offline/source.relative
        source.checkpoint['artifactPath'] = str(source.path)
        source.pin()
        test.fixture.record['metadataPins']['manifest'] = source.pins['manifest']
        test.fixture.pin()
        metadata = dict(selection=test.fixture.raw, **source.metadata,
                        ci=test.metadata['ci'], local=test.metadata['local'])
        commitments = {name:test.plan[name] for name in
                       ('nonce','revision','imageId','probeSha256','configurationSha256')}
        request=dict(metadata={n:base64.b64encode(v).decode('ascii') for n,v in metadata.items()},
                     commitments=commitments)
        if original:
            from historical import original_four_use as policy
            selected,_=policy.legacy.inputs.selection.decode_report(metadata['selection'],policy.H(metadata['selection']))
            export=policy.legacy.inputs.expectations.source_plan({n:metadata[n] for n in ('manifest','checkpoint')},
                {n:policy.H(metadata[n]) for n in ('manifest','checkpoint')})
            request['expected']=dict(root=str(offline.resolve()),
                artifacts={v.kind:dict(path=v.path,bytes=v.bytes,sha256=v.sha256) for v in (*selected.artifacts,export.artifact)},
                revision=commitments['revision'],imageId=commitments['imageId'],probeSha256=commitments['probeSha256'],
                configurationSha256=commitments['configurationSha256'],executionInventorySha256='7'*64,
                policySha256=policy.H(Path(policy.__file__).read_bytes()))
        (offline/'generated-peer-metadata.json').write_text(json.dumps(request),encoding='utf-8')
        script = Path(__file__).with_name('RetainedServicePeerPrototype.Tests.ps1')
        args = [powershell,'-NoLogo','-NoProfile','-NonInteractive','-File',str(script),
                '-Python',sys.executable,'-InputRoot',str(offline)]
        if original:
            args.append('-OriginalPurpose')
        if fault:
            args.append('-ExitAfterRelease')
        if code_drift:
            args.append('-InjectCodeName')
        result = subprocess.run(args,capture_output=True,text=True,timeout=125,
                                **({'creationflags':subprocess.CREATE_NO_WINDOW} if sys.platform=='win32' else {}))
        if result.returncode:
            print(result.stdout)
            print(result.stderr,file=sys.stderr)
            return result.returncode
        proof = [json.loads(line) for line in result.stdout.splitlines()]
        assert len(proof)==1 and proof[0]['verified'] and not proof[0]['nativeTargetInvoked']
        print(json.dumps(proof[0],sort_keys=True))
        return 0
    finally:
        if generated is not None:
            assert generated.parent == Path(__file__).resolve().parents[2]/'artifacts'
            shutil.rmtree(generated)
        test.doCleanups()


if __name__=='__main__':
    sys.exit(main(sys.argv[1], fault='--exit-after-release' in sys.argv[2:], code_drift='--code-drift' in sys.argv[2:], original='--original-purpose' in sys.argv[2:]))
