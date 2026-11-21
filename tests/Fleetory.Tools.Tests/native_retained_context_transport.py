"""Actual independent parent/retained controller context handoff; no Docker operations."""
import copy
import json
from pathlib import Path
import sys
import uuid
from unittest.mock import patch

from audit_probe_image_tests import BASE_VALUES
import audit_retained_context_transport as policy
from historical_audit_restore_tests import fixture

C,H,packet=policy.C,policy.H,policy.packet


def exercise(prepared):
    manifest=C(prepared.published['bundle'])
    outcomes=[];sources=policy.source_measurement(prepared.repository)
    paths={name:getattr(prepared,name) for name in ('python','powershell','git','dotnet')}
    pins={name:H(Path(path).read_bytes()) for name,path in paths.items()}
    with policy.bundle.HeldProbeBundle(prepared.root/'reference/publish',manifest,H(manifest)) as reference:
        descriptors={name:pin.fd for name,pin in reference.pins.items()}
        packet.require(len(descriptors)==58)
        for case in ('close','controller-death-after-offer'):
            plan,_=fixture();plan.update(nonce=str(uuid.uuid4()),revision=prepared.published['source']['revision'],
                codeSha256=prepared.published['source']['sha256'],probeBundleSha256=reference.value['sha256'],
                probeSha256=reference.entries['ServerBackendProbe.dll']['sha256'])
            operator=prepared.root/('context-parent-'+plan['nonce']);operator.mkdir(mode=0o700)
            raw=C(plan)
            with policy.RetainedContextTransport(prepared.repository,operator,raw,reference,copy.deepcopy(BASE_VALUES),
                    runtime_paths=paths,runtime_pins=pins,source_pins=sources) as controller:
                context=controller.context_bytes()
                packet.require(len(context)>0 and controller._offer['publicationDescriptorsHeld']==58)
                packet.require(descriptors=={name:pin.fd for name,pin in reference.pins.items()})
                if case!='close':
                    controller._fence.terminate()
                    try:controller.context_bytes()
                    except (OSError,ValueError):pass
                    else:raise ValueError('Dead retained controller remained usable.')
                    packet.require(policy.guard.identity.current_identity(controller._runtimes['python'])==controller._parent)
            result=controller.result()
            packet.require(result['gracefulDescriptorClosureVerified'] is (case=='close') and
                result['controllerDeathObserved'] is (case!='close') and result['parentAliveAfterControllerExit'] is True and
                result['publicationDescriptorsHeld']==58 and result['contextSha256']==H(context))
            before={p.name:H(p.read_bytes()) for p in operator.iterdir()}
            with patch.object(policy.process,'_spawn') as spawn:
                try:policy.RetainedContextTransport(prepared.repository,operator,raw,reference,copy.deepcopy(BASE_VALUES),
                    runtime_paths=paths,runtime_pins=pins,source_pins=sources)
                except OSError:pass
                else:raise ValueError('Consumed controller transport restarted.')
                spawn.assert_not_called()
            packet.require(before=={p.name:H(p.read_bytes()) for p in operator.iterdir()})
            outcomes.append(dict(case=case,result=result,parentReference58Unchanged=True,restartRefusedBeforeSpawn=True))
        reference.check()
    return dict(schema='fleetory.actual-retained-context-transport.v1',verified=True,cases=outcomes,sourcePins=sources,
        actualRetainedNativeControllers=2,sourceRevision=prepared.published['source']['revision'],sourceFilesPinned=len(sources),
        parentOwnsControllerFence=True,independentParentReferenceUsed=True,wireImageOrContainerIdsAccepted=False,
        dockerOperationsPerformed=0,retainedControllerDeathCleanupVerified=False,originalInputsRead=False,originalPrivatePkiUsed=False,
        sourceVpsAccessed=False,fullSystemRecoveryVerified=False,phase7Complete=False)


def run():
    from native_publication_faults import reference_fixture
    with reference_fixture() as prepared:result=exercise(prepared)
    result['ownPublicFixtureDisposed']=True
    return result


if __name__=='__main__':
    packet.require(len(sys.argv)==1)
    print('ACTUAL RETAINED CONTEXT TRANSPORT PASS: '+json.dumps(run(),sort_keys=True))
