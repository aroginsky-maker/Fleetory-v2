"""Actual retained native publication, optionally through a fixed public Docker image and stopped readback."""
import copy
import json
import os
import uuid

import audit_publication_continuation as policy
from audit_probe_image_tests import BASE_VALUES
from historical_audit_restore_tests import fixture
from native_audit_preparation import claim_plan, sha
from native_probe_image import ProbeBuild, bounded_docker, STOP_FORMAT

packet, C, H = policy.packet, policy.prep.canonical, policy.packet.digest


def exercise(repository, root, powershell, python, git, dotnet, published, *, with_image):
    packet.require(type(with_image) is bool)
    client, bases, version = None, copy.deepcopy(BASE_VALUES), None
    if with_image:
        client = ProbeBuild();version = client.metadata.preflight();bases = []
        for reference in policy.probe.BASES:
            try:value = client.base(reference)
            except RuntimeError:
                client.metadata.call(['pull','--quiet',reference],timeout=120);value = client.base(reference)
            bases.append(value)
        policy.probe.bases(bases)
    plan, _ = fixture()
    plan.update(nonce=str(uuid.uuid4()), revision=published['source']['revision'], codeSha256=published['source']['sha256'],
        probeBundleSha256=published['bundle']['sha256'],
        probeSha256=next(e['sha256'] for e in published['bundle']['entries'] if e['path']=='ServerBackendProbe.dll'))
    raw, claimed = claim_plan(root, plan, powershell, python)
    pins = policy.measure_sources(repository);resource = None;readback = None
    try:
        with claimed as session:
            with policy.retain_owner(repository,powershell,python,git,dotnet,raw,pins,session,
                    git_sha256=sha(git),dotnet_sha256=sha(dotnet),manifest=C(published['bundle'])) as retained:
                before = {name:pin.fd for name,pin in retained._bundle.pins.items()}
                packet.require(len(before)==58 and retained.native_result['fence']['noRunningMembersVerified'] is True)
                resource = retained.image(bases);context = resource.build_bytes()
                packet.require(H(context)==resource.intent['contextSha256'])
                duplicate = False
                try:retained.image(bases)
                except ValueError:duplicate = True
                packet.require(duplicate)
                if with_image:
                    identifier = client.build(resource)
                    resource.bind(C(client.observed(identifier)),identifier)
                    stored = client.create(identifier,resource.intent)
                    observation = client.metadata.call(['container','inspect','--format',STOP_FORMAT,stored])
                    copied = bounded_docker(['cp',stored+':/tool/.','-'],limit=policy.ns.bundle.MAX_CONTEXT)
                    readback = retained.complete(resource,stored,observation,copied)
                    client.stopped(stored,identifier,resource.intent)
                retained.check()
                packet.require(before=={name:pin.fd for name,pin in retained._bundle.pins.items()})
                packet.require(policy.measure_sources(repository)==pins)
                report = retained.report();native = retained.native_result
                records = {n:json.loads(session._records[n][1]) for n in session._records if n.startswith('publication-continuation-')}
                descriptor_states = [os.fstat(fd) for fd in before.values()]
                packet.require(all(state.st_size>0 for state in descriptor_states))
            closed = False
            try:resource.build_bytes()
            except ValueError:closed = True
            packet.require(closed)
            for fd in before.values():
                try:os.fstat(fd)
                except OSError:pass
                else:raise AssertionError('A transferred publication descriptor survived close.')
            packet.require((repository/'artifacts'/policy.ns.name(plan['nonce'])).is_dir())
    finally:
        if client is not None:
            client.cleanup()
            packet.require([client.base(reference) for reference in policy.probe.BASES]==bases)
    return dict(schema='fleetory.generated-publication-continuation.v1', verified=True,
        revision=published['source']['revision'], native=native, continuation=report, records=records,
        same58DescriptorsHeldThroughContext=True, contextSha256=resource.intent['contextSha256'], contextBytes=len(context),
        nativeOwnerExitedBeforeImageIntent=True, consumedContinuationReplayRefused=duplicate, closedImageUseRefused=closed,
        allTransferredDescriptorsClosed=True, namespacePreservedUntilFixtureDisposal=True,
        actualDockerImageAndStoppedReadbackVerified=with_image, readback=readback, dockerVersion=version,
        ownStoppedContainersAbsent=with_image, ownImageReceiptIdsAbsent=with_image, cachedBasesPreserved=with_image,
        containersCreated=1 if with_image else 0, servicesStarted=0, selectedSourceFilesPinned=len(pins),
        controllerDeathCleanupVerified=False, operationalLeaseAuthorized=False, backendCleanupAuthorized=False,
        compilerClosureAuthenticated=False, originalInputsRead=False, originalPrivatePkiUsed=False, sourceVpsAccessed=False,
        fullSystemRecoveryVerified=False, phase7Complete=False)
