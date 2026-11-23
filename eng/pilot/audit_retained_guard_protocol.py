"""Fixed retained guardian handoff. Child performs typed bindings, never Docker or cleanup."""
from contextlib import ExitStack
import os
import sys
import threading
import time

import audit_retained_context_transport as context
import audit_retained_runtime as retained

packet,C,H=context.packet,context.C,context.H
runtime,container=retained.runtime,retained.container
MAX_FRAME=32768
HEADER='fleetory.retained-guardian-header.v1'


def _tag(schema,header,offer):
    return dict(schema=schema,headerSha256=H(header),nonce=offer['nonce'],contextSha256=offer['contextSha256'])


def image_frame(header,offer,image,copy_resource,readback):
    return dict(_tag('fleetory.retained-guardian-image.v1',header,offer),imageId=image['id'],
        imageObservationBase64=context.encode(image['observation']),copyId=copy_resource['id'],
        copyObservationBase64=context.encode(copy_resource['projection']),readbackBytes=len(readback),readbackSha256=H(readback))


def runtime_frame(header,offer,intent,resource):
    return dict(_tag('fleetory.retained-guardian-observation.v1',header,offer),runtimeIntentSha256=H(C(intent)),
        containerId=resource['id'],observationBase64=context.encode(resource['observation']))


def _image_record(raw,intent,observation,identifier,opened,now):
    value=packet.strict_json(raw,8192)
    _,created=context.probe.ProbeImageBinding._observe(observation,intent,identifier,now)
    observed=value.get('observedAtNs')
    packet.require(type(observed) is int and opened<=observed<=now<intent['expiresNs'])
    expected=dict(schema='fleetory.audit-probe-image-binding.v1',nonce=intent['nonce'],reservationSha256=intent['controlSha256'],
        intentSha256=H(C(intent)),imageId=identifier,definitionSha256=intent['definitionSha256'],contextSha256=intent['contextSha256'],
        bundleManifestSha256=intent['bundleManifestSha256'],bundleSha256=intent['bundleSha256'],sourceCodeSha256=intent['sourceCodeSha256'],
        probeSha256=intent['probeSha256'],createdNs=created,observedAtNs=observed,observationSha256=H(observation),cleanupAuthorized=False)
    packet.require(raw==C(expected)+b'\n')
    return expected


def _preparation(intent,offer,declared,pins):
    source={key:intent[key] for key in runtime.SOURCE_FIELDS+retained.EXTRA_FIELDS}
    guard=context.guard
    return dict(schema='fleetory.retained-guard-preparation.v1',purpose='retained-publication-guardian-preparation.v1',
        status='PREPARED_NO_DISPATCH',nonce=intent['nonce'],revision=intent['revision'],controller=declared['controller'],
        reservationSha256=intent['controlSha256'],runtimeIntentSha256=H(C(intent)),frozenRuntimeIntentSha256=H(C(intent)),
        lineage=source,publicationDescriptorsHeld=offer['publicationDescriptorsHeld'],
        sourcePinsSha256=H(C({n:pins[n] for n in guard.SOURCES})),sourceFilesPinned=len(guard.SOURCES),
        pythonSha256=declared['runtimes']['python'],dockerSha256=declared['runtimes']['docker'],admissionExpiresNs=intent['expiresNs'],
        actualPreparingControllerIdentityVerified=True,exactUnboundRetainedSourceChecked=True,publicationAndReadbackCapabilitiesHeld=True,
        localPreparationAttemptFlushed=True,preparationReplayRefusedWhileRecordRetained=True,guardianProcessStarted=False,
        ownDockerCreateReceiptAvailable=False,dockerOperationsPerformed=0,launchAuthorized=False,cleanupAuthorized=False,
        retainedControllerDeathCleanupVerified=False,retainedExpiryCleanupVerified=False,publicationOriginAuthenticated=False,
        dependenciesAuthenticated=False,independentRollbackResistanceVerified=False,originalInputsRead=False,originalPrivatePkiUsed=False,
        sourceVpsAccessed=False,fullSystemRecoveryVerified=False,phase7Complete=False)


def admit_runtime(raw,header,offer,facts,reference,now):
    """Compare child metadata with the parent's independently owned RPC replies/reference."""
    value=packet.strict_json(raw,MAX_FRAME)
    packet.keys(value,'schema headerSha256 nonce contextSha256 runtimeIntentBase64 imageBindingBase64 readbackBase64 preparation '
        'publicationDescriptorsHeld heldDescriptorsSha256 childDockerOperationsPerformed')
    packet.require({k:value[k] for k in _tag('',header,offer)}==_tag('fleetory.retained-guardian-runtime.v1',header,offer))
    packet.require(value['publicationDescriptorsHeld']==offer['publicationDescriptorsHeld'] and type(value['publicationDescriptorsHeld']) is int and
        value['heldDescriptorsSha256']==offer['heldDescriptorsSha256'] and value['childDockerOperationsPerformed']==0 and
        type(value['childDockerOperationsPerformed']) is int)
    declared,plan,_,_=context._header(header)
    image_intent=packet.strict_json(packet.decode(offer['imageIntentBase64'],context.probe.image.MAX_INTENT),context.probe.image.MAX_INTENT)
    image_raw=packet.decode(value['imageBindingBase64'],8192)
    _image_record(image_raw,image_intent,facts['imageObservation'],facts['imageId'],facts['imageObservedNs'],now)
    checked=context.bundle.verify_readback(facts['readback'],reference)
    readback=dict(schema='fleetory.publication-continuation-readback.v1',nonce=offer['nonce'],
        continuationSha256=offer['publicationBindingSha256'],imageBindingSha256=H(image_raw),imageId=facts['imageId'],containerId=facts['copyId'],
        stoppedObservationSha256=H(facts['copyProjection']),readbackSha256=H(facts['readback']),bundleManifestSha256=reference.pin,
        files=checked['files'],bytes=checked['bytes'],operationalLeaseAuthorized=False,backendCleanupAuthorized=False)
    readback_raw=packet.decode(value['readbackBase64'],8192);packet.require(readback_raw==C(readback)+b'\n')
    source=dict(imageId=facts['imageId'],imageBindingSha256=H(image_raw),imageIntentSha256=H(C(image_intent)),
        bundleManifestSha256=reference.pin,sourceCodeSha256=plan['codeSha256'],runtimeProfileSha256=runtime.PROFILE_SHA256,
        publicationContinuationSha256=offer['publicationBindingSha256'],publicationReadbackSha256=H(readback_raw),
        heldDescriptorsSha256=offer['heldDescriptorsSha256'],runtimeCodeSha256=H(C({n:declared['sourcePins'][n] for n in retained.EXTRA_SOURCES})))
    raw_intent=packet.decode(value['runtimeIntentBase64'],container.MAX_INTENT);intent=packet.strict_json(raw_intent,container.MAX_INTENT)
    opened=intent.get('openedNs');packet.require(type(opened) is int and facts['imageObservedNs']<=opened<=now)
    labels=dict(image_intent['labels'],**{'fleetory.audit.control.profile':retained.PURPOSE,
        'fleetory.audit.control.image.binding':source['imageBindingSha256'],'fleetory.audit.control.runtime.profile':runtime.PROFILE_SHA256,
        'fleetory.audit.control.publication':source['publicationContinuationSha256'],'fleetory.audit.control.runtime.code':source['runtimeCodeSha256']})
    expected=dict(schema=retained.SCHEMA,purpose=retained.PURPOSE,nonce=offer['nonce'],revision=plan['revision'],
        controlSha256=offer['reservationSha256'],image=facts['imageId'],**source,name=runtime.name(offer['nonce']),labels=labels,
        openedNs=opened,expiresNs=min(image_intent['expiresNs'],offer['retainedExpiresNs']))
    packet.require(raw_intent==C(expected) and now<expected['expiresNs'] and runtime.runtime_profile()==runtime.PROFILE)
    packet.require(C(value['preparation'])==C(_preparation(expected,offer,declared,declared['sourcePins'])))
    return expected


def admit_bound(raw,header,offer,intent,resource,now):
    value=packet.strict_json(raw,MAX_FRAME)
    packet.keys(value,'schema headerSha256 nonce contextSha256 backendBindingBase64 publicationDescriptorsHeld '
        'heldDescriptorsSha256 preparationHeldThroughCreateReply preparationClosedBeforeObservation childDockerOperationsPerformed')
    packet.require({k:value[k] for k in _tag('',header,offer)}==_tag('fleetory.retained-guardian-bound.v1',header,offer))
    packet.require(value['publicationDescriptorsHeld']==offer['publicationDescriptorsHeld'] and type(value['publicationDescriptorsHeld']) is int and
        value['heldDescriptorsSha256']==offer['heldDescriptorsSha256'] and value['preparationHeldThroughCreateReply'] is True and
        value['preparationClosedBeforeObservation'] is True and type(value['childDockerOperationsPerformed']) is int and value['childDockerOperationsPerformed']==0)
    raw_binding=packet.decode(value['backendBindingBase64'],8192);binding=packet.strict_json(raw_binding,8192)
    _,created=runtime._observe_runtime(resource['observation'],intent,resource['id'],now,retained.OBSERVATION_SCHEMA)
    observed=binding.get('observedAtNs');packet.require(type(observed) is int and resource['finishedNs']<=observed<=now<intent['expiresNs'])
    expected=dict(schema='fleetory.retained-probe-runtime-binding.v1',nonce=intent['nonce'],reservationSha256=intent['controlSha256'],
        intentSha256=H(C(intent)),containerId=resource['id'],name='/'+intent['name'],createdNs=created,
        observedAtNs=observed,observationSha256=H(resource['observation']),cleanupAuthorized=False,
        **{k:intent[k] for k in runtime.SOURCE_FIELDS+retained.EXTRA_FIELDS})
    packet.require(raw_binding==C(expected)+b'\n')
    return H(raw_binding)


def _read_exact(count):
    value=bytearray()
    while len(value)<count:
        chunk=os.read(sys.stdin.fileno(),min(65536,count-len(value)));packet.require(bool(chunk));value.extend(chunk)
    return bytes(value)


def _read_message(box):
    try:
        size=context.frame_size(_read_exact(4),MAX_FRAME);raw=_read_exact(size);value=packet.strict_json(raw,MAX_FRAME)
        count=value.get('readbackBytes',0);packet.require(type(count) is int and 0<=count<=context.bundle.MAX_CONTEXT)
        box['value'],box['payload']=value,_read_exact(count)
    except Exception:box['error']=True
    finally:box['done']=True


def _receive(source,parent,nonce,pin):
    box={'done':False};threading.Thread(target=_read_message,args=(box,),daemon=True).start()
    while not box['done']:
        source.check();packet.require(parent.snapshot()['state']=='live');time.sleep(0.05)
    packet.require(not box.get('error'));source.check()
    if box['value']==context.close_request(nonce,pin):
        packet.require(not box['payload']);return None
    return box['value'],box['payload']


def serve(source,image,parent,session,repository,runtimes,root,header,offer,descriptors,write):
    """Fixed two binding stages and cancellation at each stage; no Docker calls in the child."""
    nonce,pin=offer['nonce'],offer['contextSha256']
    request=_receive(source,parent,nonce,pin)
    if request is None:return
    value,archive=request
    packet.keys(value,'schema headerSha256 nonce contextSha256 imageId imageObservationBase64 copyId copyObservationBase64 readbackBytes readbackSha256')
    packet.require({k:value[k] for k in _tag('',header,offer)}==_tag('fleetory.retained-guardian-image.v1',header,offer) and
        value['readbackBytes']==len(archive) and value['readbackSha256']==H(archive))
    image.bind(packet.decode(value['imageObservationBase64'],container.MAX_OBSERVATION),value['imageId'])
    source.complete(image,value['copyId'],packet.decode(value['copyObservationBase64'],container.MAX_OBSERVATION),archive)
    with ExitStack() as held:
        pins=retained.measure_sources(image);raw=retained.prepare(session,image,pins)
        target=held.enter_context(retained.RetainedRuntimeBinding(session,raw,H(raw),image,source_pins=pins))
        operator=root/'guardian-preparation';operator.mkdir(mode=0o700,exist_ok=False)
        selected={n:context._header(header)[0]['sourcePins'][n] for n in context.guard.SOURCES}
        prepared=held.enter_context(retained.RetainedGuardPreparation(session,target,operator,
            python_path=sys.executable,python_sha256=context._header(header)[0]['runtimes']['python'],
            docker_path=runtimes['docker'].path,docker_sha256=runtimes['docker'].digest,source_pins=selected))
        report=prepared.report();packet.require(len(descriptors)==report['publicationDescriptorsHeld'])
        reply=dict(_tag('fleetory.retained-guardian-runtime.v1',header,offer),runtimeIntentBase64=context.encode(C(target.intent)),
            imageBindingBase64=context.encode(session._records['image-binding.json'][1]),
            readbackBase64=context.encode(session._records['publication-continuation-readback.json'][1]),preparation=report,
            publicationDescriptorsHeld=len(descriptors),heldDescriptorsSha256=report['lineage']['heldDescriptorsSha256'],childDockerOperationsPerformed=0)
        write(context.frame(reply,MAX_FRAME))
        request=_receive(source,parent,nonce,pin)
        if request is None:return
        value,payload=request;packet.require(not payload)
        packet.keys(value,'schema headerSha256 nonce contextSha256 runtimeIntentSha256 containerId observationBase64')
        packet.require({k:value[k] for k in _tag('',header,offer)}==_tag('fleetory.retained-guardian-observation.v1',header,offer) and value['runtimeIntentSha256']==H(raw))
        prepared.check();prepared.close()
        target.bind(packet.decode(value['observationBase64'],container.MAX_OBSERVATION),value['containerId'])
        packet.require(descriptors=={n:p.fd for n,p in source._bundle.pins.items()})
        reply=dict(_tag('fleetory.retained-guardian-bound.v1',header,offer),backendBindingBase64=context.encode(session._records['backend-binding.json'][1]),
            publicationDescriptorsHeld=len(descriptors),heldDescriptorsSha256=source.descriptor_pin,
            preparationHeldThroughCreateReply=True,preparationClosedBeforeObservation=True,childDockerOperationsPerformed=0)
        write(context.frame(reply,MAX_FRAME))
        packet.require(_receive(source,parent,nonce,pin) is None)


if __name__=='__main__':raise SystemExit('Fixed public retained guardian handoff library; no command, Docker, service or secret CLI.')
