"""Actual generated sleep worker tied to the still-held native publication/image; no backend service."""
import json
from pathlib import Path
import shutil
import sys

import audit_retained_runtime as policy
from native_probe_runtime import RuntimeFixture, FORMAT

packet, C, H = policy.packet, policy.container.canonical, policy.packet.digest


class RetainedRuntimeFixture(RuntimeFixture):
    def observed(self, identifier):
        packet.require(type(identifier) is str and len(identifier)==64 and all(c in '0123456789abcdef' for c in identifier))
        template=FORMAT.replace(policy.runtime.OBSERVATION_SCHEMA,policy.OBSERVATION_SCHEMA)
        return packet.strict_json(self.call(['container','inspect','--format',template,identifier]),policy.container.MAX_OBSERVATION)

    def prepare_guardian(self,session,target):
        import audit_public_cleanup_guard as guard
        retained=target._source._continuation
        root=retained._delivery.root.path
        operator=session._parent.path/('retained-guard-preparation-'+session._plan['nonce'])
        operator.mkdir(mode=0o700,exist_ok=False)
        python=Path(sys.executable).resolve(strict=True)
        docker=Path(shutil.which('docker') or '').resolve(strict=True)
        sources={name:H((root/name).read_bytes()) for name in guard.SOURCES}
        descriptors={name:pin.fd for name,pin in retained._bundle.pins.items()}
        with policy.RetainedGuardPreparation(session,target,operator,python_path=python,python_sha256=H(python.read_bytes()),
                docker_path=docker,docker_sha256=H(docker.read_bytes()),source_pins=sources) as prepared:
            report=prepared.report()
            packet.require(report['publicationDescriptorsHeld']==len(descriptors)==58 and
                report['controller']['pid']==guard.os.getpid() and report['actualPreparingControllerIdentityVerified'] is True and
                report['sourceFilesPinned']==len(guard.SOURCES)==61 and report['sourcePinsSha256']==H(C(sources)))
            packet.require(report['lineage']['heldDescriptorsSha256']==retained.descriptor_pin and
                descriptors=={name:pin.fd for name,pin in retained._bundle.pins.items()})
        packet.require(target.report()['observationAttemptConsumed'] is False)
        retained.check()
        return dict(report=report,sourcePins=sources,same58DescriptorsHeld=True,observationSlotUnconsumed=True,
            actualNativePublicationAndReadbackUsed=True,guardianProcessStarted=False,dockerOperationsPerformed=0)

    def verify(self, session, source):
        sources=policy.measure_sources(source);raw=policy.prepare(session,source,sources)
        image_record=session._records['image-binding.json'][1]
        readback_record=session._records['publication-continuation-readback.json'][1]
        with policy.RetainedRuntimeBinding(session,raw,H(raw),source,source_pins=sources) as target:
            preparation=self.prepare_guardian(session,target)
            try:
                identifier=self.create(target.intent);observed=self.observed(identifier)
                report=target.bind(C(observed),identifier)
                packet.require(report['retainedPublicationSleepRuntimeBound'] is True and report['additionalRuntimeSourcesHeld']==4)
                kernel=self.kernel(identifier)
                replay=False
                try:target.bind(C(observed),identifier)
                except ValueError:replay=True
                packet.require(replay and self.observed(identifier)==observed and
                    session._records['image-binding.json'][1]==image_record and
                    session._records['publication-continuation-readback.json'][1]==readback_record)
                record=json.loads(session._records['backend-binding.json'][1])
                packet.require(record['schema']=='fleetory.retained-probe-runtime-binding.v1' and
                    record['publicationReadbackSha256']==H(readback_record) and
                    record['imageBindingSha256']==H(image_record) and
                    target.intent['expiresNs']==min(source.intent['expiresNs'],source._continuation.expires))
                for key in ('operationalLeaseAuthorized','liveServiceLeaseAuthorized','executionAuthorized','cleanupAuthorized',
                        'backendCleanupAuthorized','backendServiceStartedVerified','controllerDeathCleanupVerified','fullSystemRecoveryVerified','phase7Complete'):
                    packet.require(report[key] is False)
            finally:self.cleanup()
            target.report();source.report()
            packet.require(len(self.receipts)==1 and self.listed_id(identifier)==[])
        denied=False
        try:target.report()
        except ValueError:denied=True
        packet.require(denied)
        return dict(schema='fleetory.generated-retained-sleep-runtime.v1',verified=True,**kernel,
            runtime=report,record=record,intent=target.intent,selectedAdditionalSourcePins=sources,guardianPreparation=preparation,
            sameControllerPublicationImageReadbackVerified=True,same58DescriptorsStillHeld=True,
            admissionIsMinimumOfBothDeadlines=True,consumedRuntimeObservationReplayRefused=True,closedRuntimeUseRefused=True,
            imageAndReadbackRecordsPreserved=True,ownSleepWorkerAbsent=True,cleanupBeforeAdmissionExpiry=True,
            createdSleepWorkers=1,backendServicesStarted=0,commandLifetimeSeconds=660,
            operationalLeaseAuthorized=False,liveServiceLeaseAuthorized=False,controllerDeathCleanupVerified=False,
            backendCleanupAuthorized=False,originalInputsRead=False,originalPrivatePkiUsed=False,sourceVpsAccessed=False,
            fullSystemRecoveryVerified=False,phase7Complete=False)
