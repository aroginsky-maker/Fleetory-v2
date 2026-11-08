"""Actual generated sleep worker tied to the still-held native publication/image; no backend service."""
import json

import audit_retained_runtime as policy
from native_probe_runtime import RuntimeFixture, FORMAT

packet, C, H = policy.packet, policy.container.canonical, policy.packet.digest


class RetainedRuntimeFixture(RuntimeFixture):
    def observed(self, identifier):
        packet.require(type(identifier) is str and len(identifier)==64 and all(c in '0123456789abcdef' for c in identifier))
        template=FORMAT.replace(policy.runtime.OBSERVATION_SCHEMA,policy.OBSERVATION_SCHEMA)
        return packet.strict_json(self.call(['container','inspect','--format',template,identifier]),policy.container.MAX_OBSERVATION)

    def verify(self, session, source):
        sources=policy.measure_sources(source);raw=policy.prepare(session,source,sources)
        image_record=session._records['image-binding.json'][1]
        readback_record=session._records['publication-continuation-readback.json'][1]
        with policy.RetainedRuntimeBinding(session,raw,H(raw),source,source_pins=sources) as target:
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
            runtime=report,record=record,intent=target.intent,selectedAdditionalSourcePins=sources,
            sameControllerPublicationImageReadbackVerified=True,same58DescriptorsStillHeld=True,
            admissionIsMinimumOfBothDeadlines=True,consumedRuntimeObservationReplayRefused=True,closedRuntimeUseRefused=True,
            imageAndReadbackRecordsPreserved=True,ownSleepWorkerAbsent=True,cleanupBeforeAdmissionExpiry=True,
            createdSleepWorkers=1,backendServicesStarted=0,commandLifetimeSeconds=660,
            operationalLeaseAuthorized=False,liveServiceLeaseAuthorized=False,controllerDeathCleanupVerified=False,
            backendCleanupAuthorized=False,originalInputsRead=False,originalPrivatePkiUsed=False,sourceVpsAccessed=False,
            fullSystemRecoveryVerified=False,phase7Complete=False)
