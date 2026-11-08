"""Actual generated probe-image runtime and kernel observations; sleep/public scratch only."""
import json
import re

from audit_probe_runtime_tests import policy, packet, container
from native_audit_resource_binding import NativeBinding, FIELDS
from native_probe_image import run as build_probe

FIELDS = dict(FIELDS, environment='.Config.Env', ulimits='.HostConfig.Ulimits')
FORMAT = '{"schema":"' + policy.OBSERVATION_SCHEMA + '",' + ','.join(
    json.dumps(k) + ':{{json ' + v + '}}' for k, v in FIELDS.items()) + '}'
SCRATCH = '''set -eu
for d in /data /tmp; do
  f="$d/fleetory-public-runtime-check"
  printf '#!/bin/sh\nexit 0\n' > "$f"
  chmod 700 "$f"
  set +e
  "$f" >/dev/null 2>&1
  code=$?
  set -e
  [ "$code" -eq 126 ] || exit 7
  stat -c '%a:%u:%g:%h' "$f"
  rm "$f"
done
'''


def mount_size(options):
    values = [v[5:] for v in options if v.startswith('size=')]
    packet.require(len(values) == 1)
    found = re.fullmatch(r'([0-9]+)([kmg]?)', values[0])
    packet.require(found is not None)
    return int(found[1]) * {'':1, 'k':1024, 'm':1024**2, 'g':1024**3}[found[2]]


class RuntimeFixture(NativeBinding):
    def arguments(self, intent):
        args = ['run', '-d', '--pull=never', '--name', intent['name'], '--rm', '--network=none', '--read-only',
            '--user=3322:3322', '--cap-drop=ALL', '--security-opt=no-new-privileges:true', '--memory=384m',
            '--cpus=1', '--pids-limit=128', '--restart=no', '--ulimit=core=0:0', '--entrypoint=/bin/sh']
        for path, value in policy.TMPFS.items():args.extend(['--tmpfs', path + ':' + value])
        return args

    def source_reference(self, intent):
        container.image_id(intent['image'])
        return intent['image']

    def command(self, intent):
        return policy.COMMAND

    def observed(self, identifier):
        packet.require(type(identifier) is str and re.fullmatch('[a-f0-9]{64}', identifier))
        return packet.strict_json(self.call(['container', 'inspect', '--format', FORMAT, identifier]), container.MAX_OBSERVATION)

    def kernel(self, identifier):
        status = self.call(['exec', identifier, '/bin/cat', '/proc/1/status']).decode('ascii')
        fields = {row.split(':', 1)[0]:row.split(':', 1)[1].strip() for row in status.splitlines() if ':' in row}
        packet.require(fields['Name'] == 'sleep')
        packet.require(fields['Uid'].split() == ['3322'] * 4 and fields['Gid'].split() == ['3322'] * 4)
        packet.require(all(int(fields[n], 16) == 0 for n in ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb')))
        packet.require(fields['NoNewPrivs'] == '1' and fields['Seccomp'] == '2')
        rows = self.call(['exec', identifier, '/bin/cat', '/proc/mounts']).decode('ascii').splitlines()
        selected = {row.split()[1]:set(row.split()[3].split(',')) for row in rows if row.split()[1] in ('/', '/data', '/tmp')}
        packet.require(set(selected) == {'/', '/data', '/tmp'} and 'ro' in selected['/'])
        for path, size in (('/data', 256 * 1024**2), ('/tmp', 32 * 1024**2)):
            options = selected[path]
            packet.require({'rw', 'noexec', 'nosuid', 'nodev', 'uid=3322', 'gid=3322', 'mode=700'} <= options and mount_size(options) == size)
        interfaces = self.call(['exec', identifier, '/bin/cat', '/proc/net/dev']).decode('ascii')
        packet.require([r.split(':')[0].strip() for r in interfaces.splitlines() if ':' in r] == ['lo'])
        routes = self.call(['exec', identifier, '/bin/cat', '/proc/net/route']).decode('ascii').splitlines()[1:]
        packet.require(not any(r.split()[1] == '00000000' for r in routes if r.split()))
        checked = self.call(['exec', identifier, '/bin/sh', '-c', SCRATCH]).decode('ascii').splitlines()
        packet.require(checked == ['700:3322:3322:1', '700:3322:3322:1'])
        return dict(pidOneSleepObserved=True, uidGidVerified=True, allCapabilitySetsZero=True, noNewPrivilegesVerified=True, seccompFilterObserved=True,
            rootReadonlyObserved=True, bothTmpfsFlagsSizesOwnersModesVerified=True, publicScratchWritableAndRemoved=True,
            bothTmpfsDirectExecutionDenied=True, onlyLoopbackObserved=True, noDefaultRouteObserved=True)

    def __call__(self, session, source, fresh_session):
        raw = policy.prepare(session, source)
        target = policy.ProbeRuntimeBinding(session, raw, packet.digest(raw), source)
        image_record = session._records['image-binding.json'][1]
        try:
            identifier = self.create(target.intent)
            first = self.observed(identifier)
            report = target.bind(container.canonical(first), identifier)
            packet.require(report['generatedProbeRuntimeBound'] is True and first['configImage'] == first['imageId'] == source.report()['imageId'])
            kernel = self.kernel(identifier)
            denied = False
            try:target.bind(container.canonical(first), identifier)
            except ValueError:denied = True
            packet.require(denied)
            foreign = fresh_session()
            denied = False
            try:policy.ProbeRuntimeBinding(foreign, raw, packet.digest(raw), source)
            except ValueError:denied = True
            packet.require(denied and 'backend-attempt.json' in foreign._records and 'backend-intent.json' not in foreign._records)
            packet.require(self.observed(identifier) == first and session._records['image-binding.json'][1] == image_record)
            packet.require(target.intent['expiresNs'] == source.intent['expiresNs'])
            record = json.loads(session._records['backend-binding.json'][1])
            packet.require(record['imageBindingSha256'] == packet.digest(image_record) and record['schema'] == 'fleetory.audit-probe-runtime-binding.v1')
            for name in ('executionAuthorized', 'cleanupAuthorized', 'backendCleanupAuthorized', 'backendServiceStartedVerified',
                    'actualProbeNativeOwnerAcknowledged', 'operationalLeaseAuthorized', 'fullSystemRecoveryVerified', 'phase7Complete'):
                packet.require(report[name] is False)
        finally:
            self.cleanup()
        source.report()  # Successful disposal must still be inside the image admission lease.
        packet.require(len(self.receipts) == 1 and self.listed_id(self.receipts[0][0]) == [])
        return dict(schema='fleetory.generated-native-probe-runtime.v1', verified=True, **kernel,
            imageAndConfigImageImmutable=True, imageRecordIntentAndManifestMatched=True, sameHeldControllerVerified=True,
            sharedAdmissionExpiryVerified=True, cleanupBeforeAdmissionExpiry=True, runtimeProfileSha256=policy.PROFILE_SHA256, consumedObservationReplayRefused=True,
            foreignControllerRefused=True, foreignAttemptConsumed=True, sourceImageRecordPreserved=True,
            runtimeMetadataUnchangedAfterScratch=True, createdSleepWorkers=1, backendServicesStarted=0,
            ownedSleepWorkersAbsent=True, fixtureCleanupFromOwnCreateReceiptOnly=True, commandLifetimeSeconds=660,
            operationalLeaseAuthorized=False, runtimeContinuityVerified=False, actualProbeNativeOwnerAcknowledged=False,
            backendCleanupAuthorized=False, abruptOwnerDeathBackendCleanupVerified=False, originalInputsRead=False,
            originalPrivatePkiUsed=False, sourceVpsAccessed=False, fullSystemRecoveryVerified=False, phase7Complete=False)


def run():
    result = build_probe(runtime_check=RuntimeFixture())
    runtime = result.pop('runtimeObservation')
    return dict(schema='fleetory.generated-native-probe-runtime-pair.v1', verified=True,
        imageAndStoppedCopy=result, runtime=runtime, totalCreatedContainers=2, backendServicesStarted=0,
        freshPublicImageRequiredForSameHeldSource=True, actualProbeNativeOwnerAcknowledged=False,
        backendCleanupAuthorized=False, abruptOwnerDeathBackendCleanupVerified=False, originalInputsRead=False,
        originalPrivatePkiUsed=False, sourceVpsAccessed=False, fullSystemRecoveryVerified=False, phase7Complete=False)


if __name__ == '__main__':
    print('NATIVE PROBE RUNTIME PASS: ' + json.dumps(run(), sort_keys=True))
