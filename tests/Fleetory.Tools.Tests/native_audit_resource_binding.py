"""Two fresh empty local containers and three generated control sessions. No original data."""
from contextlib import ExitStack
import json
from pathlib import Path
import re
import tempfile
import uuid
from unittest.mock import patch

from audit_backend_binding_tests import binding, control, control_plan
from recovery_isolation_tests import DockerRehearsal

FIELDS = dict(id='.Id', name='.Name', imageId='.Image', created='.Created', labels='.Config.Labels',
    configImage='.Config.Image', user='.Config.User', entrypoint='.Config.Entrypoint', command='.Config.Cmd',
    running='.State.Running', paused='.State.Paused', restarting='.State.Restarting', dead='.State.Dead',
    networkMode='.HostConfig.NetworkMode', networks='.NetworkSettings.Networks', readonly='.HostConfig.ReadonlyRootfs',
    privileged='.HostConfig.Privileged', capDrop='.HostConfig.CapDrop', capAdd='(index .HostConfig "CapAdd")',
    securityOpt='.HostConfig.SecurityOpt', memory='.HostConfig.Memory', nanoCpus='.HostConfig.NanoCpus',
    pidsLimit='.HostConfig.PidsLimit', mounts='.Mounts', ports='(index .NetworkSettings "Ports")',
    portBindings='(index .HostConfig "PortBindings")', binds='(index .HostConfig "Binds")', tmpfs='(index .HostConfig "Tmpfs")',
    volumesFrom='(index .HostConfig "VolumesFrom")', devices='(index .HostConfig "Devices")', deviceRequests='(index .HostConfig "DeviceRequests")',
    pidMode='.HostConfig.PidMode', ipcMode='.HostConfig.IpcMode', utsMode='.HostConfig.UTSMode',
    usernsMode='.HostConfig.UsernsMode', restart='.HostConfig.RestartPolicy', autoRemove='.HostConfig.AutoRemove',
    publishAllPorts='.HostConfig.PublishAllPorts')
FORMAT = '{"schema":"fleetory.audit-generated-container-observation.v1",' + ','.join(
    json.dumps(name) + ':{{json ' + path + '}}' for name, path in FIELDS.items()) + '}'


class NativeBinding(DockerRehearsal):
    def __init__(self):
        super().__init__()
        self.receipts = []

    def observed(self, identifier):
        binding.packet.require(type(identifier) is str and re.fullmatch('[a-f0-9]{64}', identifier))
        data = self.call(['container', 'inspect', '--format', FORMAT, identifier])
        return binding.packet.strict_json(data, binding.MAX_OBSERVATION)

    def listed_id(self, identifier):
        return self.call(['container', 'ls', '-a', '--no-trunc', '--filter', 'id=' + identifier, '--format', '{{.ID}}']).decode().split()

    def cleanup_identity(self, identifier):
        template = '{"id":{{json .Id}},"name":{{json .Name}},"labels":{{json .Config.Labels}},"imageId":{{json .Image}}}'
        return binding.packet.strict_json(self.call(['container', 'inspect', '--format', template, identifier]), binding.MAX_OBSERVATION)

    def create(self, intent):
        existing = self.call(['container', 'ls', '-a', '--no-trunc', '--filter', 'name=^/' + intent['name'] + '$', '--format', '{{.ID}}'])
        binding.packet.require(not existing.strip())
        args = ['run', '-d', '--pull=never', '--name', intent['name'], '--rm', '--network=none', '--read-only',
            '--user=65534:65534', '--cap-drop=ALL', '--security-opt=no-new-privileges:true', '--memory=64m',
            '--cpus=0.25', '--pids-limit=32', '--restart=no', '--entrypoint=python']
        for name, value in intent['labels'].items():
            args.extend(['--label', name + '=' + value])
        identifier = self.call(args + [binding.IMAGE, *binding.COMMAND]).decode().strip()
        binding.packet.require(re.fullmatch('[a-f0-9]{64}', identifier))
        self.receipts.append((identifier, intent))
        return identifier

    def cleanup(self):
        # Fixture authority is its own successful Docker create receipt, not the metadata gate.
        for identifier, intent in reversed(self.receipts):
            present = self.listed_id(identifier)
            if present:
                binding.packet.require(present == [identifier])
                observed = self.cleanup_identity(identifier)
                binding.packet.require(observed['id'] == identifier and observed['name'] == '/' + intent['name'] and
                    observed['labels'] == intent['labels'] and observed['imageId'] == intent['imageId'])
                self.call(['container', 'rm', '-f', identifier])
            binding.packet.require(self.listed_id(identifier) == [])

    def run(self):
        version = self.preflight()
        expected_image = self.call(['image', 'inspect', '--format', '{{.Id}}', binding.IMAGE]).decode().strip()
        binding.image_id(expected_image)
        with tempfile.TemporaryDirectory(prefix='fleetory-native-bound-resource-') as temp, ExitStack() as stack:
            root = Path(temp).resolve()

            def reserve():
                plan = control_plan(str(uuid.uuid4()))
                encoded = binding.canonical(plan)
                session = stack.enter_context(control.claim(root, encoded, binding.packet.digest(encoded)))
                data = binding.prepare(session, expected_image)
                return session, binding.ContainerBinding(session, data, binding.packet.digest(data))

            try:
                _, sentinel = reserve()
                foreign_id = self.create(sentinel.intent)
                before = self.observed(foreign_id)
                _, target = reserve()
                target_id = self.create(target.intent)
                result = target.bind(binding.canonical(self.observed(target_id)), target_id)
                binding.packet.require(result['generatedContainerIdBound'] is True and result['containerId'] == target_id)
                refused_session, refused = reserve()
                denied = False
                try:
                    refused.bind(binding.canonical(self.observed(foreign_id)), foreign_id)
                except ValueError:
                    denied = True
                binding.packet.require(denied and refused.report()['generatedContainerIdBound'] is False)
                binding.packet.require((refused_session._directory.path / 'backend-binding-attempt.json').is_file() and
                    not (refused_session._directory.path / 'backend-binding.json').exists())
                binding.packet.require(self.observed(foreign_id) == before and self.listed_id(target_id) == [target_id])
                proof = dict(schema='fleetory.generated-native-resource-binding.v1', verified=True, dockerVersion=version,
                    createdEmptyContainers=2, controllerIntents=3, acceptedIdBindings=1, foreignObservationRefused=True,
                    refusedObservationAttemptConsumed=True, sentinelPreserved=True, selectedInspectFieldsOnly=True,
                    privateInputsReleased=False, originalInputsRead=False, originalPrivatePkiUsed=False,
                    legacyNativeOwnerIntegrated=False, dockerObservationAuthenticated=False, abruptOwnerDeathCleanupVerified=False,
                    backendCleanupAuthorized=False, fullSystemRecoveryVerified=False, phase7Complete=False)
            finally:
                self.cleanup()
        proof['ownedContainersAbsent'] = True
        return proof


def verify_failure_cleanup():
    client = NativeBinding()
    refused = False
    with patch.object(client, 'observed', side_effect=RuntimeError('generated inspect refusal')):
        try:
            client.run()
        except RuntimeError as error:
            binding.packet.require(str(error) == 'generated inspect refusal')
            refused = True
    binding.packet.require(refused and len(client.receipts) == 1 and client.listed_id(client.receipts[0][0]) == [])


if __name__ == '__main__':
    result = NativeBinding().run()
    verify_failure_cleanup()
    result.update(observationFailureCleanupVerified=True, observationFailureContainersRemoved=1)
    print('AUDIT RESOURCE DOCKER PASS: ' + json.dumps(result, sort_keys=True))
