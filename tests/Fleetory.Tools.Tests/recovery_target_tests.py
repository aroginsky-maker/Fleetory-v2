"""Portable target model/metadata contracts; no real images, Docker or secret material."""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'eng/pilot'))
import recovery_target as target


class TargetTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='fleetory-target-contract-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.images = {**target.PUBLIC, **{role: 'sha256:' + str(i) * 64
                        for i, role in enumerate(sorted(target.CUSTOM), 1)}}
        self.project = target.PREFIX + 'a' * 32
        self.model = target.render(self.project, self.images)
        self.pin()

    def pin(self):
        packet = json.dumps({'schema': 'fleetory.recovery-target-images.v1', 'images': self.images}).encode()
        (self.root / 'images.json').write_bytes(packet)
        self.pin_hash = hashlib.sha256(packet).hexdigest()

    def cli(self, extra=(), packet=None):
        return subprocess.run([sys.executable, '-B', str(Path(target.__file__)), '--images', 'images.json',
                               '--expected-images-sha256', self.pin_hash, *extra],
                              input=packet, cwd=self.root, capture_output=True, timeout=10)

    def refuse(self, model):
        with self.assertRaises(Exception):
            target.validate(model, self.images)

    def test_cli_render_and_validate_are_read_only(self):
        before = (self.root / 'images.json').read_bytes()
        result = self.cli(('--project', self.project))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), self.model)
        verified = self.cli(('--validate',), result.stdout)
        self.assertEqual(verified.returncode, 0, verified.stderr)
        report = json.loads(verified.stdout)
        self.assertTrue(report['creationOnly'])
        for field in ('applicationsStarted', 'sourceMaterialLoaded', 'fullSystemRecoveryVerified', 'phase7Complete'):
            self.assertIs(report[field], False)
        self.assertEqual(before, (self.root / 'images.json').read_bytes())
        self.assertEqual(len(list(self.root.iterdir())), 1)

    def test_image_manifest_pin_cannot_be_rebaselined(self):
        self.images['server'] = 'sha256:' + 'd' * 64
        previous = self.pin_hash
        self.pin()
        self.pin_hash = previous
        self.assertEqual(self.cli().returncode, 1)

    def test_role_image_set_is_complete_pinned_and_unique(self):
        for role in self.images:
            changed = dict(self.images)
            changed[role] = 'mutable:latest'
            with self.assertRaises(Exception):
                target.validate_images(changed)
        changed = dict(self.images, server=self.images['signer'])
        with self.assertRaises(Exception):
            target.validate_images(changed)
        changed.pop('server')
        with self.assertRaises(Exception):
            target.validate_images(changed)

    def test_project_cannot_select_live_or_invalid_namespace(self):
        for name in ('fleetory-pilot', '', '../target', target.PREFIX + 'A' * 32, self.project + '\n'):
            model = copy.deepcopy(self.model)
            model['name'] = name
            self.refuse(model)
        self.assertEqual(self.cli(('--project', '')).returncode, 1)

    def test_extra_root_material_and_roles_are_rejected(self):
        for key in ('include', 'volumes', 'secrets', 'configs', 'x-target'):
            self.refuse(dict(self.model, **{key: {}}))
        model = copy.deepcopy(self.model)
        model['services']['agent'] = copy.deepcopy(model['services']['server'])
        self.refuse(model)

    def test_service_overrides_mounts_ports_and_credentials_are_rejected(self):
        for role in self.images:
            for field, value in {'network_mode': 'host', 'ports': ['127.0.0.1:1234:1234'],
                                 'volumes': ['/live:/run/secrets'], 'env_file': ['private.env'],
                                 'environment': {'TOKEN': 'private.synthetic'}, 'entrypoint': ['sh'],
                                 'command': ['serve'], 'build': '.', 'devices': ['/dev/null'],
                                 'extra_hosts': ['source:host-gateway'], 'dns': ['1.1.1.1'],
                                 'post_start': [{'command': 'serve'}], 'use_api_socket': True}.items():
                model = copy.deepcopy(self.model)
                model['services'][role][field] = value
                self.refuse(model)

    def test_reviewed_service_settings_cannot_be_weakened(self):
        for field, value in {'image': self.images['signer'], 'pull_policy': 'always', 'user': '0:0',
                             'read_only': False, 'cap_drop': [], 'security_opt': [], 'restart': 'always',
                             'healthcheck': {'disable': False}, 'mem_limit': '2g', 'cpus': 1,
                             'pids_limit': 1000, 'tmpfs': []}.items():
            model = copy.deepcopy(self.model)
            model['services']['server'][field] = value
            self.refuse(model)

    def test_bool_integer_and_near_decimal_substitutions_are_rejected(self):
        for field, value in (('pids_limit', True), ('pids_limit', 64.0), ('cpus', '0.25'), ('read_only', 1)):
            model = copy.deepcopy(self.model)
            model['services']['server'][field] = value
            self.refuse(model)
        packet = json.dumps(self.model).encode()
        changed = packet.replace(b'0.25', b'0.2500000000000000000001', 1)
        self.assertEqual(self.cli(('--validate',), changed).returncode, 1)

    def test_networks_and_memberships_are_exact_and_internal(self):
        for field, value in {'internal': False, 'enable_ipv6': True, 'external': True,
                             'driver': 'host', 'name': 'live_net', 'ipam': {}}.items():
            model = copy.deepcopy(self.model)
            model['networks']['app_net'][field] = value
            self.refuse(model)
        model = copy.deepcopy(self.model)
        model['services']['server']['networks'].append('signer_net')
        self.refuse(model)

    def test_labels_and_postgres_volume_override_cannot_be_reparented(self):
        for change in ('service', 'network', 'postgres'):
            model = copy.deepcopy(self.model)
            if change == 'service':
                model['services']['server']['labels'][target.SESSION] = 'b' * 32
            elif change == 'network':
                model['networks']['app_net']['labels'][target.SESSION] = 'b' * 32
            else:
                model['services']['postgres']['tmpfs'] = [target.TEMP]
            self.refuse(model)

    def test_cli_stdin_is_bounded_strict_and_content_free(self):
        packet = json.dumps(self.model).encode()
        for invalid in (b'', b'\xff', b' ' * (target.MAX_INPUT + 1),
                        packet.replace(b'"name":', b'"name":"private.synthetic","name":', 1),
                        packet.replace(b'0.25', b'NaN', 1)):
            result = self.cli(('--validate',), invalid)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stdout, b'')
            self.assertNotIn(b'private.synthetic', result.stderr)

    def test_cli_cannot_override_root_or_validation_namespace(self):
        self.assertEqual(self.cli(('--root', str(self.root))).returncode, 2)
        self.assertEqual(self.cli(('--validate', '--project', self.project), json.dumps(self.model).encode()).returncode, 1)

    def test_compose_environment_ignores_files_profiles_and_overrides(self):
        source = {'PATH': 'unchanged', 'COMPOSE_FILE': 'live.yaml', 'COMPOSE_ENV_FILES': 'private.env',
                  'COMPOSE_PROFILES': 'signer-approved', 'COMPOSE_DISABLE_ENV_FILE': '0'}
        result = target.compose_environment(source)
        self.assertEqual(result, {'PATH': 'unchanged', 'COMPOSE_DISABLE_ENV_FILE': '1'})
        self.assertEqual(source['COMPOSE_DISABLE_ENV_FILE'], '0')

    def metadata(self, role):
        service = self.model['services'][role]
        image = {'id': 'sha256:' + 'f' * 64, 'entrypoint': ['/image-entrypoint'], 'command': ['image-command'],
                 'volumes': {'/var/lib/postgresql': {}} if role == 'postgres' else None}
        state = {'Status': 'created', 'Running': False, 'StartedAt': '0001-01-01T00:00:00Z',
                 'FinishedAt': '0001-01-01T00:00:00Z'}
        host = {'ReadonlyRootfs': True, 'Privileged': False, 'CapDrop': ['ALL'], 'CapAdd': None,
                'SecurityOpt': ['no-new-privileges:true'], 'PortBindings': {}, 'Binds': None, 'VolumesFrom': None,
                'Memory': int(target.MEMORY[role][:-1]) * 1024 * 1024, 'NanoCpus': 250000000, 'PidsLimit': 64,
                'Tmpfs': dict(value.split(':', 1) for value in service['tmpfs']),
                'NetworkMode': self.project + '_' + service['networks'][0],
                'PidMode': '', 'UTSMode': '', 'UsernsMode': '', 'IpcMode': 'private'}
        container = {'name': '/' + self.project + '-' + role + '-1',
                     'labels': {**service['labels'], 'com.docker.compose.project': self.project},
                     'state': state, 'restartCount': 0, 'imageReference': service['image'], 'imageId': image['id'],
                     'entrypoint': image['entrypoint'], 'command': image['command'], 'user': service['user'],
                     'healthcheck': {'Test': ['NONE']}, 'host': host, 'mounts': [],
                     'networks': {self.project + '_' + name: {} for name in service['networks']}}
        return service, container, image

    def test_never_started_metadata_of_all_eight_roles_is_accepted(self):
        for role in self.images:
            target.verify_created(role, *self.metadata(role), self.project)

    def test_any_start_restart_or_command_override_is_rejected(self):
        for field, value in (('Status', 'running'), ('Running', True), ('StartedAt', '2026-11-03T00:00:00Z')):
            service, container, image = self.metadata('server')
            container['state'][field] = value
            with self.assertRaises(Exception):
                target.verify_created('server', service, container, image, self.project)
        for field, value in {'restartCount': 1, 'entrypoint': ['sh'], 'command': ['changed'],
                             'imageId': 'sha256:' + 'e' * 64, 'user': '0', 'networks': {'bridge': {}}}.items():
            service, container, image = self.metadata('server')
            container[field] = value
            with self.assertRaises(Exception):
                target.verify_created('server', service, container, image, self.project)

    def test_host_bind_privilege_and_volume_leaks_are_rejected(self):
        changes = {'ReadonlyRootfs': False, 'Privileged': True, 'CapDrop': [], 'CapAdd': ['NET_ADMIN'],
                   'SecurityOpt': [], 'PortBindings': {'80/tcp': [{'HostPort': '80'}]},
                   'Binds': ['/live:/data'], 'VolumesFrom': ['live'], 'Memory': 0,
                   'NanoCpus': 0, 'PidsLimit': 0, 'Tmpfs': {}, 'NetworkMode': 'host',
                   'PidMode': 'host', 'UTSMode': 'host', 'UsernsMode': 'host', 'IpcMode': 'host'}
        for field, value in changes.items():
            service, container, image = self.metadata('postgres')
            container['host'][field] = value
            with self.assertRaises(Exception):
                target.verify_created('postgres', service, container, image, self.project)
        for mount in ({'Type': 'volume', 'Destination': '/var/lib/postgresql'},
                      {'Type': 'bind', 'Destination': '/tmp'}, {'Type': 'tmpfs', 'Destination': '/unknown'}):
            service, container, image = self.metadata('postgres')
            container['mounts'] = [mount]
            with self.assertRaises(Exception):
                target.verify_created('postgres', service, container, image, self.project)

    def test_unreviewed_image_volume_and_wrong_owner_are_rejected(self):
        service, container, image = self.metadata('postgres')
        image['volumes']['/unreviewed'] = {}
        with self.assertRaises(Exception):
            target.verify_created('postgres', service, container, image, self.project)
        service, container, image = self.metadata('postgres')
        container['labels'][target.SESSION] = 'b' * 32
        with self.assertRaises(Exception):
            target.verify_created('postgres', service, container, image, self.project)


if __name__ == '__main__':
    unittest.main(verbosity=2)
