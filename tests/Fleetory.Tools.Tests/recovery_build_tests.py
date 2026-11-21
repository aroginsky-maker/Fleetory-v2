"""Synthetic code-context contracts, without Docker, networking or recovery materials."""
import gzip
import copy
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'eng/pilot'))
import recovery_build as build
import release_inputs_tests as fixtures

REPO = Path(__file__).resolve().parents[2]
SOURCE = {'server/Server.Dockerfile': 'infra/pilot/Server.Dockerfile',
          'signer/Dockerfile': 'infra/command-signer/Dockerfile',
          'signer/entrypoint.sh': 'infra/command-signer/entrypoint.sh',
          'signer/.dockerignore': 'infra/command-signer/.dockerignore'}


class RecoveryBuildTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.ReleaseInputsTests('test_wrong_archive_pin_is_rejected_without_contents')
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root = self.fixture.root
        self.members = [(name, (REPO / SOURCE[name]).read_bytes() if name in SOURCE else packet, kind)
                        for name, packet, kind in self.fixture.members]
        self.keycloak = (REPO / 'infra/pilot/Keycloak.Dockerfile').read_bytes()
        self.pin()

    def pin(self, members=None):
        self.fixture.pin(gzip.compress(self.fixture.tar(self.members if members is None else members)))

    def contexts(self):
        return build.contexts(self.root, self.fixture.name, self.fixture.digest, self.keycloak)

    def unpack(self, packet):
        result = {}
        with tarfile.open(fileobj=io.BytesIO(packet)) as reader:
            for member in reader:
                self.assertTrue(member.isfile())
                self.assertEqual((member.uid, member.gid, member.mtime), (0, 0, 0))
                self.assertEqual(member.mode, 0o555 if member.name == 'entrypoint.sh' else 0o444)
                self.assertFalse(member.pax_headers)
                self.assertNotIn(member.name, result)
                result[member.name] = reader.extractfile(member).read()
        return result

    def cli(self, extra=()):
        return subprocess.run([sys.executable, '-B', str(Path(build.__file__)), '--archive', self.fixture.name,
                               '--expected-sha256', self.fixture.digest, *extra],
                              capture_output=True, timeout=10, cwd=self.root)

    def test_contexts_contain_only_exact_role_inputs(self):
        inventory, packets = self.contexts()
        self.assertEqual(set(packets), {'server', 'signer', 'keycloak'})
        for role in ('server', 'signer'):
            expected = {name[len(role) + 1:] for name in inventory['files'] if name.startswith(role + '/')}
            if role == 'server':
                expected = (expected - {'Server.Dockerfile'}) | {'Dockerfile'}
            self.assertEqual(set(self.unpack(packets[role])), expected)
        self.assertEqual(self.unpack(packets['keycloak']), {'Dockerfile': self.keycloak.replace(b'\r\n', b'\n')})

    def test_all_copied_runtime_payload_bytes_are_preserved(self):
        _, packets = self.contexts()
        originals = {name: packet for name, packet, _ in self.members}
        for role in ('server', 'signer'):
            context = self.unpack(packets[role])
            for name, packet in context.items():
                if name.startswith('publish/') or name == 'entrypoint.sh':
                    self.assertEqual(packet, originals[role + '/' + name])

    def test_contexts_are_deterministic_even_if_archive_order_changes(self):
        _, first = self.contexts()
        self.pin(list(reversed(self.members)))
        _, second = self.contexts()
        self.assertEqual(first, second)

    def test_cli_is_read_only_content_free_and_does_not_invoke_docker(self):
        before = {str(p): p.read_bytes() for p in self.root.iterdir()}
        result = self.cli()
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        for field in ('dockerInvoked', 'servicesStarted', 'releaseSignatureVerified', 'sourceRevisionAuthenticated',
                      'fullSystemRecoveryVerified', 'phase7Complete'):
            self.assertIs(report[field], False)
        self.assertNotIn(b'private.synthetic.', result.stdout + result.stderr)
        self.assertEqual(before, {str(p): p.read_bytes() for p in self.root.iterdir()})
        for role, context in report['contexts'].items():
            packet = self.contexts()[1][role]
            self.assertEqual(context['bytes'], len(packet))
            self.assertEqual(context['sha256'], hashlib.sha256(packet).hexdigest())

    def test_rewritten_archive_pin_does_not_bypass_recipe_pins(self):
        for recipe in SOURCE:
            with self.subTest(recipe=recipe):
                self.pin([(name, packet + b'\n# unreviewed' if name == recipe else packet, kind)
                          for name, packet, kind in self.members])
                with self.assertRaises(Exception):
                    self.contexts()

    def test_changed_keycloak_recipe_is_refused(self):
        for packet in (self.keycloak + b'\nRUN curl unreviewed\n', b'FROM keycloak:latest', b''):
            self.keycloak = packet
            with self.assertRaises(Exception):
                self.contexts()

    def test_recipe_size_and_binary_type_are_bounded(self):
        for packet in (b'X' * 16385, 'not-bytes', bytearray(self.keycloak)):
            with self.assertRaises(Exception):
                build.recipe('keycloak/Dockerfile', packet)

    def test_line_ending_normalization_does_not_modify_copy_payload(self):
        changed = [(name, packet.replace(b'\r\n', b'\n').replace(b'\n', b'\r\n')
                    if name in SOURCE else packet, kind) for name, packet, kind in self.members]
        self.pin(changed)
        _, packets = self.contexts()
        for role in ('server', 'signer'):
            self.assertNotIn(b'\r\n', self.unpack(packets[role])['Dockerfile'])
        expected = next(packet for name, packet, _ in changed if name == 'signer/entrypoint.sh')
        self.assertEqual(self.unpack(packets['signer'])['entrypoint.sh'], expected)

    def test_wrong_pin_and_invalid_input_never_print_contents(self):
        self.fixture.digest = '0' * 64
        result = self.cli()
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, b'')
        self.assertNotIn(b'private.synthetic.', result.stderr)

    def test_unexpected_material_fails_before_context_generation(self):
        for name in ('server/publish/admin.key', 'signer/publish/token', '../outside', 'keycloak/private.conf'):
            self.pin(self.members + [(name, b'private.synthetic.secret', tarfile.REGTYPE)])
            with self.assertRaises(Exception):
                self.contexts()

    def test_missing_inputs_cannot_produce_partial_contexts(self):
        self.pin(self.members[1:])
        with self.assertRaises(Exception):
            self.contexts()

    def test_cli_cannot_select_root_recipe_destination_or_docker_host(self):
        for option in ('--root', '--recipe', '--destination', '--docker-host', '--build'):
            self.assertEqual(self.cli((option, 'unreviewed')).returncode, 2)

    def image_pair(self, role):
        base = {'id': 'sha256:' + 'a' * 64, 'os': 'linux', 'arch': 'amd64',
                'layers': ['sha256:' + 'b' * 64], 'volumes': None, 'ports': None,
                'user': 'upstream', 'workdir': '/', 'entrypoint': ['/upstream'],
                'cmd': ['/bin/bash'], 'env': ['PUBLIC_BASE=value']}
        image = copy.deepcopy(base)
        image['id'] = 'sha256:' + 'c' * 64
        image['layers'].append('sha256:' + 'd' * 64)
        if role == 'keycloak':
            image.update(user='1000:0')
            image['env'] += ['KC_DB=postgres', 'KC_HEALTH_ENABLED=true']
        else:
            image.update(user='1654', workdir='/app', cmd=None,
                         entrypoint=['dotnet', '/app/Fleetory.Server.dll'] if role == 'server' else ['/app/entrypoint.sh'])
            image['env'] += ['DOTNET_ENVIRONMENT=Production', 'DOTNET_EnableDiagnostics=0',
                             'ASPNETCORE_URLS=' if role == 'server' else 'ASPNETCORE_HTTP_PORTS=']
            if role == 'signer':
                image['ports'] = {'9443/tcp': {}}
        return image, base

    def test_fresh_image_metadata_accepts_only_reviewed_role_configuration(self):
        for role in build.BASES:
            image, base = self.image_pair(role)
            result = build.verify_image(role, image, base)
            self.assertIs(result['runtimeMetadataVerified'], True)
            self.assertIs(result['historicalSourceImageReproduced'], False)
            self.assertIs(result['fullSystemRecoveryVerified'], False)

    def test_child_entrypoint_clears_inherited_command(self):
        for role in ('server', 'signer'):
            image, base = self.image_pair(role)
            build.verify_image(role, image, base)
            image['cmd'] = base['cmd']
            with self.assertRaises(Exception):
                build.verify_image(role, image, base)

    def test_image_metadata_mutations_are_rejected(self):
        changes = {'os': 'windows', 'arch': 'arm64', 'id': 'mutable:tag',
                   'layers': ['sha256:' + 'e' * 64], 'volumes': {'/private': {}},
                   'user': '0', 'workdir': '/unreviewed', 'entrypoint': ['/bin/bash'],
                   'cmd': ['serve'], 'env': ['PUBLIC_BASE=value', 'PRIVATE_TOKEN=synthetic'],
                   'ports': {'12345/tcp': {}}}
        for role in build.BASES:
            for field, value in changes.items():
                with self.subTest(role=role, field=field):
                    image, base = self.image_pair(role)
                    image[field] = value
                    with self.assertRaises(Exception):
                        build.verify_image(role, image, base)

    def test_duplicate_malformed_and_missing_base_environment_are_rejected(self):
        for values in (['A=1', 'A=2'], ['missing-equals'], ['=empty-key'], None):
            with self.assertRaises(Exception):
                build.environment(values)


if __name__ == '__main__':
    unittest.main(verbosity=2)
