"""Synthetic isolation contracts and an opt-in owned local Docker rehearsal."""
import copy
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import unittest
import uuid
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / 'eng/pilot'))
import recovery_isolation as isolation


class ContractTests(unittest.TestCase):
    rejected = 0

    def setUp(self):
        self.project = isolation.PREFIX + uuid.uuid4().hex
        self.model = isolation.render(self.project)

    def refuse(self, change):
        candidate = copy.deepcopy(self.model)
        change(candidate)
        with self.assertRaises(isolation.archive.ArchiveError):
            isolation.validate(candidate)
        ContractTests.rejected += 1

    def cli(self, args, data=None):
        return subprocess.run([sys.executable, '-B', str(Path(isolation.__file__)), *args],
                              input=data, capture_output=True, timeout=5)

    def test_generated_profile_and_read_only_cli_validation(self):
        result = self.cli(['--project', self.project])
        self.assertEqual(result.returncode, 0, result.stderr)
        model = json.loads(result.stdout)
        self.assertEqual(model, self.model)
        result = self.cli(['--validate'], result.stdout)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual((report['services'], report['internalNetworks']), (8, 3))
        for key in ('realRecoveryStarted','fullSystemRecoveryVerified','independentCustodyVerified','phase7Complete'):
            self.assertIs(report[key], False)

    def test_project_cannot_select_production_or_another_namespace(self):
        for project in ('fleetory-pilot', 'TUX', '', isolation.PREFIX + '0' * 31,
                        isolation.PREFIX + 'A' * 32, isolation.PREFIX + '0' * 32 + '\n', '../project'):
            self.refuse(lambda m: m.update(name=project))
        self.assertEqual(self.cli(['--project','fleetory-pilot']).returncode, 1)

    def test_root_includes_external_material_are_rejected(self):
        for field in ('volumes','secrets','configs','include','extensions','x-probe'):
            self.refuse(lambda m: m.update({field:{}}))

    def test_service_set_is_complete_and_closed(self):
        self.refuse(lambda m: m['services'].pop('openbao'))
        self.refuse(lambda m: m['services'].update(realAgent=copy.deepcopy(m['services']['server'])))

    def test_host_network_is_rejected_for_every_role(self):
        for role in isolation.MEMBERS:
            self.refuse(lambda m: m['services'][role].update(network_mode='host'))

    def test_even_loopback_port_publication_is_rejected(self):
        for role in isolation.MEMBERS:
            for value in (['18080:18080'], ['127.0.0.1:18080:18080']):
                self.refuse(lambda m: m['services'][role].update(ports=value))

    def test_mounts_and_host_namespace_delegation_are_rejected(self):
        for field, value in {'volumes':['/srv/live:/run/secrets:ro'], 'volumes_from':['live'],
                             'configs':[], 'secrets':[], 'pid':'host','ipc':'host','userns_mode':'host',
                             'use_api_socket':True,'devices':['/dev/null'],'runtime':'custom',
                             'post_start':[{'command':'changed'}],'deploy':{},'build':'.'}.items():
            self.refuse(lambda m: m['services']['server'].update({field:value}))

    def test_real_images_and_changed_entrypoints_are_rejected(self):
        self.refuse(lambda m: m['services']['signer'].update(image='fleetory-command-signer:live'))
        self.refuse(lambda m: m['services']['server'].update(entrypoint=['sh','-c']))
        self.refuse(lambda m: m['services']['server'].update(command=['python','-c','print("changed")']))
        self.refuse(lambda m: m['services']['server']['command'].__setitem__(-1,'signer'))

    def test_privilege_and_mutability_are_rejected(self):
        for field, value in {'privileged':True,'cap_add':['NET_ADMIN'],'cap_drop':[],
                             'read_only':False,'security_opt':[],'user':'0:0','restart':'always'}.items():
            self.refuse(lambda m: m['services']['signer'].update({field:value}))

    def test_secret_or_resolver_injection_is_rejected(self):
        for field in ('environment','env_file','dns','extra_hosts','links','profiles','provider'):
            self.refuse(lambda m: m['services']['server'].update({field:[]}))

    def test_networks_are_exact_internal_isolated_bridges(self):
        for field, value in {'internal':False,'enable_ipv6':True,'driver':'host',
                             'external':True,'name':'fleetory-pilot_app_net','ipam':{}}.items():
            self.refuse(lambda m: m['networks']['app_net'].update({field:value}))
        self.refuse(lambda m: m['networks']['app_net']['driver_opts'].update({isolation.GATEWAY_OPTION:'nat'}))
        self.refuse(lambda m: m['networks']['app_net']['driver_opts'].update(unreviewed='true'))
        self.refuse(lambda m: m['networks'].pop('audit_net'))
        self.refuse(lambda m: m['networks'].update(default=isolation.network('0'*32)))

    def test_roles_cannot_join_unreviewed_segments(self):
        self.refuse(lambda m: m['services']['server']['networks'].append('signer_net'))
        self.refuse(lambda m: m['services']['signer'].update(networks=['app_net']))
        self.refuse(lambda m: m['services']['postgres'].update(networks=['app_net']))
        self.refuse(lambda m: m['services']['server']['networks'].append('app_net'))
        self.refuse(lambda m: m['services']['server'].update(networks={'app_net':{}}))

    def test_session_and_role_labels_cannot_be_reparented(self):
        self.refuse(lambda m: m['services']['server']['labels'].update({isolation.SESSION:'0'*32}))
        self.refuse(lambda m: m['services']['server']['labels'].update({isolation.ROLE:'signer'}))
        self.refuse(lambda m: m['networks']['app_net']['labels'].update({isolation.SESSION:'0'*32}))
        self.refuse(lambda m: m['services']['server']['labels'].update(extra='unreviewed'))

    def test_limits_and_boolean_fields_are_typed(self):
        for field, value in {'cpus':'0.25','pids_limit':True,'mem_limit':'2g','read_only':'true'}.items():
            self.refuse(lambda m: m['services']['server'].update({field:value}))
        self.refuse(lambda m: m['networks']['app_net'].update(internal='true'))

    def test_strict_bounded_stdin_and_content_free_errors(self):
        packet = json.dumps(self.model).encode()
        candidates = [b'', b'\xff', b' '* (isolation.MAX_MODEL+1), b'['+packet+b']',
                      packet.replace(b'"name":',b'"name":"private.synthetic.marker","name":',1),
                      packet.replace(b'0.25',b'NaN',1)]
        for candidate in candidates:
            result = self.cli(['--validate'], candidate)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stdout, b'')
            self.assertNotIn(b'private.synthetic.marker', result.stderr)

    def test_validation_cannot_override_namespace(self):
        result = self.cli(['--validate','--project',self.project],json.dumps(self.model).encode())
        self.assertEqual(result.returncode, 1)

    def test_equivalent_member_and_property_order_is_accepted(self):
        self.model['services']['postgres']['networks'].reverse()
        self.model['services'] = dict(reversed(list(self.model['services'].items())))
        self.assertEqual(isolation.validate(self.model)['services'], 8)

    def test_specific_trust_domains_preserve_restricted_connections(self):
        def shared(left, right):
            return bool(set(self.model['services'][left]['networks']) & set(self.model['services'][right]['networks']))
        for left,right in [('server','signer'),('server','openbao'),('server','audit-store'),
                           ('keycloak','signer'),('caddy','openbao'),('signer','audit-store')]:
            self.assertFalse(shared(left,right), (left,right))
        for left,right in [('server','postgres'),('signer','postgres'),('signer','openbao'),
                           ('server','audit-gateway'),('audit-gateway','audit-store'),('caddy','server')]:
            self.assertTrue(shared(left,right), (left,right))

    def test_compose_environment_cannot_read_unreviewed_files_or_overrides(self):
        injected = {'COMPOSE_ENV_FILES':'private.synthetic.env','COMPOSE_FILE':'live.yaml',
                    'COMPOSE_PROFILES':'unreviewed','COMPOSE_DISABLE_ENV_FILE':'0'}
        completed = subprocess.CompletedProcess([],0,stdout=b'',stderr=b'')
        with patch.dict(os.environ,injected), patch.object(subprocess,'run',return_value=completed) as invoked:
            DockerRehearsal().call(['context','show'])
            forwarded = invoked.call_args.kwargs['env']
            self.assertEqual(forwarded['COMPOSE_DISABLE_ENV_FILE'],'1')
            for key in injected.keys()-{'COMPOSE_DISABLE_ENV_FILE'}:
                self.assertNotIn(key,forwarded)
            self.assertEqual(os.environ['COMPOSE_DISABLE_ENV_FILE'],'0')


CLIENT = '''import json,socket,sys
items=json.load(sys.stdin)
result=[]
for item in items:
    connected=False
    try:
        with socket.create_connection((item['ip'],18080),timeout=0.4) as connection:
            connected=connection.recv(64).decode('ascii').strip()==item['role']
    except OSError:
        pass
    result.append(connected)
with open('/proc/net/route',encoding='ascii') as routes:
    default=any(line.split()[1]=='00000000' for line in list(routes)[1:] if line.split())
print(json.dumps({'connected':result,'defaultRoute':default}))
'''

READY = '''import socket,time
ready=False
for _ in range(100):
    try:
        with socket.create_connection(('127.0.0.1',18080),timeout=0.2) as connection:
            ready=bool(connection.recv(64))
        if ready: break
    except OSError: pass
    time.sleep(0.05)
if not ready: raise RuntimeError('Synthetic listener not ready.')
'''


class DockerRehearsal:
    def __init__(self):
        self.project = isolation.PREFIX + uuid.uuid4().hex
        self.identity = isolation.session(self.project)
        self.model = isolation.render(self.project)
        self.packet = json.dumps(self.model).encode()
        self.created = False

    def call(self, args, data=None, timeout=30):
        environment = {key:value for key,value in os.environ.items() if not key.startswith('COMPOSE_')}
        environment['COMPOSE_DISABLE_ENV_FILE'] = '1'
        result = subprocess.run(['docker', *args], input=data, capture_output=True, timeout=timeout,env=environment)
        if result.returncode:
            raise RuntimeError('Synthetic Docker operation refused; no production data logged.')
        if len(result.stdout) > 262144:
            raise RuntimeError('Synthetic Docker metadata exceeded its bound.')
        return result.stdout

    def listed(self, kind):
        options = ['-a'] if kind=='container' else []
        return self.call([kind,'ls',*options,'-q','--filter','label='+isolation.SESSION+'='+self.identity]).decode().split()

    def inspect(self, kind, identity):
        if not re.fullmatch(r'[0-9a-f]{12,64}',identity):
            raise RuntimeError('Unexpected owned Docker identifier.')
        value = json.loads(self.call([kind,'inspect',identity]))[0]
        labels = value['Config']['Labels'] if kind=='container' else value['Labels']
        if labels.get(isolation.SESSION)!=self.identity or labels.get('com.docker.compose.project')!=self.project:
            raise RuntimeError('Synthetic resource ownership mismatch.')
        return value

    def cleanup(self):
        for identity in self.listed('container'):
            value = self.inspect('container',identity)
            role = value['Config']['Labels'].get(isolation.ROLE)
            if role not in isolation.MEMBERS or value['Name']!='/'+self.project+'-'+role+'-1':
                raise RuntimeError('Unexpected synthetic container name; cleanup refused.')
            self.call(['container','rm','-f','-v',identity])
        for identity in self.listed('network'):
            value = self.inspect('network',identity)
            if value['Name'] not in {self.project+'_'+n for n in isolation.NETWORKS}:
                raise RuntimeError('Unexpected synthetic network; cleanup refused.')
            self.call(['network','rm',identity])
        if self.listed('container') or self.listed('network'):
            raise RuntimeError('Owned synthetic resources remain.')

    def preflight(self):
        isolation.validate(self.model)
        if os.environ.get('DOCKER_HOST'):
            raise RuntimeError('Unreviewed Docker host override refused.')
        context = self.call(['context','show']).decode().strip()
        if context not in ('default','desktop-linux'):
            raise RuntimeError('Remote/unreviewed Docker context refused.')
        endpoint = self.call(['context','inspect',context,'--format','{{.Endpoints.docker.Host}}']).decode().strip()
        if endpoint not in ('unix:///var/run/docker.sock','npipe:////./pipe/docker_engine','npipe:////./pipe/dockerDesktopLinuxEngine'):
            raise RuntimeError('Only reviewed local Docker endpoints are supported.')
        version = self.call(['version','--format','{{.Server.Version}}']).decode().strip()
        if self.call(['info','--format','{{.OSType}}']).decode().strip()!='linux' or int(version.split('.')[0])<28:
            raise RuntimeError('Rehearsal requires a local Linux Docker Engine 28 or newer.')
        if self.listed('container') or self.listed('network'):
            raise RuntimeError('Synthetic namespace already exists.')
        self.call(['image','inspect',isolation.IMAGE])
        return version

    def verify_networks(self):
        networks = {}
        for identity in self.listed('network'):
            value = self.inspect('network',identity)
            isolation.archive.require(value['Internal'] is True and value['Driver']=='bridge' and not value['EnableIPv6'])
            isolation.archive.require(value['Options'][isolation.GATEWAY_OPTION]=='isolated')
            networks[value['Name']] = ipaddress.ip_network(value['IPAM']['Config'][0]['Subnet'])
        isolation.archive.require(set(networks)=={self.project+'_'+n for n in isolation.NETWORKS})
        return networks

    def verify_containers(self, networks):
        containers = {}
        expected_image = json.loads(self.call(['image','inspect',isolation.IMAGE]))[0]['Id']
        for identity in self.listed('container'):
            value = self.inspect('container',identity)
            role = value['Config']['Labels'][isolation.ROLE]
            isolation.archive.require(role in isolation.MEMBERS and role not in containers)
            host = value['HostConfig']
            isolation.archive.require(value['Image']==expected_image and value['State']['Running'])
            isolation.archive.require(value['Config']['User']=='65534:65534' and host['ReadonlyRootfs'])
            isolation.archive.require(not host['Privileged'] and host['CapDrop']==['ALL'] and not host['CapAdd'])
            isolation.archive.require('no-new-privileges:true' in host['SecurityOpt'])
            isolation.archive.require(not host['PortBindings'] and not value['Mounts'])
            isolation.archive.require(host['Memory']==64*1024*1024 and host['NanoCpus']==250000000 and host['PidsLimit']==32)
            isolation.archive.require(value['Config']['Cmd']==isolation.command(role))
            attached = value['NetworkSettings']['Networks']
            isolation.archive.require(set(attached)=={self.project+'_'+n for n in isolation.MEMBERS[role]})
            for name, endpoint in attached.items():
                isolation.archive.require(ipaddress.ip_address(endpoint['IPAddress']) in networks[name])
            containers[role] = (identity, attached)
        isolation.archive.require(set(containers)==set(isolation.MEMBERS))
        for identity,_ in containers.values():
            self.call(['exec',identity,'python','-I','-B','-c',READY])
        return containers

    def verify_connections(self, containers):
        allowed = denied = 0
        for role,(identity,_) in containers.items():
            targets, expected = [], []
            for other,(_,attached) in containers.items():
                if role==other:
                    continue
                shared = set(isolation.MEMBERS[role]) & set(isolation.MEMBERS[other])
                network_name = sorted(shared or set(isolation.MEMBERS[other]))[0]
                targets.append({'role':other,'ip':attached[self.project+'_'+network_name]['IPAddress']})
                expected.append(bool(shared))
            result = json.loads(self.call(['exec','-i',identity,'python','-I','-B','-c',CLIENT],json.dumps(targets).encode()))
            isolation.archive.require(result['connected']==expected and result['defaultRoute'] is False)
            allowed += expected.count(True)
            denied += expected.count(False)
        isolation.archive.require((allowed,denied)==(28,28))
        return allowed, denied

    def run(self):
        version = self.preflight()
        try:
            self.created = True
            self.call(['compose','-p',self.project,'-f','-','up','-d','--no-build','--pull','never'],self.packet,timeout=90)
            networks = self.verify_networks()
            containers = self.verify_containers(networks)
            allowed, denied = self.verify_connections(containers)
            return {'schema':'fleetory.synthetic-recovery-isolation.v1','dockerVersion':version,
                    'services':8,'isolatedInternalNetworks':3,'allowedConnections':allowed,
                    'deniedConnections':denied,'containersWithoutDefaultRoute':8,
                    'publishedPorts':0,'sourceMounts':0,'realRecoveryStarted':False,
                    'fullSystemRecoveryVerified':False,'phase7Complete':False}
        finally:
            if self.created:
                self.cleanup()


if __name__=='__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--docker', action='store_true', help='Run only the owned synthetic local rehearsal.')
    args = parser.parse_args()
    result = unittest.TextTestRunner(verbosity=1).run(unittest.defaultTestLoader.loadTestsFromTestCase(ContractTests))
    if not result.wasSuccessful():
        sys.exit(1)
    print('RECOVERY ISOLATION CONTRACT PASS: '+str(ContractTests.rejected)+' unsafe model mutations rejected.')
    if args.docker:
        record = DockerRehearsal().run()
        record['ownedResourcesRemoved'] = True
        print('RECOVERY ISOLATION DOCKER PASS: '+json.dumps(record,sort_keys=True))
