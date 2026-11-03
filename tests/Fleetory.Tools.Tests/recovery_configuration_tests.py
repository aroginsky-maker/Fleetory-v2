"""Closed recovery profile contracts and native unstarted File-provider builders."""
import argparse
import copy
import json
from pathlib import Path
import re
import secrets
import subprocess
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0,str(REPO / 'eng/pilot'))
import recovery_configuration as config
import recovery_files as files
from recovery_tls import local_docker
from recovery_tls_tests import generate_material

RUNTIME = 'mcr.microsoft.com/dotnet/aspnet:10.0@sha256:de0ee358cdd672f7017a003bed21e9ac9ed48a27c922a59b18175b6e82fa7fee'
LABEL = 'fleetory.recovery.configuration.session'


class ConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.profile = config.render()

    def refuse(self, mutate):
        value = copy.deepcopy(self.profile)
        mutate(value)
        with self.assertRaises(Exception):
            config.validate(value)

    def test_exact_file_provider_and_seventeen_slots(self):
        config.validate(self.profile)
        self.assertEqual(sum(map(len,self.profile['slots'].values())),17)
        self.assertEqual(self.profile['provider'],'File')

    def test_provider_switch_or_extra_credentials_refused(self):
        self.refuse(lambda p:p.update(provider='OpenBao'))
        self.refuse(lambda p:p['profiles']['server'].update({'Fleetory:Secrets:Provider':'OpenBao'}))
        self.refuse(lambda p:p['profiles']['server'].update({'ConnectionStrings:Fleetory':'hidden'}))

    def test_root_and_slot_expansion_refused(self):
        self.refuse(lambda p:p['profiles']['server'].update({'Fleetory:Secrets:Directory':'/source/secrets'}))
        self.refuse(lambda p:p['slots']['signer'].append('ca-private-key'))
        self.refuse(lambda p:p['slots']['server'].remove('audit-immudb-password'))

    def test_gateways_oidc_audit_and_verified_origins_are_fixed(self):
        for key, value in {'Fleetory:AdminGateway:Enabled':'false','Fleetory:AdminGateway:Oidc:Enabled':'false',
                           'Fleetory:AuditExport:Enabled':'false','Fleetory:AdminGateway:BindAddress':'0.0.0.0',
                           'Fleetory:AdminGateway:Oidc:Authority':'https://live.invalid/realms/fleetory',
                           'Fleetory:AuditExport:Address':'http://immudb:8080'}.items():
            self.refuse(lambda p:p['profiles']['server'].update({key:value}))

    def test_signer_origin_and_version_are_closed(self):
        for key, value in {'Signer:TransitAddress':'http://openbao:8200','Signer:TransitKey':'production',
                           'Signer:TransitKeyVersion':'2','Signer:BindAddress':'0.0.0.0'}.items():
            self.refuse(lambda p:p['profiles']['signer'].update({key:value}))

    def test_native_arguments_contain_no_secret_values(self):
        for role in config.SLOTS:
            args = config.arguments(self.profile,role)
            self.assertEqual(args[0],role)
            self.assertFalse(any('Password=' in value or 'Token=' in value for value in args))
        with self.assertRaises(Exception):
            config.arguments(self.profile,'issuer')

    def test_cli_reports_preparation_without_runtime_promotion(self):
        result = subprocess.run([sys.executable,'-B',config.__file__,'--validate'],
                                input=json.dumps(self.profile).encode(),capture_output=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr)
        record = json.loads(result.stdout)
        for key in ('originalMaterialApproved','servicesStarted','fullSystemRecoveryVerified','phase7Complete'):
            self.assertIs(record[key],False)

    def test_cli_refuses_duplicate_or_unbounded_inputs(self):
        for packet in (b'{"schema":1,"schema":2}',b'x'*16385):
            result = subprocess.run([sys.executable,'-B',config.__file__,'--validate'],input=packet,
                                    capture_output=True,timeout=10)
            self.assertEqual(result.returncode,1)
            self.assertNotIn(packet[:50],result.stderr)


class NativeLab:
    def __init__(self, published):
        self.context = local_docker()
        self.identity = secrets.token_hex(16)
        self.name = 'fleetory-config-'+self.identity
        self.published = Path(published).resolve(strict=True)
        config.archive.require(self.published == (REPO / 'artifacts/recovery-configuration').absolute() and
                               ',' not in str(self.published) and (self.published / 'RecoveryConfiguration.dll').is_file())
        self.created = False
        self.forbidden = []

    def call(self, args, packet=None, check=True):
        result = subprocess.run(['docker','--context',self.context,*args],input=packet,capture_output=True,timeout=60)
        config.archive.require(len(result.stdout) <= 65536 and len(result.stderr) <= 65536 and
                               (not check or result.returncode == 0))
        return result

    def owned(self):
        template = '{"label":{{json (index .Config.Labels "'+LABEL+'")}},"image":{{json .Config.Image}},"user":{{json .Config.User}},"host":{{json .HostConfig}},"mounts":{{json .Mounts}}}'
        value = json.loads(self.call(['inspect',self.name,'--format',template]).stdout)
        host = value['host']
        config.archive.require(value['label'] == self.identity and value['image'] == RUNTIME and value['user'] == '1654:1654')
        config.archive.require(host['NetworkMode'] == 'none' and host['ReadonlyRootfs'] and not host['Privileged'] and
                               not host['PortBindings'] and host['CapDrop'] == ['ALL'] and not host['CapAdd'] and
                               'no-new-privileges' in host['SecurityOpt'][0] and host['Memory'] == 268435456 and
                               host['NanoCpus'] == 1000000000 and host['PidsLimit'] == 64)
        config.archive.require(len(value['mounts']) == 1 and value['mounts'][0]['Type'] == 'bind' and
                               value['mounts'][0]['Destination'] == '/tool' and not value['mounts'][0]['RW'])

    def setup(self):
        config.archive.require(self.call(['container','inspect',self.name],check=False).returncode != 0)
        self.call(['image','inspect',RUNTIME,'--format','{{.Id}}'])
        config.archive.require(self.call(['info','--format','{{.OSType}}']).stdout.strip() == b'linux')
        self.call(['create','--name',self.name,'--label',LABEL+'='+self.identity,'--network','none','--read-only',
                   '--user','1654:1654','--cap-drop','ALL','--security-opt','no-new-privileges','--memory','256m',
                   '--cpus','1','--pids-limit','64','--tmpfs','/tmp:rw,noexec,nosuid,size=32m,mode=0700,uid=1654,gid=1654',
                   '--mount','type=bind,src='+str(self.published)+',dst=/tool,readonly',
                   '-e','DOTNET_ENVIRONMENT=Production','-e','DOTNET_EnableDiagnostics=0','-e','DOTNET_PROCESSOR_COUNT=2',
                   '-e','HOME=/tmp','-e','ASPNETCORE_URLS=', '--entrypoint','sh',RUNTIME,'-ec','while :; do sleep 1; done'])
        self.created = True
        self.owned()
        self.call(['start',self.name])
        self.call(['exec',self.name,'sh','-ec','mkdir -m 700 /tmp/material /tmp/material/server /tmp/material/signer'])

    def write(self, role, name, packet):
        config.archive.require(role in config.SLOTS and name in config.SLOTS[role] and 0 < len(packet) <= 16385)
        self.owned()
        path = config.ROOT+role+'/'+name
        self.call(['exec','-i',self.name,'sh','-ec','umask 077; cat > "$1"; chmod 0600 "$1"','private-config',path],packet)
        config.archive.require(self.call(['exec',self.name,'stat','-c','%a:%u:%h',path]).stdout.strip() == b'600:1654:1')

    def probe(self, role, expected='accepted', change=None):
        profile = config.render()
        args = config.arguments(profile,role)
        if change:
            key,value = change
            args = [arg for arg in args if not arg.startswith('--'+key+'=')]+['--'+key+'='+value]
        self.owned()
        result = self.call(['exec',self.name,'dotnet','/tool/RecoveryConfiguration.dll',*args],check=False)
        config.archive.require(not any(value in result.stdout+result.stderr for value in self.forbidden))
        record = config.archive.parse(result.stdout,16384)
        config.archive.require(result.returncode == (0 if expected == 'accepted' else 2) and
                               record['category'] == expected and record['role'] == role and
                               not any(record[key] for key in ('servicesStarted','databaseOpened','issuerActivated','originalMaterialApprovalInferred')))
        return record

    def cleanup(self):
        if self.created:
            self.owned()
            self.call(['rm','-f',self.name])
            config.archive.require(self.call(['container','inspect',self.name],check=False).returncode != 0)


def material_packet(root, descriptor, role, name, key):
    if name == 'signer-transit-public-key':
        return key.encode()
    if name == 'signer-transit-token':
        return secrets.token_hex(32).encode()
    _,_,packet = files.inspect_file(root,descriptor,role+'/'+name,16384,retain=True)
    if name in ('fleetory-postgresql','signer-postgresql'):
        packet = packet.replace(('/run/fleetory-'+role).encode(),(config.ROOT+role).encode())
    return packet


def generated_packets(lab, generated):
    key = json.loads(lab.call(['exec',lab.name,'dotnet','/tool/RecoveryConfiguration.dll','public-key']).stdout)['publicKey']
    packets = {}
    with files.rooted(generated / 'upload/secrets') as (root,descriptor):
        for role,names in config.SLOTS.items():
            for name in names:
                packet = material_packet(root,descriptor,role,name,key)
                packets[(role,name)] = packet
                lab.write(role,name,packet)
    return packets


def secret_canaries(packets):
    result = []
    for (_,name),packet in packets.items():
        password = re.search(rb'Password=([^;]+)',packet)
        if password:
            result.append(password[1])
        if name in ('audit-immudb-password','signer-transit-token'):
            result.append(packet.strip())
        if b'PRIVATE KEY' in packet:
            result.extend(line[:40] for line in packet.splitlines() if len(line) >= 40 and not line.startswith(b'-----'))
    return result


def missing_checks(lab, packets):
    for role,name in packets:
        path = config.ROOT+role+'/'+name
        lab.call(['exec',lab.name,'mv',path,path+'-held'])
        try:
            lab.probe(role,'unreadable-secret')
        finally:
            lab.call(['exec',lab.name,'mv',path+'-held',path])
    return len(packets)


def provider_checks(lab):
    changes = ((('Fleetory:Secrets:Provider','Unknown'),'provider'),
               (('Fleetory:Secrets:Provider','OpenBao'),'provider-mix'),
               (('ConnectionStrings:Fleetory',''),'provider-mix'),
               (('Fleetory:AdminGateway:Oidc:Enabled','false'),'oidc'))
    for change,expected in changes:
        lab.probe('server',expected,change)
    return len(changes)


def permission_checks(lab):
    for role in config.SLOTS:
        path = config.ROOT+role+'/'+config.SLOTS[role][0]
        lab.call(['exec',lab.name,'chmod','0644',path])
        try:
            lab.probe(role,'file-permissions')
        finally:
            lab.call(['exec',lab.name,'chmod','0600',path])
    return 2


def database_checks(lab, packets):
    for role,name in (('server','fleetory-postgresql'),('signer','signer-postgresql')):
        original = packets[(role,name)]
        lab.write(role,name,original.replace(b'SSL Mode=VerifyFull',b'SSL Mode=Disable'))
        try:
            lab.probe(role,'database')
        finally:
            lab.write(role,name,original)
    return 2


def no_listeners(lab):
    sockets = lab.call(['exec',lab.name,'sh','-ec','cat /proc/net/tcp /proc/net/tcp6']).stdout
    config.archive.require(not any(len(row.split()) > 3 and row.split()[3] == b'0A' for row in sockets.splitlines()))


def native(published):
    with tempfile.TemporaryDirectory(prefix='fleetory-config-generated-') as temporary:
        generated = generate_material(Path(temporary))
        public = json.loads((generated / 'manifest.json').read_text(encoding='utf-8-sig'))
        config.archive.require(public['applicationCommit'] == 'a'*40)
        lab = NativeLab(published)
        try:
            lab.setup()
            packets = generated_packets(lab,generated)
            lab.forbidden = secret_canaries(packets)
            for role in config.SLOTS:
                lab.probe(role)
            denied = missing_checks(lab,packets)+provider_checks(lab)+permission_checks(lab)+database_checks(lab,packets)
            config.archive.require(denied == 25)
            no_listeners(lab)
        finally:
            lab.cleanup()
    return {'schema':'fleetory.native-recovery-configuration.v1','provider':'File','requiredFiles':17,
            'nativeBuildersAccepted':2,'negativeCases':denied,'ownedResourcesRemoved':True,'generatedMaterialRemoved':True,
            'syntheticOnly':True,'originalMaterialUsed':False,'servicesStarted':False,'databaseOpened':False,
            'issuerActivated':False,'tcpListenersObserved':0,'secretCanariesAbsent':True,'providerAuthenticationVerified':False,
            'fullSystemRecoveryVerified':False,'phase7Complete':False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native-publish')
    args = parser.parse_args()
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(ConfigurationTests))
    if not result.wasSuccessful():
        sys.exit(1)
    if args.native_publish:
        print('NATIVE RECOVERY CONFIG PASS: '+json.dumps(native(args.native_publish),sort_keys=True))
