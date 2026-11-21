"""A separate SDK request cannot widen the existing historical native gate."""
import unittest

import historical_create_gate_tests as old
from historical import build_runtime_create_profile as build

CONTEXT='c'*64


def policy():return build.BuildCreatePolicy(old.IMAGE,old.NONCE,old.TOKEN,'1.56',CONTEXT)


def body():return build.definition(old.IMAGE,old.NONCE,CONTEXT)


def create(p,value=None):
    return p.authorize('POST','/v1.56/containers/create?name='+p.name,
                       old.headers(),old.raw(body() if value is None else value))


class BuildPolicyTests(unittest.TestCase):
    def test_fixed_sdk_request_one_attempt(self):
        p=policy()
        self.assertEqual('create',create(p))
        self.assertEqual('fleetory-public-build-'+old.NONCE.replace('-',''),p.name)
        with self.assertRaises(old.gate.GateRefusal):create(p)

    def test_both_profiles_refuse_each_others_request(self):
        with self.assertRaises(old.gate.GateRefusal):old.create(old.policy(),body())
        with self.assertRaises(old.gate.GateRefusal):create(policy(),old.body())

    def test_wrong_namespace_or_extra_api_never_authorized(self):
        for method,target in [('POST','/v1.56/containers/create?name='+old.policy().name),
                              ('POST','/v1.56/build'),('POST','/v1.56/containers/x/start'),
                              ('DELETE','/v1.56/containers/x'),('GET','/containers/json')]:
            with self.subTest(target=target):
                p=policy()
                with self.assertRaises(old.gate.GateRefusal):p.authorize(method,target,old.headers(),old.raw(body()))
                with self.assertRaises(old.gate.GateRefusal):create(p)

    def test_authentication_is_required(self):
        p=policy()
        with self.assertRaises(old.gate.GateRefusal):
            p.authorize('POST','/v1.56/containers/create?name='+p.name,{},old.raw(body()))

    def test_unsafe_config_mutations_and_repair_refused(self):
        changes=[('User','0:0'),('Image','sha256:'+'f'*64),('WorkingDir','/'),
                 ('Entrypoint',['/bin/sh']),('Cmd',['-c','arbitrary']),
                 ('Env',['TOKEN=expanded']),('Volumes',{'/host':{}}),
                 ('Labels',{}),('ExposedPorts',{'8080/tcp':{}}),
                 ('NetworkingConfig',{'EndpointsConfig':{'bridge':{}}})]
        for key,value in changes:
            with self.subTest(key=key):
                request=body();request[key]=value;p=policy()
                with self.assertRaises(old.gate.GateRefusal):create(p,request)
                with self.assertRaises(old.gate.GateRefusal):create(p)

    def test_unsafe_host_mutations_and_repair_refused(self):
        changes=[('NetworkMode','host'),('ReadonlyRootfs',False),('AutoRemove',True),
                 ('CapDrop',[]),('CapAdd',['SYS_ADMIN']),('SecurityOpt',[]),
                 ('Memory',2147483649),('NanoCpus',0),('PidsLimit',0),('Tmpfs',{}),
                 ('Binds',['/:/host']),('Privileged',True),('PidMode','host'),
                 ('Devices',[{'PathOnHost':'/dev/sda'}]),
                 ('PortBindings',{'8080/tcp':[{'HostPort':'8080'}]}),
                 ('RestartPolicy',{'Name':'always','MaximumRetryCount':0})]
        for key,value in changes:
            with self.subTest(key=key):
                request=body();request['HostConfig'][key]=value;p=policy()
                with self.assertRaises(old.gate.GateRefusal):create(p,request)
                with self.assertRaises(old.gate.GateRefusal):create(p)

    def test_type_coercion_not_accepted(self):
        for key,value in [('ReadonlyRootfs',1),('AutoRemove',0),('Memory',2147483648.0),('PidsLimit',True)]:
            request=body();request['HostConfig'][key]=value
            with self.assertRaises(old.gate.GateRefusal):create(policy(),request)

    def test_missing_required_fields_refused(self):
        for scope in ('config','host'):
            for key in (body() if scope=='config' else body()['HostConfig']):
                request=body();target=request if scope=='config' else request['HostConfig'];del target[key]
                with self.subTest(scope=scope,key=key):
                    with self.assertRaises(old.gate.GateRefusal):create(policy(),request)

    def test_context_and_label_cannot_expand(self):
        for value in ('c'*63,'C'*64,'../file',True):
            with self.assertRaises(old.gate.GateRefusal):build.BuildCreatePolicy(old.IMAGE,old.NONCE,old.TOKEN,'1.56',value)
        request=body();request['Labels']['fleetory.public-build.context']='d'*64
        with self.assertRaises(old.gate.GateRefusal):create(policy(),request)

    def test_optional_empty_defaults_do_not_admit_values(self):
        request=body();request['Env']=None;request['HostConfig']['Binds']=[]
        self.assertEqual('create',create(policy(),request))
        request['HostConfig']['Binds']=['/tmp:/work']
        with self.assertRaises(old.gate.GateRefusal):create(policy(),request)

    def test_create_body_cannot_add_ownership_or_root_claim(self):
        for key in ('cleanupAuthorized','owner','profile','root','command'):
            request=body();request[key]=True
            with self.assertRaises(old.gate.GateRefusal):create(policy(),request)

    def test_duplicate_json_field_refused(self):
        request=old.raw(body()).replace(b'"User":"65534:65534"',b'"User":"0","User":"65534:65534"')
        p=policy()
        with self.assertRaises(old.gate.GateRefusal):
            p.authorize('POST','/v1.56/containers/create?name='+p.name,old.headers(),request)


if __name__=='__main__':unittest.main()
