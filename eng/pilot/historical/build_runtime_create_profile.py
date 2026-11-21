"""Separate closed SDK create-request policy; no native creator or cleanup API."""
import re
from historical import historical_create_gate as gate

PURPOSE='retained-public-offline-build.v1'
TMPFS={'/work':'rw,noexec,nosuid,nodev,size=1073741824,uid=65534,gid=65534,mode=0700',
       '/run/fleetory-build-tmp':'rw,noexec,nosuid,nodev,size=67108864,uid=65534,gid=65534,mode=0700'}
COMMAND=['--signal=TERM','--kill-after=5s','300s','/bin/sh','/payload/control/build.sh']


def definition(image,nonce,context_sha256):
    gate.require(type(context_sha256) is str and re.fullmatch('[a-f0-9]{64}',context_sha256))
    return {'Image':image,'User':'65534:65534','Entrypoint':['/usr/bin/timeout'],
            'Cmd':list(COMMAND),'WorkingDir':'/work','Env':['TMPDIR=/run/fleetory-build-tmp'],
            'Labels':{'fleetory.public-build.session':nonce,'fleetory.public-build.profile':PURPOSE,
                      'fleetory.public-build.context':context_sha256},
            'HostConfig':{'NetworkMode':'none','ReadonlyRootfs':True,'AutoRemove':False,
                          'CapDrop':['ALL'],'SecurityOpt':['no-new-privileges'],
                          'Memory':2147483648,'NanoCpus':2000000000,'PidsLimit':128,
                          'Ulimits':[{'Name':'core','Hard':0,'Soft':0}],'Tmpfs':dict(TMPFS)}}


class BuildCreatePolicy(gate.CreateGatePolicy):
    """Trusted live owner must supply its actual input-image/context objects separately.

    Matching this JSON cannot grant image, build, start or removal custody.
    The original historical gate remains the default and does not select this
    class from a wire flag, version, label or profile value.
    """
    _name_prefix='fleetory-public-build-'

    def __init__(self,image,nonce,token,version,context_sha256):
        super().__init__(image,nonce,token,version)
        gate.require(type(context_sha256) is str and re.fullmatch('[a-f0-9]{64}',context_sha256))
        self.context_sha256=context_sha256

    def _validate_body(self,body):
        value=gate.document(body)
        expected=definition(self.image,self.nonce,self.context_sha256)
        expected_host=expected.pop('HostConfig')
        host=value.pop('HostConfig',None)
        gate._profile(value,expected,{'AttachStdout':(True,False),'AttachStderr':(True,False),
                       'NetworkingConfig':({'EndpointsConfig':{}},),'OnBuild':(None,)},gate.CONFIG_DEFAULTS)
        gate._profile(host,expected_host,{'ConsoleSize':([0,0],),
                       'LogConfig':({'Type':'','Config':{}},),
                       'RestartPolicy':({'Name':'no','MaximumRetryCount':0},),
                       'MemorySwappiness':(-1,)},gate.HOST_DEFAULTS)


if __name__=='__main__':
    raise SystemExit('Build create profile is metadata-only; live creator/witness integration is required.')
