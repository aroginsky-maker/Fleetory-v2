#requires -Version 7.3
. (Join-Path $PSScriptRoot 'PublicBuildImagePolicy.ps1')
function Get-PublicBuildSdkArguments([string]$Image,[string]$Session,[string]$ContextSha256){
    if($Image -cnotmatch '^sha256:[a-f0-9]{64}\z' -or $ContextSha256 -cnotmatch '^[a-f0-9]{64}\z'){throw 'Public SDK image/context refused.'}
    [Fleetory.Pilot.PublicBuildInstance]::Validate($Session)
    return [string[]]@('create','--name',('fleetory-public-build-'+$Session.Replace('-','')),
        '--network','none','--read-only','--user','65534:65534','--cap-drop','ALL','--security-opt','no-new-privileges',
        '--memory','2147483648','--cpus','2','--pids-limit','128','--ulimit','core=0:0',
        '--tmpfs','/work:rw,noexec,nosuid,nodev,size=1073741824,uid=65534,gid=65534,mode=0700',
        '--tmpfs','/run/fleetory-build-tmp:rw,noexec,nosuid,nodev,size=67108864,uid=65534,gid=65534,mode=0700',
        '--env','TMPDIR=/run/fleetory-build-tmp','--workdir','/work','--entrypoint','/usr/bin/timeout',
        '--label',('fleetory.public-build.session='+$Session),
        '--label','fleetory.public-build.profile=retained-public-offline-build.v1',
        '--label',('fleetory.public-build.context='+$ContextSha256),$Image,
        '--signal=TERM','--kill-after=5s','300s','/bin/sh','/payload/control/build.sh')
}
