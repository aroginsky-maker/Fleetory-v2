$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot '../../eng/pilot/PublicBuildImageTransaction.ps1')
. (Join-Path $PSScriptRoot '../../eng/pilot/PublicBuildSdkTransaction.ps1')
$script:checks=0
function Check($Value,$Name){if(-not $Value){throw $Name};$script:checks++}
$image='sha256:'+('b'*64);$script:testContainerId='c'*64;$session=[guid]::NewGuid().ToString('D')
foreach($fault in @('none','controller-loss','exit-code','root','memory','network','mount','environment','capability','label','workdir','command','create-unknown','remove-unknown','core-limit','pid-mode','device-request','unexpected-mount')){
    $script:model=@{Fault=$fault;Created=0;Started=0;Removed=0;Inspected=0;Copied=0;Gone=$false;Released=$false}
    $c=@{Fixture=[guid]::NewGuid().ToString('D');Root='public';ImageName='public';SourceContextSha256=('a'*64);SdkImage='sdk';ImageId=$null;ImageClaimed=$false}
    $imageClient={}
    $build=[Func[Tuple[int,byte[],byte[]]]]{[Tuple]::Create(0,[Text.Encoding]::ASCII.GetBytes($image+"`n"),[byte[]]@())}
    $null=[Fleetory.Pilot.PublicBuildImageCustody]::Build($c,$imageClient,[byte[]]@(1),$build)
    $native={param([string[]]$Arguments,[byte[]]$InputBytes)
        $m=$script:model;$text='';$errorText='';$exit=0
        switch($Arguments[0]){
            'create' {$m.Created++;$text=if($m.Fault -ceq 'create-unknown'){'truncated'}else{$script:testContainerId+"`n"}}
            'start' {$m.Started++;$text=$script:testContainerId+"`n"}
            'rm' {$m.Removed++;$m.Gone=$true;$text=if($m.Fault -ceq 'remove-unknown'){'truncated'}else{$script:testContainerId+"`n"}}
            'cp' {$m.Copied++;$text='generated output archive placeholder'}
            'logs' {$text='generated SDK log fixture'}
            'exec' {
                if($Arguments[2] -ceq '/usr/bin/tar'){$m.Copied++;$text='generated output archive placeholder';break}
                if($Arguments[4] -ceq 'printf x > /work/release'){$m.Released=$true}
            }
            'inspect' {
                $m.Inspected++
                if($m.Gone){$exit=1;$errorText='Error: no such container: '+$script:testContainerId+"`n";break}
                $info=@{Id=$script:testContainerId;Image=$image;Name=('/fleetory-public-build-'+$session.Replace('-',''));
                    Config=@{User='65534:65534';WorkingDir='/work';Entrypoint=@('/usr/bin/timeout');
                        Cmd=@('--signal=TERM','--kill-after=5s','300s','/bin/sh','/payload/control/build.sh');
                        Env=@('TMPDIR=/run/fleetory-build-tmp');Labels=@{'fleetory.public-build.session'=$session;'fleetory.public-build.context'=$c.SourceContextSha256;'fleetory.public-build.profile'='retained-public-offline-build.v1'}};
                    HostConfig=@{NetworkMode='none';ReadonlyRootfs=$true;AutoRemove=$false;Privileged=$false;Memory=2147483648;NanoCpus=2000000000;PidsLimit=128;
                        CapDrop=@('ALL');CapAdd=$null;Devices=$null;DeviceRequests=$null;PidMode='';IpcMode='private';UTSMode='';Ulimits=@(@{Name='core';Hard=0;Soft=0});SecurityOpt=@('no-new-privileges');Binds=$null;PortBindings=@{};
                        Tmpfs=@{'/work'='rw,noexec,nosuid,nodev,size=1073741824,uid=65534,gid=65534,mode=0700';
                            '/run/fleetory-build-tmp'='rw,noexec,nosuid,nodev,size=67108864,uid=65534,gid=65534,mode=0700'}};
                    Mounts=@();State=@{Status=$(if($m.Started){if($m.Released -or $m.Fault -ceq 'exit-code'){'exited'}else{'running'}}else{'created'});Running=($m.Started -and -not $m.Released -and $m.Fault -cne 'exit-code');ExitCode=$(if($m.Fault -ceq 'exit-code'){1}else{0})}}
                switch($m.Fault){
                    'root' {$info.HostConfig.ReadonlyRootfs=$false}
                    'memory' {$info.HostConfig.Memory=4294967296}
                    'network' {$info.HostConfig.NetworkMode='host'}
                    'mount' {$info.HostConfig.Binds=@('/:/host')}
                    'environment' {$info.Config.Env=@('TMPDIR=/tmp')}
                    'capability' {$info.HostConfig.CapAdd=@('SYS_ADMIN')}
                    'label' {$info.Config.Labels['fleetory.public-build.context']='wrong'}
                    'workdir' {$info.Config.WorkingDir='/'}
                    'command' {$info.Config.Cmd=@('/bin/sh')}
                    'core-limit' {$info.HostConfig.Ulimits[0].Hard=1}
                    'pid-mode' {$info.HostConfig.PidMode='host'}
                    'device-request' {$info.HostConfig.DeviceRequests=@(@{Count=-1})}
                    'unexpected-mount' {$info.Mounts=@(@{Type='bind';Source='/';Destination='/host'})}
                }
                $text=ConvertTo-Json -InputObject @($info) -Depth 12 -Compress
            }
            default {throw 'Unmodeled command'}
        }
        return [Tuple]::Create($exit,[Text.Encoding]::UTF8.GetBytes($text),[Text.Encoding]::UTF8.GetBytes($errorText))
    }
    $bind={param($Context,$Client) Check ([Fleetory.Pilot.PublicBuildImageCustody]::Id($Context,$Client) -ceq $image) 'original-live-image-required';return $session}
    $alive={return -not ($script:model.Fault -ceq 'controller-loss' -and $script:model.Started -eq 1)}
    $failed=$false;$failureData=$null
    try{$result=Invoke-PublicBuildSdkTransaction @{Invoke=$native;BindSdk=$bind} $c $imageClient $alive {param($ContainerId) Check ($ContainerId -ceq $script:testContainerId) 'original-ready-id'}}catch{$failed=$true;$failureData=$_.Exception.Data['PublicSdkDiagnostic'];if($fault -ceq 'none'){throw}}
    Check ($failed -eq ($fault -cne 'none')) ('result-'+$fault)
    Check ($model.Created -eq 1) 'single-container-create'
    Check ($model.Removed -eq $(if($fault -ceq 'create-unknown'){0}else{1})) 'sole-owned-removal'
    if($fault -ceq 'none'){Check ($result.containerClosed -and $result.outputBytes -gt 0) 'output-held-after-own-cleanup'}
    else{Check ($model.Copied -eq $(if($fault -ceq 'remove-unknown'){1}else{0})) 'no-output-after-refusal'}
    if($fault -ceq 'exit-code'){
        Check ($failureData.state -ceq 'exited' -and $failureData.exitCode -eq 1 -and -not $failureData.logReadFailed -and
            [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($failureData.stdoutTailBase64)) -ceq 'generated SDK log fixture') 'failure-diagnostic-retained-before-cleanup'
    }
}
Write-Output "PASS $checks SDK transaction assertions; synthetic native replies; runtime drift and unknown outcomes refused."

$global:LASTEXITCODE=0
