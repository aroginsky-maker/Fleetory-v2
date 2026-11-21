$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot '../../eng/pilot/AuditDataResourceOwnership.ps1')
. (Join-Path $PSScriptRoot '../../eng/pilot/PublicBuildDockerClient.ps1')
$script:checks=0
function Check($Value,$Name){if(-not $Value){throw $Name};$script:checks++}
function Refused([scriptblock]$Action,$Name){$failed=$false;try{& $Action}catch{$failed=$true};Check $failed $Name}
$testRoot=Join-Path ([IO.Path]::GetTempPath()) ('fleetory-sdk-client-'+[guid]::NewGuid().ToString('N'))
[Fleetory.Pilot.ExclusiveAuditDirectory]::Create($testRoot)
$docker=Join-Path $testRoot $(if($IsWindows){'docker.exe'}else{'docker'})
$file=[IO.FileStream]::new($docker,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
try{$bytes=[Text.Encoding]::ASCII.GetBytes('generated non-executable model client');$file.Write($bytes,0,$bytes.Length)}finally{$file.Dispose()}
try{
$hash=(Get-FileHash -LiteralPath $docker -Algorithm SHA256).Hash.ToLowerInvariant()
$script:nativeCalls=0;$script:containerId='c'*64
function Invoke-NativeBytes($Executable,[string[]]$Arguments,[byte[]]$InputBytes,[int]$TimeoutSeconds,[switch]$ClassicDockerEnvironment){
    $script:nativeCalls++
    Check ($ClassicDockerEnvironment -and $TimeoutSeconds -eq 120) 'fixed-native-environment-and-deadline'
    Check ($Arguments[0] -ceq '--config' -and $Arguments[2] -ceq '--host' -and $Arguments[3] -ceq $(if($IsWindows){'npipe:////./pipe/dockerDesktopLinuxEngine'}else{'unix:///var/run/docker.sock'})) 'fixed-endpoint-prefix'
    $text=$script:containerId+"`n"
    return @{ExitCode=0;Stdout=$text;StdoutBytes=[Text.Encoding]::ASCII.GetBytes($text);StderrBytes=[byte[]]@()}
}
foreach($case in @('valid','invalid-create','unknown-create')){
    $image='sha256:'+('b'*64);$imageClient={}
    $ctx=@{Fixture=[guid]::NewGuid().ToString('D');Root='public';ImageName='public';SourceContextSha256=('a'*64);SdkImage='sdk';ImageId=$null;ImageClaimed=$false}
    $createImage=[Func[Tuple[int,byte[],byte[]]]]{[Tuple]::Create(0,[Text.Encoding]::ASCII.GetBytes($image+"`n"),[byte[]]@())}
    $null=[Fleetory.Pilot.PublicBuildImageCustody]::Build($ctx,$imageClient,[byte[]]@(1),$createImage)
    $config=Join-Path $testRoot ('sdk-client-config-'+[guid]::NewGuid().ToString('N'))
    $client=New-PublicBuildDockerClient $docker $hash $config
    $originalNative=$null;$originalSdkArguments=$null;$originalImageArguments=$null
    try{
        Refused {& $client.BindSdk $ctx.Clone() $imageClient} 'copied-image-context-no-binding'
        Refused {& $client.BindSdk $ctx {}} 'different-image-client-no-binding'
        $session=& $client.BindSdk $ctx $imageClient
        Refused {& $client.BindSdk $ctx $imageClient} 'sdk-binding-single-use'
        $argsFixed=Get-PublicBuildSdkArguments $image $session $ctx.SourceContextSha256
        $originalNative=${function:Invoke-NativeBytes}
        $originalSdkArguments=${function:Get-PublicBuildSdkArguments}
        $originalImageArguments=${function:Get-PublicBuildImageArguments}
        if($case -ceq 'valid'){
            Set-Item -Path Function:Invoke-NativeBytes -Value {throw 'Ambient native replacement must not run.'}
            Set-Item -Path Function:Get-PublicBuildSdkArguments -Value {throw 'Ambient SDK policy replacement must not run.'}
            Set-Item -Path Function:Get-PublicBuildImageArguments -Value {throw 'Ambient image policy replacement must not run.'}
        }
        $before=$script:nativeCalls
        if($case -ceq 'invalid-create'){
            $bad=[string[]]$argsFixed.Clone();$bad[4]='host'
            Refused {& $client.Invoke $bad $null} 'bad-network-no-native-call'
            Refused {& $client.Invoke $argsFixed $null} 'invalid-create-consumed-no-repair'
            Check ($script:nativeCalls -eq $before) 'invalid-create-no-side-effect'
        }else{
            $script:containerId=if($case -ceq 'unknown-create'){'truncated'}else{'c'*64}
            $null=& $client.Invoke $argsFixed $null
            Refused {& $client.Invoke $argsFixed $null} 'create-no-replay'
            Check ($script:nativeCalls -eq $before+1) 'one-create-call'
            if($case -ceq 'unknown-create'){
                Refused {& $client.Invoke @('start',('c'*64)) $null} 'unknown-id-no-start-or-adoption'
                Check ($script:nativeCalls -eq $before+1) 'unknown-create-no-next-call'
            }else{
                Refused {& $client.Invoke @('start',('f'*64)) $null} 'foreign-container-no-start'
                $null=& $client.Invoke @('start',('c'*64)) $null
                Refused {& $client.Invoke @('start',('c'*64)) $null} 'start-no-replay'
                Refused {& $client.Invoke @('cp',(('c'*64)+':/etc'),'-') $null} 'foreign-output-path-refused'
                Refused {& $client.Invoke @('cp',(('c'*64)+':/work/output/.'),'-') $null} 'unsupported-cp-route-removed'
                Refused {& $client.Invoke @('exec',('c'*64),'/usr/bin/tar','-C','/etc','-cf','-','.') $null} 'foreign-tar-path-refused'
                $null=& $client.Invoke @('exec',('c'*64),'/usr/bin/tar','-C','/work/output','-cf','-','.') $null
                Refused {& $client.Invoke @('exec',('c'*64),'/bin/sh','-c','cat /etc/passwd') $null} 'arbitrary-exec-refused'
                Refused {& $client.Invoke @('exec',('c'*64),'/bin/sh','-c','test -f /tmp/publish.ready') $null} 'foreign-ready-path-refused'
                $null=& $client.Invoke @('exec',('c'*64),'/bin/sh','-c','printf x > /work/release') $null
                Refused {& $client.Invoke @('exec',('c'*64),'/bin/sh','-c','printf x > /work/release') $null} 'release-single-use'
            }
        }
    }finally{
        if($null -ne $originalNative){Set-Item -Path Function:Invoke-NativeBytes -Value $originalNative}
        if($null -ne $originalSdkArguments){Set-Item -Path Function:Get-PublicBuildSdkArguments -Value $originalSdkArguments}
        if($null -ne $originalImageArguments){Set-Item -Path Function:Get-PublicBuildImageArguments -Value $originalImageArguments}
        & $client.Dispose
    }
    Check (-not (Test-Path -LiteralPath $config)) 'own-empty-config-removed'
}
Write-Output "PASS $checks SDK native-client boundary checks; native process calls mocked; no Docker mutation."

}finally{
    # The generated file is known, and configs must already be absent. Never recurse.
    [IO.File]::Delete($docker)
    [IO.Directory]::Delete($testRoot,$false)
}

$global:LASTEXITCODE=0
