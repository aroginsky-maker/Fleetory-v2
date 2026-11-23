#requires -Version 7.3
. (Join-Path $PSScriptRoot 'AuditDataResourceOwnership.ps1')
. (Join-Path $PSScriptRoot 'PilotNativeProcess.ps1')
. (Join-Path $PSScriptRoot 'PilotNativeExecutableLease.ps1')
. (Join-Path $PSScriptRoot 'PublicBuildImagePolicy.ps1')
. (Join-Path $PSScriptRoot 'PublicBuildSdkPolicy.ps1')

# Must be created inside the surviving trusted worker. The delegate accepts no
# endpoint, config, executable or operation profile from a wire request.
function New-PublicBuildDockerClient([string]$Docker,[string]$ExpectedDockerSha256,[string]$PrivateConfig){
    if(-not [IO.Path]::IsPathFullyQualified($Docker) -or -not [IO.Path]::IsPathFullyQualified($PrivateConfig) -or
        [IO.Path]::GetFileName($Docker) -cne $(if($IsWindows){'docker.exe'}else{'docker'}) -or
        $ExpectedDockerSha256 -cnotmatch '^[a-f0-9]{64}\z'){throw 'Public build Docker identity refused.'}
    $imageArguments=${function:Get-PublicBuildImageArguments}
    $sdkArguments=${function:Get-PublicBuildSdkArguments}
    $nativeBytes=${function:Invoke-NativeBytes}
    $held=[Fleetory.Pilot.NativeExecutableLease]::new($Docker,$ExpectedDockerSha256)
    $created=$false
    try{
        $description=$held.Describe()
        $hash=$description.Item2
        [Fleetory.Pilot.ExclusiveAuditDirectory]::Create($PrivateConfig);$created=$true
        $state=@{Closed=$false;Held=$held;Path=$Docker;Config=$PrivateConfig;Sha256=$hash;Sdk=$null}
        $invoke={param([string[]]$Arguments,[byte[]]$InputBytes)
            if($state.Closed){throw 'Public build native client closed.'}
            $valid=$false
            if($Arguments.Count -eq 8 -and $Arguments[0] -ceq 'build'){
                if($Arguments[6] -cmatch '^fleetory\.public-build\.instance=([a-f0-9-]{36})\z'){
                    $fixed=& $imageArguments $Matches[1]
                    $valid=($fixed -join "`0") -ceq ($Arguments -join "`0") -and
                        $null -ne $InputBytes -and $InputBytes.Length -gt 0 -and $InputBytes.Length -le 67108864
                }
            }elseif($Arguments[0] -ceq 'create' -and $null -ne $state.Sdk){
                $sdk=$state.Sdk
                $alreadyAttempted=$sdk.CreateAttempted;$sdk.CreateAttempted=$true
                $image=[Fleetory.Pilot.PublicBuildImageCustody]::Id($sdk.Context,$sdk.Client)
                $fixed=& $sdkArguments $image $sdk.Session $sdk.Context.SourceContextSha256
                $valid=$null -eq $InputBytes -and ($fixed -join "`0") -ceq ($Arguments -join "`0") -and -not $alreadyAttempted
            }elseif($null -eq $InputBytes){
                $valid=($Arguments.Count -eq 3 -and $Arguments[0] -ceq 'image' -and $Arguments[1] -ceq 'inspect' -and $Arguments[2] -cmatch '^sha256:[a-f0-9]{64}\z') -or
                    ($Arguments.Count -eq 4 -and $Arguments[0] -ceq 'image' -and $Arguments[1] -ceq 'rm' -and $Arguments[2] -ceq '--no-prune' -and $Arguments[3] -cmatch '^sha256:[a-f0-9]{64}\z')
                if(-not $valid -and $null -ne $state.Sdk -and $null -ne $state.Sdk.Id){
                    $sdk=$state.Sdk
                    $null=[Fleetory.Pilot.PublicBuildImageCustody]::Id($sdk.Context,$sdk.Client)
                    $joined=$Arguments -join '|'
                    $valid=$joined -cin @(('inspect|'+$sdk.Id),('logs|'+$sdk.Id),('exec|'+$sdk.Id+'|/usr/bin/tar|-C|/work/output|-cf|-|.'))
                    if($joined -ceq ('exec|'+$sdk.Id+'|/bin/sh|-c|test -f /work/publish.ready')){$valid=$true}
                    if($joined -ceq ('exec|'+$sdk.Id+'|/bin/sh|-c|printf x > /work/release') -and -not $sdk.ReleaseAttempted){$valid=$true;$sdk.ReleaseAttempted=$true}
                    if($joined -ceq ('start|'+$sdk.Id) -and -not $sdk.StartAttempted){$valid=$true;$sdk.StartAttempted=$true}
                    if($joined -ceq ('rm|--force|'+$sdk.Id) -and -not $sdk.RemoveAttempted){$valid=$true;$sdk.RemoveAttempted=$true}
                    if($sdk.RemoveAttempted -and $joined -cnotin @(('inspect|'+$sdk.Id),('rm|--force|'+$sdk.Id))){$valid=$false}
                }
            }
            if(-not $valid){throw 'Public build native command refused.'}
            $prefix=@('--config',$state.Config,'--host',$(if($IsWindows){'npipe:////./pipe/dockerDesktopLinuxEngine'}else{'unix:///var/run/docker.sock'}))
            $result=& $nativeBytes $state.Path ($prefix+$Arguments) $InputBytes -TimeoutSeconds 120 -ClassicDockerEnvironment -ExecutableLease $state.Held
            if($Arguments[0] -ceq 'create' -and $result.ExitCode -eq 0 -and $result.Stdout -cmatch '^([a-f0-9]{64})\r?\n\z'){$state.Sdk.Id=$Matches[1]}
            return [Tuple[int,byte[],byte[]]]::new($result.ExitCode,$result.StdoutBytes,$result.StderrBytes)
        }.GetNewClosure()
        $bindSdk={param($ImageContext,$ImageClient)
            if($state.Closed -or $null -ne $state.Sdk){throw 'Public SDK binding consumed.'}
            $null=[Fleetory.Pilot.PublicBuildImageCustody]::Id($ImageContext,$ImageClient)
            $state.Sdk=@{Context=$ImageContext;Client=$ImageClient;Session=[guid]::NewGuid().ToString('D');Id=$null;
                CreateAttempted=$false;StartAttempted=$false;RemoveAttempted=$false;ReleaseAttempted=$false}
            return $state.Sdk.Session
        }.GetNewClosure()
        $dispose={
            if($state.Closed){throw 'Public build native client disposal replay refused.'}
            $state.Closed=$true
            try{[IO.Directory]::Delete($state.Config,$false)}finally{$state.Held.Dispose()}
        }.GetNewClosure()
        return @{Invoke=$invoke;Dispose=$dispose;BindSdk=$bindSdk}
    }catch{
        $held.Dispose()
        if($created){[IO.Directory]::Delete($PrivateConfig,$false)}
        throw
    }
}
