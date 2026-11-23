#requires -Version 7.3
# Trusted live owner supplies root/state/watch/cleaning. No CLI or authority is created here.
. (Join-Path (Split-Path $PSScriptRoot -Parent) 'PilotNativeExecutableLease.ps1')
function Invoke-Docker([string[]]$Arguments,[byte[]]$InputBytes=$null,[int]$TimeoutSeconds=60,[switch]$AllowFailure,[scriptblock]$ObserveProcess=$null){
    Assert-Pair ($cleaning -or $watch.Elapsed.TotalSeconds -lt 600) 'fixture-deadline'
    $external=Get-Variable -Name retainedExternalController -ValueOnly -ErrorAction SilentlyContinue
    $cleanupCommand=$Arguments.Count -gt 0 -and ($Arguments[0] -cin @('inspect','rm') -or
        ($Arguments[0] -ceq 'image' -and $Arguments.Count -gt 1 -and $Arguments[1] -cin @('inspect','rm')))
    if($null -ne $external -and -not $cleaning -and -not $cleanupCommand){Assert-RetainedControllerPipe $external}
    $privateConfig=$null
    try{
        if($null -ne $ObserveProcess){
            Assert-RetainedObservedWorkArguments $Arguments
            foreach($name in @('DOCKER_API_VERSION','DOCKER_CUSTOM_HEADERS')){
                Assert-Pair ([string]::IsNullOrEmpty([Environment]::GetEnvironmentVariable($name))) 'observed-client-no-ambient-override'
            }
            # Both observed clients use a private empty config and a fixed local Engine endpoint.
            $privateConfig=Join-Path $root ('observed-client-'+[Guid]::NewGuid().ToString('N'))
            [Fleetory.Pilot.ExclusiveAuditDirectory]::Create($privateConfig)
            if(-not $state.ContainsKey('DockerExecutableLease')){
                if($IsLinux){$selected='/usr/bin/docker'}else{
                    $commands=@(Get-Command docker.exe -CommandType Application -ErrorAction Stop)
                    Assert-Pair ($commands.Count -eq 1) 'observed-client-unambiguous-executable'
                    $selected=$commands[0].Source
                }
                $file=[IO.FileInfo]::new($selected);$resolved=$file.ResolveLinkTarget($true)
                $state.DockerExecutablePath=if($null -ne $resolved){$resolved.FullName}else{$file.FullName}
                $pin=(Get-FileHash -LiteralPath $state.DockerExecutablePath -Algorithm SHA256).Hash.ToLowerInvariant()
                $state.DockerExecutableLease=[Fleetory.Pilot.NativeExecutableLease]::new($state.DockerExecutablePath,$pin)
            }
            $executable=$state.DockerExecutablePath
            $endpoint=if($IsLinux){'unix:///var/run/docker.sock'}else{'npipe:////./pipe/dockerDesktopLinuxEngine'}
            $result=Invoke-NativeBytes $executable (@('--config',$privateConfig,'--host',$endpoint)+$Arguments) $InputBytes $TimeoutSeconds -ObserveProcess $ObserveProcess -DockerClientEnvironment -ExecutableLease $state.DockerExecutableLease
        }else{
            $result=if($IsLinux){Invoke-NativeBytes '/bin/sh' @('-c',(Get-ProviderDockerShellCommand $Arguments -ClassicBuilder:($Arguments[0] -ceq 'build'))) $InputBytes $TimeoutSeconds}
                else{Invoke-NativeBytes 'docker' (@('--context','desktop-linux')+$Arguments) $InputBytes $TimeoutSeconds}
        }
    }finally{if($null -ne $privateConfig){[IO.Directory]::Delete($privateConfig,$false)}}
    $script:lastExit=$result.ExitCode;$script:lastClass='unclassified'
    foreach($kind in @('syntax error','does not exist','permission denied','no such file','authentication failed','connection refused')){if(($result.Stdout+$result.Stderr).Contains($kind,[StringComparison]::OrdinalIgnoreCase)){$script:lastClass=$kind.Replace(' ','-');break}}
    if($result.Stderr -cmatch 'ERROR:\s+([A-Z0-9]{5})\b'){$script:lastClass='sqlstate-'+$Matches[1]}
    foreach($secret in $state.Canaries){Assert-Pair (-not ($result.Stdout+$result.Stderr).Contains($secret,[StringComparison]::Ordinal)) 'credential-canary'}
    if(-not $AllowFailure){Assert-Pair ($result.ExitCode -eq 0) 'docker-operation'}
    return $result
}
