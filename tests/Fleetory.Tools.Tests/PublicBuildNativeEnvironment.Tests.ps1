#requires -Version 7.3
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot '../../eng/pilot/PilotNativeProcess.ps1')
$saved=@{}
foreach($name in @('FLEETORY_BUILD_AMBIENT_CANARY','DOCKER_API_VERSION','DOCKER_CUSTOM_HEADERS','DOCKER_BUILDKIT','DOCKER_HOST')){
    $saved[$name]=[Environment]::GetEnvironmentVariable($name)
    [Environment]::SetEnvironmentVariable($name,'generated-model-canary')
}
try{
    $clean='if([Environment]::GetEnvironmentVariable("FLEETORY_BUILD_AMBIENT_CANARY") -or [Environment]::GetEnvironmentVariable("DOCKER_API_VERSION") -or [Environment]::GetEnvironmentVariable("DOCKER_CUSTOM_HEADERS") -or [Environment]::GetEnvironmentVariable("DOCKER_HOST") -or [Environment]::GetEnvironmentVariable("DOCKER_BUILDKIT") -cne "0"){exit 9};[Console]::Out.Write("CLEAN")'
    $executable=if($IsWindows){[Environment]::ProcessPath}else{'/bin/sh'}
    $arguments=if($IsWindows){@('-NoLogo','-NoProfile','-NonInteractive','-Command',$clean)}else{@('-c','test -z "$FLEETORY_BUILD_AMBIENT_CANARY$DOCKER_API_VERSION$DOCKER_CUSTOM_HEADERS$DOCKER_HOST" && test "$DOCKER_BUILDKIT" = 0 && printf CLEAN')}
    $reply=Invoke-NativeBytes $executable $arguments -TimeoutSeconds 10 -ClassicDockerEnvironment
    if($reply.ExitCode -ne 0 -or $reply.Stdout -cne 'CLEAN' -or $reply.Stderr -cne ''){throw 'Explicit clean Docker child environment failed.'}
    $normal='if([Environment]::GetEnvironmentVariable("FLEETORY_BUILD_AMBIENT_CANARY") -cne "generated-model-canary" -or [Environment]::GetEnvironmentVariable("DOCKER_BUILDKIT") -cne "generated-model-canary" -or [Environment]::GetEnvironmentVariable("DOCKER_HOST")){exit 9};[Console]::Out.Write("DEFAULT")'
    $arguments=if($IsWindows){@('-NoLogo','-NoProfile','-NonInteractive','-Command',$normal)}else{@('-c','test "$FLEETORY_BUILD_AMBIENT_CANARY" = generated-model-canary && test "$DOCKER_BUILDKIT" = generated-model-canary && test -z "$DOCKER_HOST" && printf DEFAULT')}
    $reply=Invoke-NativeBytes $executable $arguments -TimeoutSeconds 10
    if($reply.ExitCode -ne 0 -or $reply.Stdout -cne 'DEFAULT' -or $reply.Stderr -cne ''){throw 'Existing native child environment changed.'}
}finally{foreach($name in $saved.Keys){[Environment]::SetEnvironmentVariable($name,$saved[$name])}}
Write-Output 'PUBLIC BUILD NATIVE ENVIRONMENT PASS: clean opt-in and unchanged legacy default verified with actual child processes.'
$global:LASTEXITCODE=0
