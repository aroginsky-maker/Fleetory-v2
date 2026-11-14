#requires -Version 7.3
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
foreach($name in @('PilotNativeProcess.ps1','ProviderRecoveryPolicy.ps1','ImmuDataRoundtripPolicy.ps1','HistoricalAuditInputPins.ps1')){
    . (Join-Path $PSScriptRoot ('../../eng/pilot/'+$name))
}
$parent=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd([IO.Path]::DirectorySeparatorChar)
$root=Join-Path $parent ('fleetory-input-pins-'+[Guid]::NewGuid().ToString('N'))
$repo=Join-Path $root 'repo';$bundle=Join-Path $root 'publish';$checks=0
function Check([bool]$Value){if(-not $Value){throw 'Historical input pin assertion failed.'};$script:checks++}
function Refused([scriptblock]$Action){
    $denied=$false;try{$null=& $Action}catch{$denied=$true}
    Check $denied
}
function Write-Fixture([string]$Relative,[string]$Value,[string]$Base=$repo){
    $path=Join-Path $Base $Relative;$null=[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($path))
    [IO.File]::WriteAllText($path,$Value,[Text.UTF8Encoding]::new($false))
}
function Git-Fixture([string[]]$Arguments){
    $r=Invoke-NativeBytes 'git' (@('-C',$repo,'-c','user.name=fixture','-c','user.email=fixture@example.invalid')+$Arguments) -TimeoutSeconds 10
    if($r.ExitCode -ne 0){throw 'Generated Git fixture failed.'}
}
try{
    $null=[IO.Directory]::CreateDirectory($repo);$null=[IO.Directory]::CreateDirectory($bundle)
    $roots=@('.config/dotnet-tools.json','.editorconfig','Directory.Build.props','Directory.Packages.props',
        'Directory.Solution.targets','Fleetory.sln','NuGet.Config','global.json')
    $tracked=@('eng/Probe.cs','src/Core.cs','tests/Fleetory.Tools.Tests/case.ps1')+$roots[0..6]
    foreach($name in $tracked){Write-Fixture $name ('fixture '+$name)}
    Git-Fixture @('init','--quiet');Git-Fixture (@('add','--')+$tracked);Git-Fixture @('commit','--quiet','-m','Generated fixture')
    Write-Fixture 'global.json' 'active untracked SDK overlay'
    $pin=Get-HistoricalAuditCodeSnapshot $repo
    Check ($pin.schema -ceq 'fleetory.historical-code-snapshot.v2' -and $pin.files -eq 11 -and
        $pin.rootBuildInputs -eq 8 -and $pin.activeSdkInputMeasured -and -not $pin.repositoryCleanClaimed -and
        -not $pin.softwareOriginAuthenticated -and -not $pin.executionContinuityVerified)
    Check ((Get-HistoricalAuditCodeSnapshot $repo).sha256 -ceq $pin.sha256)
    foreach($name in ($roots+$tracked[0..2])){
        $path=Join-Path $repo $name;$bytes=[IO.File]::ReadAllBytes($path)
        try{
            [IO.File]::WriteAllText($path,'changed')
            $changed=Get-HistoricalAuditCodeSnapshot $repo
            Check ($changed.sha256 -cne $pin.sha256 -and $changed.revision -ceq $pin.revision)
        }finally{[IO.File]::WriteAllBytes($path,$bytes)}
    }
    foreach($name in $roots){
        $path=Join-Path $repo $name;$bytes=[IO.File]::ReadAllBytes($path)
        try{[IO.File]::Delete($path);Refused {Get-HistoricalAuditCodeSnapshot $repo}}finally{[IO.File]::WriteAllBytes($path,$bytes)}
    }
    Git-Fixture @('commit','--allow-empty','--quiet','-m','Same files new revision')
    $second=Get-HistoricalAuditCodeSnapshot $repo
    Check ($second.sha256 -cne $pin.sha256 -and $second.revision -cne $pin.revision)
    $probeFiles=@('ServerBackendProbe.dll','ServerBackendProbe.deps.json','ServerBackendProbe.runtimeconfig.json','dependency.dll','probe.pdb','nested/resource.dll')
    foreach($name in $probeFiles){Write-Fixture $name ('published '+$name) $bundle}
    $bundlePin=Get-HistoricalProbeBundle $bundle
    Check ($bundlePin.files -eq 6 -and $bundlePin.entries.Count -eq 7 -and
        -not $bundlePin.runtimeDependenciesAuthenticated -and -not $bundlePin.softwareOriginAuthenticated)
    Check ((Get-HistoricalProbeBundle $bundle).sha256 -ceq $bundlePin.sha256)
    foreach($name in $probeFiles){
        $path=Join-Path $bundle $name;$bytes=[IO.File]::ReadAllBytes($path)
        try{[IO.File]::WriteAllText($path,'mutated');Check ((Get-HistoricalProbeBundle $bundle).sha256 -cne $bundlePin.sha256)}finally{[IO.File]::WriteAllBytes($path,$bytes)}
    }
    foreach($name in $probeFiles[0..2]){
        $path=Join-Path $bundle $name;$bytes=[IO.File]::ReadAllBytes($path)
        try{
            [IO.File]::Delete($path);Refused {Get-HistoricalProbeBundle $bundle}
            $null=[IO.Directory]::CreateDirectory($path);Refused {Get-HistoricalProbeBundle $bundle}
        }finally{if([IO.Directory]::Exists($path)){[IO.Directory]::Delete($path)};[IO.File]::WriteAllBytes($path,$bytes)}
    }
    Write-Fixture 'extra.dll' 'extra' $bundle
    Check ((Get-HistoricalProbeBundle $bundle).sha256 -cne $bundlePin.sha256)
    [IO.File]::Delete((Join-Path $bundle 'extra.dll'))
    foreach($name in @('execute.exe','space name.dll')){
        try{Write-Fixture $name 'unsafe' $bundle;Refused {Get-HistoricalProbeBundle $bundle}}finally{[IO.File]::Delete((Join-Path $bundle $name))}
    }
    # Directory symlinks on Linux and junctions on Windows require no privileged fixture grant.
    $link=Join-Path $bundle 'linked';$target=Join-Path $root 'outside';$null=[IO.Directory]::CreateDirectory($target)
    try{
        $null=New-Item -ItemType $(if($IsWindows){'Junction'}else{'SymbolicLink'}) -Path $link -Target $target
        Refused {Get-HistoricalProbeBundle $bundle}
    }finally{if(Test-Path -LiteralPath $link){[IO.Directory]::Delete($link)}}
    if($IsLinux){
        try{Write-Fixture 'DEPENDENCY.dll' 'alias' $bundle;Refused {Get-HistoricalProbeBundle $bundle}}finally{[IO.File]::Delete((Join-Path $bundle 'DEPENDENCY.dll'))}
    }
    $script:listText=($bundlePin.entries|ForEach-Object {$_.kind+':'+$_.path}) -join "`n"
    $script:hashText=($bundlePin.entries|Where-Object {$_.kind -ceq 'f'}|ForEach-Object {$_.sha256+'  /tool/'+$_.path}) -join "`n"
    $script:dockerCalls=0
    function Invoke-Docker([string[]]$Arguments){
        $script:dockerCalls++
        if($Arguments[2] -ceq 'find'){return @{Stdout=$script:listText;Stderr=''}}
        if($Arguments[2] -ceq 'sha256sum'){return @{Stdout=$script:hashText;Stderr=''}}
        throw 'Unexpected bundle verification command.'
    }
    $context=@{ProbeBundle=$bundlePin};$store=@{Id='a'*64}
    Assert-HistoricalProbeContainerBundle $context $store;Check ($script:dockerCalls -eq 2)
    $goodList=$script:listText;$goodHashes=$script:hashText
    foreach($changed in @($goodList+"`nf:extra.dll",($goodList -replace 'f:dependency.dll','l:dependency.dll'),($goodList -replace 'f:dependency.dll\n?',''))){
        $script:listText=$changed;Refused {Assert-HistoricalProbeContainerBundle $context $store}
    }
    $script:listText=$goodList;$script:hashText=$goodHashes.Replace($bundlePin.entries[0].sha256,'0'*64)
    Refused {Assert-HistoricalProbeContainerBundle $context $store}
    $script:hashText=$goodHashes+"`nextra";Refused {Assert-HistoricalProbeContainerBundle $context $store}
    Write-Output ('HISTORICAL INPUT PINS PASS:'+$checks+' generated assertions;active root inputs,revision,complete application bundle,links and container mismatches checked;no original inputs or runtime-origin claim.')
}finally{
    $resolved=[IO.Path]::GetFullPath($root)
    if($resolved -cne $root -or [IO.Path]::GetDirectoryName($resolved) -cne $parent -or [IO.Path]::GetFileName($resolved) -cnotmatch '^fleetory-input-pins-[a-f0-9]{32}\z'){throw 'Fixture cleanup containment failed.'}
    if(Test-Path -LiteralPath $resolved){Remove-Item -LiteralPath $resolved -Recurse -Force}
}
