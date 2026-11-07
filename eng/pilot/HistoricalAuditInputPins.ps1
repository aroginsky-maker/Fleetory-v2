#requires -Version 7.3
# Public build/application snapshots only; not runtime/origin or retained execution continuity.
function Get-HistoricalAuditRevision([string]$Repository,[string]$Git='git'){
    $r=Invoke-NativeBytes $Git @('-C',$Repository,'rev-parse','--verify','HEAD') -TimeoutSeconds 10
    Assert-ImmuData ($r.ExitCode -eq 0 -and [string]::IsNullOrWhiteSpace($r.Stderr) -and
        $r.Stdout.Trim() -cmatch '^[a-f0-9]{40}\z') 'controller-code-revision'
    return $r.Stdout.Trim()
}
function Get-HistoricalInputFileHash([string]$Path,[long]$Limit){
    $before=Get-ProviderOrdinaryItem $Path
    Assert-ImmuData (-not $before.PSIsContainer -and $before.Length -ge 0 -and $before.Length -le $Limit) 'controller-input-file'
    $stamp=@($before.Length,$before.LastWriteTimeUtc.Ticks,$before.CreationTimeUtc.Ticks)
    $stream=$null;$hash=$null
    try{
        $stream=[IO.FileStream]::new($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        $hash=[Security.Cryptography.IncrementalHash]::CreateHash([Security.Cryptography.HashAlgorithmName]::SHA256)
        $buffer=[byte[]]::new(65536);[long]$count=0
        while(($n=$stream.Read($buffer,0,$buffer.Length)) -gt 0){
            $count+=$n;Assert-ImmuData ($count -le $Limit) 'controller-input-bound';$hash.AppendData($buffer,0,$n)
        }
        $after=Get-ProviderOrdinaryItem $Path
        Assert-ImmuData ($count -eq $stamp[0] -and $after.Length -eq $stamp[0] -and
            $after.LastWriteTimeUtc.Ticks -eq $stamp[1] -and $after.CreationTimeUtc.Ticks -eq $stamp[2]) 'controller-input-changed'
        return @{bytes=$count;sha256=[Convert]::ToHexString($hash.GetHashAndReset()).ToLowerInvariant()}
    }finally{if($null -ne $hash){$hash.Dispose()};if($null -ne $stream){$stream.Dispose()}}
}
function Get-HistoricalAuditCodeSnapshot([string]$Repository,[string]$Git='git'){
    $root=Get-ProviderOrdinaryItem $Repository
    Assert-ImmuData ($root.PSIsContainer -and $root.FullName -ceq $Repository) 'controller-code-root'
    $revision=Get-HistoricalAuditRevision $Repository $Git
    $listed=Invoke-NativeBytes $Git @('-C',$Repository,'ls-files','--','eng','src','tests/Fleetory.Tools.Tests') -TimeoutSeconds 10
    Assert-ImmuData ($listed.ExitCode -eq 0 -and [string]::IsNullOrWhiteSpace($listed.Stderr)) 'controller-code-list'
    $names=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach($name in ($listed.Stdout -split '\r?\n')){
        if(-not $name){continue}
        Assert-ImmuData ($name -cmatch '^(eng|src|tests/Fleetory\.Tools\.Tests)/[A-Za-z0-9_./-]+\z' -and
            -not ($name -split '/').Contains('..') -and $names.Add($name)) 'controller-code-path'
    }
    $roots=@('.config/dotnet-tools.json','.editorconfig','Directory.Build.props','Directory.Packages.props',
        'Directory.Solution.targets','Fleetory.sln','NuGet.Config','global.json')
    foreach($name in $roots){Assert-ImmuData ($names.Add($name)) 'controller-root-input-duplicate'}
    Assert-ImmuData ($names.Count -gt $roots.Count -and $names.Count -le 768) 'controller-code-count'
    $ordered=[string[]]@($names);[Array]::Sort($ordered,[StringComparer]::Ordinal)
    $lines=[Text.StringBuilder]::new("fleetory.historical.native-controller-code.v2`n$revision`n")
    [long]$total=0
    foreach($name in $ordered){
        $path=[IO.Path]::GetFullPath((Join-Path $Repository $name))
        Assert-ImmuData ($path.StartsWith($Repository+[IO.Path]::DirectorySeparatorChar,[StringComparison]::Ordinal)) 'controller-code-containment'
        $file=Get-HistoricalInputFileHash $path 1048576
        $total+=$file.bytes;Assert-ImmuData ($total -le 67108864) 'controller-code-total'
        $null=$lines.Append($name).Append("`n").Append($file.bytes.ToString([Globalization.CultureInfo]::InvariantCulture)).Append("`n").Append($file.sha256).Append("`n")
    }
    Assert-ImmuData ((Get-HistoricalAuditRevision $Repository $Git) -ceq $revision) 'controller-code-revision-changed'
    return @{schema='fleetory.historical-code-snapshot.v2';revision=$revision;sha256=(Get-ImmuDataHash ([Text.Encoding]::UTF8.GetBytes($lines.ToString())));
        files=$ordered.Length;rootBuildInputs=$roots.Count;bytes=$total;activeSdkInputMeasured=$true;repositoryCleanClaimed=$false;
        softwareOriginAuthenticated=$false;executionContinuityVerified=$false}
}
function Get-HistoricalProbeBundle([string]$Directory){
    $root=Get-ProviderOrdinaryItem $Directory
    Assert-ImmuData ($root.PSIsContainer -and $root.FullName -ceq $Directory) 'controller-probe-root'
    $pending=[Collections.Generic.Stack[string]]::new();$pending.Push($Directory)
    $entries=[Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    $aliases=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    [long]$total=0;$files=0
    while($pending.Count){
        $parent=$pending.Pop()
        foreach($item in @(Get-ChildItem -LiteralPath $parent -Force)){
            $ordinary=Get-ProviderOrdinaryItem $item.FullName
            $relative=[IO.Path]::GetRelativePath($Directory,$ordinary.FullName).Replace([IO.Path]::DirectorySeparatorChar,[char]'/')
            Assert-ImmuData ($relative -cmatch '^[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+){0,7}\z' -and
                -not ($relative -split '/').Contains('..') -and $aliases.Add($relative) -and $entries.Count -lt 256) 'controller-probe-entry'
            if($ordinary.PSIsContainer){
                $entries.Add($relative,@{kind='d';path=$relative;bytes=0;sha256='-'})
                $pending.Push($ordinary.FullName)
            }else{
                Assert-ImmuData ($ordinary.Extension -cin @('.dll','.json','.pdb') -and $files -lt 128) 'controller-probe-file-type'
                $file=Get-HistoricalInputFileHash $ordinary.FullName 33554432
                $total+=$file.bytes;Assert-ImmuData ($total -le 67108864) 'controller-probe-total'
                $files++;$entries.Add($relative,@{kind='f';path=$relative;bytes=$file.bytes;sha256=$file.sha256})
            }
        }
    }
    Assert-ImmuData ($files -gt 0 -and $entries.ContainsKey('ServerBackendProbe.dll') -and
        $entries.ContainsKey('ServerBackendProbe.deps.json') -and $entries.ContainsKey('ServerBackendProbe.runtimeconfig.json') -and
        $entries['ServerBackendProbe.dll'].kind -ceq 'f' -and $entries['ServerBackendProbe.deps.json'].kind -ceq 'f' -and
        $entries['ServerBackendProbe.runtimeconfig.json'].kind -ceq 'f') 'controller-probe-required'
    $ordered=[string[]]@($entries.Keys);[Array]::Sort($ordered,[StringComparer]::Ordinal)
    $lines=[Text.StringBuilder]::new("fleetory.historical.probe-bundle.v1`n")
    $values=@(foreach($name in $ordered){
        $entry=$entries[$name]
        $null=$lines.Append($entry.kind).Append(':').Append($name).Append("`n").Append($entry.bytes.ToString([Globalization.CultureInfo]::InvariantCulture)).Append("`n").Append($entry.sha256).Append("`n")
        $entry
    })
    return @{schema='fleetory.historical-probe-bundle.v1';sha256=(Get-ImmuDataHash ([Text.Encoding]::UTF8.GetBytes($lines.ToString())));
        entries=$values;files=$files;bytes=$total;runtimeDependenciesAuthenticated=$false;softwareOriginAuthenticated=$false}
}
function Assert-HistoricalProbeContainerBundle($Context,$Store){
    $bundle=$Context.ProbeBundle
    Assert-ImmuData ($bundle.schema -ceq 'fleetory.historical-probe-bundle.v1' -and
        $bundle.entries.Count -gt 0 -and $bundle.entries.Count -le 256) 'controller-container-bundle-model'
    $listing=Invoke-Docker @('exec',$Store.Id,'find','/tool','-mindepth','1','-printf','%y:%P\n')
    Assert-ImmuData ($listing.Stdout.Length -le 65536 -and [string]::IsNullOrWhiteSpace($listing.Stderr)) 'controller-container-bundle-list'
    $actual=[string[]]@($listing.Stdout -split '\r?\n'|Where-Object {$_});[Array]::Sort($actual,[StringComparer]::Ordinal)
    $expected=[string[]]@($bundle.entries|ForEach-Object {$_.kind+':'+$_.path});[Array]::Sort($expected,[StringComparer]::Ordinal)
    Assert-ImmuData (($actual -join "`n") -ceq ($expected -join "`n")) 'controller-container-bundle-set'
    $files=@($bundle.entries|Where-Object {$_.kind -ceq 'f'})
    $arguments=@('exec',$Store.Id,'sha256sum','--')+@($files|ForEach-Object {'/tool/'+$_.path})
    $result=Invoke-Docker $arguments
    $lines=@($result.Stdout -split '\r?\n'|Where-Object {$_})
    Assert-ImmuData ($lines.Count -eq $files.Count -and [string]::IsNullOrWhiteSpace($result.Stderr)) 'controller-container-bundle-count'
    for($n=0;$n -lt $files.Count;$n++){
        Assert-ImmuData ($lines[$n] -ceq ($files[$n].sha256+'  /tool/'+$files[$n].path)) 'controller-container-bundle-hash'
    }
}
