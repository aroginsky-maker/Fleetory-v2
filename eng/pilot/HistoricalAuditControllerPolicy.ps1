#requires -Version 7.3
function Test-HistoricalArchiveChecksumRefusal($Result){
    if($Result.ExitCode -eq 0){return $false}
    $text=$Result.Stdout+$Result.Stderr
    return ($text -match "(?i)\btransaction checksums don't match\b" -and
        $text -notmatch '(?i)code\s*=\s*(Unavailable|Unauthenticated|PermissionDenied|DeadlineExceeded)|dial tcp|connection refused|TLS handshake|context canceled')
}

function Get-HistoricalAuditCodeHash {
    $directory=Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $listed=Invoke-NativeBytes 'git' @('-C',$directory,'ls-files','--','eng','src','tests/Fleetory.Tools.Tests') -TimeoutSeconds 10
    Assert-ImmuData ($listed.ExitCode -eq 0 -and [string]::IsNullOrWhiteSpace($listed.Stderr)) 'controller-code-list'
    $files=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach($name in ($listed.Stdout -split '\r?\n')){if($name){$null=$files.Add($name)}}
    foreach($name in @('eng/pilot/HistoricalAuditControllerPolicy.ps1','eng/pilot/Invoke-HistoricalAuditObservation.ps1','eng/pilot/historical_audit_restore.py','eng/pilot/AuditDataResourceOwnership.ps1')){$null=$files.Add($name)}
    Assert-ImmuData ($files.Count -gt 0 -and $files.Count -le 768) 'controller-code-count'
    $ordered=[string[]]@($files);[Array]::Sort($ordered,[StringComparer]::Ordinal)
    $lines=[Text.StringBuilder]::new("fleetory.historical.native-controller-code.v1`n")
    foreach($name in $ordered){
        Assert-ImmuData ($name -cmatch '^(eng|src|tests/Fleetory\.Tools\.Tests)/[A-Za-z0-9_./-]+\z' -and -not ($name -split '/').Contains('..')) 'controller-code-path'
        $path=[IO.Path]::GetFullPath((Join-Path $directory $name))
        Assert-ImmuData ($path.StartsWith($directory+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)) 'controller-code-containment'
        $item=Get-ProviderOrdinaryItem $path
        Assert-ImmuData (-not $item.PSIsContainer -and $item.Length -le 1048576) 'controller-code-file'
        $null=$lines.Append($name).Append("`n").Append((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()).Append("`n")
    }
    return Get-ImmuDataHash ([Text.Encoding]::UTF8.GetBytes($lines.ToString()))
}

function Read-HistoricalControllerPacket {
    $stream=[Console]::OpenStandardInput();$buffer=[byte[]]::new(131073);$count=0
    while($count -lt $buffer.Length){$read=$stream.Read($buffer,$count,$buffer.Length-$count);if($read -eq 0){break};$count+=$read}
    Assert-ImmuData ($count -gt 0 -and $count -le 131072) 'controller-packet-bound'
    return ,$buffer[0..($count-1)]
}
