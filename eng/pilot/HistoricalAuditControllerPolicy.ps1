#requires -Version 7.3
# Generated ten-case fixture only; this in-memory set is not a durable purpose ledger.
. (Join-Path $PSScriptRoot 'HistoricalAuditInputPins.ps1')
function New-HistoricalControllerCase($Plan,$Packet,$ChildNonce,$Consumed){
    Assert-ImmuData ($Plan -is [hashtable] -and $Plan.ContainsKey('nonce') -and $Plan.ContainsKey('schema') -and
        $Plan.nonce -is [string] -and $Plan.schema -ceq 'fleetory.historical-audit-restore-plan.v2' -and
        $Packet -is [hashtable] -and $Packet.ContainsKey('schema') -and
        $Packet.schema -ceq 'fleetory.historical-audit-restore-packet.v1') 'controller-case-model'
    $parent=[Guid]::Empty;$child=[Guid]::Empty
    Assert-ImmuData ([Guid]::TryParseExact($Plan.nonce,'D',[ref]$parent) -and $parent -ne [Guid]::Empty -and
        $parent.ToString('D') -ceq $Plan.nonce -and $ChildNonce -is [string] -and
        [Guid]::TryParseExact($ChildNonce,'D',[ref]$child) -and $child -ne [Guid]::Empty -and
        $child.ToString('D') -ceq $ChildNonce -and $child -ne $parent) 'controller-case-nonce'
    Assert-ImmuData ($Consumed -is [Collections.Generic.HashSet[string]] -and
        $Consumed.Comparer.Equals([StringComparer]::Ordinal) -and $Consumed.Count -lt 10) 'controller-case-registry'
    # Consume before serialization; failed preparation must not silently reuse an operation.
    Assert-ImmuData ($Consumed.Add($ChildNonce)) 'controller-case-replay'
    $childPlan=($Plan|ConvertTo-Json -Depth 12 -Compress -WarningAction Stop)|ConvertFrom-Json -AsHashtable -Depth 16
    $childPacket=($Packet|ConvertTo-Json -Depth 12 -Compress -WarningAction Stop)|ConvertFrom-Json -AsHashtable -Depth 16
    $childPlan.nonce=$ChildNonce
    $planBytes=[Text.Encoding]::UTF8.GetBytes(($childPlan|ConvertTo-Json -Depth 12 -Compress -WarningAction Stop))
    $childPacket.planBase64=[Convert]::ToBase64String($planBytes)
    $packetBytes=[Text.Encoding]::UTF8.GetBytes(($childPacket|ConvertTo-Json -Depth 12 -Compress -WarningAction Stop))
    Assert-ImmuData ($planBytes.Length -gt 0 -and $planBytes.Length -le 16384 -and
        $packetBytes.Length -gt 0 -and $packetBytes.Length -le 131072) 'controller-case-bound'
    return @{nonce=$ChildNonce;planSha256=(Get-ImmuDataHash $planBytes);bytes=$packetBytes}
}

function Test-HistoricalArchiveChecksumRefusal($Result){
    if($Result.ExitCode -eq 0){return $false}
    $text=$Result.Stdout+$Result.Stderr
    return ($text -match "(?i)\btransaction checksums don't match\b" -and
        $text -notmatch '(?i)code\s*=\s*(Unavailable|Unauthenticated|PermissionDenied|DeadlineExceeded)|dial tcp|connection refused|TLS handshake|context canceled')
}

function Get-HistoricalAuditCodeHash {
    $directory=Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    return (Get-HistoricalAuditCodeSnapshot $directory).sha256
}

function Read-HistoricalControllerPacket {
    $stream=[Console]::OpenStandardInput();$buffer=[byte[]]::new(131073);$count=0
    while($count -lt $buffer.Length){$read=$stream.Read($buffer,$count,$buffer.Length-$count);if($read -eq 0){break};$count+=$read}
    Assert-ImmuData ($count -gt 0 -and $count -le 131072) 'controller-packet-bound'
    return ,$buffer[0..($count-1)]
}
