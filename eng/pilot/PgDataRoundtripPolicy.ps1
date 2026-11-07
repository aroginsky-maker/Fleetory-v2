#requires -Version 7.3
# Closed generated PostgreSQL proof profile; never grants access to retained data.
function Assert-PgData([bool]$Condition,[string]$Category){if(-not $Condition){throw ('PostgreSQL data fixture refused: '+$Category)}}
function Get-PgDataHash([byte[]]$Packet){return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Packet)).ToLowerInvariant()}
function Assert-PgDataPacket([byte[]]$Packet,[string]$Expected){
    Assert-PgData ($null -ne $Packet -and $Packet.Length -ge 64 -and $Packet.Length -le 33554432 -and
        $Expected -cmatch '^[a-f0-9]{64}\z') 'packet-bound'
    Assert-PgData ([Text.Encoding]::ASCII.GetString($Packet,0,5) -ceq 'PGDMP' -and (Get-PgDataHash $Packet) -ceq $Expected) 'packet-pin-format'
}
function Get-PgDataRestoreArguments([string]$Id,[switch]$List){
    Assert-PgData ($Id -cmatch '^[a-f0-9]{64}\z') 'target-id'
    if($List){return @('exec','-i',$Id,'pg_restore','--list')}
    return @('exec','-i',$Id,'pg_restore','--exit-on-error','--single-transaction','--no-password','--role=fleetory_migrator','--username=postgres','--dbname=fleetory')
}
function Read-PgDataInventory([byte[]]$Packet){
    Assert-PgData ($null -ne $Packet -and $Packet.Length -gt 0 -and $Packet.Length -le 1048576) 'inventory-bound'
    $lines=@([Text.UTF8Encoding]::new($false,$true).GetString($Packet).TrimEnd("`r","`n") -split '\r?\n')
    Assert-PgData ($lines.Count -eq 20) 'inventory-records'
    $records=@($lines|ForEach-Object {$_|ConvertFrom-Json -AsHashtable -Depth 32})
    $profileRecord=$records[0]
    foreach($name in @('tables','unsupported','extraSchemas','extraExtensions')){Assert-PgData ($profileRecord[$name] -is [long]) 'inventory-profile-type'}
    Assert-PgData ($profileRecord.kind -ceq 'profile' -and $profileRecord.database -ceq 'fleetory' -and $profileRecord.tables -eq 18 -and
        $profileRecord.unsupported -eq 0 -and $profileRecord.extraSchemas -eq 0 -and $profileRecord.extraExtensions -eq 0 -and $records[1].kind -ceq 'catalog') 'inventory-profile'
    $names=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal);$rows=0
    foreach($r in $records[2..19]){
        Assert-PgData ($r.kind -ceq 'table' -and $r.name -cmatch '^(core|platform)\.[A-Za-z_][A-Za-z0-9_]*\z' -and $names.Add($r.name) -and
            $r.rows -is [long] -and $r.rows -ge 0 -and $r.rows -le 10000 -and $r.sha256 -cmatch '^[a-f0-9]{64}\z') 'inventory-table'
        $rows+=$r.rows
    }
    Assert-PgData ($rows -ge 8 -and $rows -le 10000 -and $names.Contains('core.devices') -and $names.Contains('platform.person_projections') -and
        @($records[2..19]|Where-Object {$_.name -ceq 'core.devices'})[0].rows -eq 2 -and
        @($records[2..19]|Where-Object {$_.name -ceq 'platform.person_projections'})[0].rows -eq 2 -and
        @($records[2..19]|Where-Object {$_.name -ceq 'platform.audit_events'})[0].rows -eq 4 -and
        @($records[2..19]|Where-Object {$_.name -ceq 'platform.audit_export_queue'})[0].rows -eq 0) 'inventory-nonempty-point'
    return @{Sha256=Get-PgDataHash $Packet;Catalog=$lines[1];Rows=$rows;Tables=18;Records=$records}
}
