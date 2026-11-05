#requires -Version 7.3
# Fresh audit-only fixture. No retained path, address or credential argument.
function Assert-ImmuData([bool]$Condition,[string]$Category){if(-not $Condition){throw ('Audit data fixture refused: '+$Category)}}
function Get-ImmuDataHash([byte[]]$Packet){return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Packet)).ToLowerInvariant()}
function Assert-ImmuDataPacket([byte[]]$Packet,[string]$Expected){
    Assert-ImmuData ($null -ne $Packet -and $Packet.Length -ge 64 -and $Packet.Length -le 33554432 -and $Expected -cmatch '^[a-f0-9]{64}\z') 'packet-bound'
    Assert-ImmuData ([Text.Encoding]::ASCII.GetString($Packet,0,10) -ceq 'IMMUBACKUP' -and (Get-ImmuDataHash $Packet) -ceq $Expected) 'packet-pin-format'
}
function Get-ImmuDataCliArguments([string]$Id,[string]$Mode){
    Assert-ImmuData ($Id -cmatch '^[a-f0-9]{64}\z' -and $Mode -cin @('login','backup','verify','restore')) 'cli-target-mode'
    $prefix=@('exec','-i','-e','HOME=/tmp',$Id,'/usr/local/bin/immuadmin','--config=/tmp/cli.toml','--tokenfile=/tmp/cli-token',
        '--immudb-address=127.0.0.1','--immudb-port=3322','--mtls','--servername=127.0.0.1',
        '--clientcas=/tmp/ca.pem','--certificate=/tmp/client.crt','--pkey=/tmp/client.key')
    $actions=@{login=@('login','immudb');backup=@('hot-backup','fleetoryaudit','--output=-');
        verify=@('hot-restore','--verify-only','--input=-');restore=@('hot-restore','fleetoryaudit','--input=-')}
    return $prefix+$actions[$Mode]
}
function Get-ImmuDataImageName([string]$Session){
    Assert-ImmuData ($Session -cmatch '^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\z') 'session'
    return ('fleetory-immu-data-'+$Session.Replace('-','')+':fixture')
}
function Assert-ImmuDataPoint($Point,$Expected){
    Assert-ImmuData ($Point.database -ceq 'fleetoryaudit' -and $Point.tx -is [long] -and $Point.tx -ge 4 -and $Point.tx -le 10 -and
        $Point.txHash -cmatch '^[A-F0-9]{64}\z' -and $Point.keyFingerprint -cmatch '^[A-F0-9]{64}\z' -and $Point.keyCount -eq 4 -and
        $Point.entriesSha256 -cmatch '^[a-f0-9]{64}\z') 'point-profile'
    foreach($name in @('database','tx','txHash','keyFingerprint','keyCount','entriesSha256')){
        Assert-ImmuData ($Point[$name] -ceq $Expected[$name]) ('point-'+$name)
    }
}
