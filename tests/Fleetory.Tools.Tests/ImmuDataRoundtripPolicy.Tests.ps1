#requires -Version 7.3
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot '../../eng/pilot/ImmuDataRoundtripPolicy.ps1')
$script:immuRefusals=0
function Refused-Immu([scriptblock]$Action){$seen=$false;try{& $Action}catch{$seen=$true};if(-not $seen){throw 'Unsafe audit profile accepted.'};$script:immuRefusals++}
$bytes=[byte[]]::new(64);[Text.Encoding]::ASCII.GetBytes('IMMUBACKUP').CopyTo($bytes,0)
$pin=Get-ImmuDataHash $bytes
Assert-ImmuDataPacket $bytes $pin
Refused-Immu {Assert-ImmuDataPacket $bytes ('f'*64)}
Refused-Immu {Assert-ImmuDataPacket ([byte[]]::new(64)) ('a'*64)}
Refused-Immu {Assert-ImmuDataPacket ([byte[]]::new(63)) ('a'*64)}
Refused-Immu {Assert-ImmuDataPacket $bytes $pin.ToUpperInvariant()}
foreach($id in @('','live-source',('a'*63),('A'*64),(('a'*64)+"`n"),'../target')){Refused-Immu {Get-ImmuDataCliArguments $id 'restore'}}
Refused-Immu {Get-ImmuDataCliArguments ('a'*64) 'force'}
Refused-Immu {Get-ImmuDataImageName ('../'+[Guid]::NewGuid().ToString())}
$args=Get-ImmuDataCliArguments ('a'*64) 'restore'
Assert-ImmuData (($args[-3..-1]-join '|') -ceq 'hot-restore|fleetoryaudit|--input=-' -and $args -cnotcontains '--force' -and $args -cnotcontains '--append') 'restore-argv'
Assert-ImmuData (((Get-ImmuDataCliArguments ('a'*64) 'verify')[-3..-1] -join '|') -ceq 'hot-restore|--verify-only|--input=-') 'verify-argv'
$expected=@{database='fleetoryaudit';tx=[long]5;txHash='A'*64;keyFingerprint='B'*64;keyCount=4;entriesSha256='c'*64}
Assert-ImmuDataPoint $expected $expected
foreach($item in @(@('database','defaultdb'),@('tx',[long]4),@('txHash',('C'*64)),@('keyFingerprint',('D'*64)),@('keyCount',3),@('entriesSha256',('e'*64)),@('tx',$true))){
    $bad=$expected.Clone();$bad[$item[0]]=$item[1];Refused-Immu {Assert-ImmuDataPoint $bad $expected}
}
Assert-ImmuData ($script:immuRefusals -eq 19) 'refusal-count'
Write-Output 'IMMU DATA POLICY PASS:19 refusals; bounded pinned packet, fixed TLS/native argv and exact signed point.'
