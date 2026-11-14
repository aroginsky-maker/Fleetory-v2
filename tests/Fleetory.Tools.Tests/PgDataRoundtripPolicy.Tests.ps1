#requires -Version 7.3
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot '../../eng/pilot/PgDataRoundtripPolicy.ps1')
$script:pgDataPolicyRefusals=0
function Refused([scriptblock]$Action){$seen=$false;try{& $Action}catch{$seen=$true};if(-not $seen){throw 'Unsafe roundtrip policy accepted.'};$script:pgDataPolicyRefusals++}
$packet=[byte[]]::new(64);[Text.Encoding]::ASCII.GetBytes('PGDMP').CopyTo($packet,0)
$pin=Get-PgDataHash $packet
Assert-PgDataPacket $packet $pin
Refused {Assert-PgDataPacket $packet ('f'*64)}
Refused {Assert-PgDataPacket ([Text.Encoding]::ASCII.GetBytes('SQLite format 3'+('x'*64))) ('a'*64)}
Refused {Assert-PgDataPacket ([byte[]]::new(63)) ('a'*64)}
Refused {Assert-PgDataPacket $packet $pin.ToUpperInvariant()}
foreach($id in @('','source-live',('a'*63),('A'*64),(('a'*64)+"`n"),'../target')){Refused {Get-PgDataRestoreArguments $id}}
$restoreArgs=Get-PgDataRestoreArguments ('a'*64)
Assert-PgData (($restoreArgs -join '|') -ceq ('exec|-i|'+('a'*64)+'|pg_restore|--exit-on-error|--single-transaction|--no-password|--role=fleetory_migrator|--username=postgres|--dbname=fleetory')) 'restore-argv'
Assert-PgData (((Get-PgDataRestoreArguments ('a'*64) -List) -join '|') -ceq ('exec|-i|'+('a'*64)+'|pg_restore|--list')) 'list-argv'
foreach($bad in @('[]','{}',"{`"kind`":`"profile`"}`n{`"kind`":`"catalog`"}")){Refused {Read-PgDataInventory ([Text.Encoding]::UTF8.GetBytes($bad))}}
$records=@(@{kind='profile';database='fleetory';tables=18;unsupported=0;extraSchemas=0;extraExtensions=0},@{kind='catalog'})
foreach($name in @('core.devices','platform.person_projections','platform.audit_events','platform.audit_export_queue')){$records+=@{kind='table';name=$name;rows=$(if($name -ceq 'platform.audit_events'){4}elseif($name -ceq 'platform.audit_export_queue'){0}else{2});sha256='a'*64}}
for($n=0;$n -lt 14;$n++){$records+=@{kind='table';name=('core.fixture_'+$n);rows=0;sha256='b'*64}}
function Inventory-Packet{return [Text.Encoding]::UTF8.GetBytes((($records|ForEach-Object {$_|ConvertTo-Json -Compress -Depth 5}) -join "`n")+"`n")}
$positive=Read-PgDataInventory (Inventory-Packet)
Assert-PgData ($positive.Rows -eq 8 -and $positive.Tables -eq 18) 'synthetic-inventory-shape'
foreach($name in @('unsupported','extraSchemas','extraExtensions')){$saved=$records[0][$name];$records[0][$name]=$false;Refused {Read-PgDataInventory (Inventory-Packet)};$records[0][$name]=$saved}
foreach($value in @($true,-1,10001)){$saved=$records[2].rows;$records[2].rows=$value;Refused {Read-PgDataInventory (Inventory-Packet)};$records[2].rows=$saved}
Assert-PgData ($script:pgDataPolicyRefusals -eq 19) 'portable-refusal-count'
Write-Output 'PG DATA POLICY PASS:19 refusals; native packet/pin, closed target/restore argv and bounded inventory.'
