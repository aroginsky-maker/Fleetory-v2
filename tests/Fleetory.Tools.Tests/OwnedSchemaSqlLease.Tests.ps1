$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot '../../eng/pilot/AuditDataResourceOwnership.ps1')
$script:checks=0;$script:reads=0;$script:alive=$true;$script:image='sha256:'+('b'*64);$script:cid='c'*64
function Check($Value,$Message){if(-not $Value){throw $Message};$script:checks++}
function Refuse([scriptblock]$Call,$Message){$failed=$false;try{$null=&$Call}catch{$failed=$true};Check $failed $Message}
function Model {
 $ctx=@{Fixture=[guid]::NewGuid().ToString('D');Root='generated';ImageName='generated';ProbeHash=('a'*64);ImageId=$null;ImageClaimed=$false;LifetimeSeconds=75;Stores=[Collections.ArrayList]::new()}
 $client=[object]::new();$build=[Func[Tuple[int,byte[],byte[]]]]{[Tuple]::Create(0,[Text.Encoding]::ASCII.GetBytes($script:image+"`n"),[byte[]]@())}
 $null=[Fleetory.Pilot.AuditImageCustody]::Build($ctx,$client,[byte[]]@(1),$build)
 $store=@{Session=[guid]::NewGuid().ToString('D');Name='model';Role='public-restore-schema';Started=[DateTimeOffset]::UtcNow;Id=$null};$null=$ctx.Stores.Add($store)
 $created=[Func[Tuple[int,byte[],byte[]]]]{[Tuple]::Create(0,[Text.Encoding]::ASCII.GetBytes($script:cid+"`n"),[byte[]]@())}
 $null=[Fleetory.Pilot.AuditContainerCustody]::Create($ctx,$store,$client,$created)
 return @{Context=$ctx;Store=$store;Client=$client}
}
function CloseStore($M){
 $removed=[Func[Tuple[int,byte[],byte[]]]]{[Tuple]::Create(0,[Text.Encoding]::ASCII.GetBytes($script:cid+"`n"),[byte[]]@())}
 $absent=[Func[Tuple[int,byte[],byte[]]]]{[Tuple]::Create(1,[byte[]]@(),[Text.Encoding]::ASCII.GetBytes('Error: no such container: '+$script:cid+"`n"))}
 [Fleetory.Pilot.AuditContainerCustody]::Remove($M.Context,$M.Store,$M.Client,$removed)
 [Fleetory.Pilot.AuditContainerCustody]::ConfirmRemoval($M.Context,$M.Store,$M.Client,$absent)
}
function Capture($M){
 $read=[Func[Tuple[int,byte[],byte[]]]]{ $script:reads++;[Tuple]::Create(0,[Text.Encoding]::UTF8.GetBytes($script:body),[byte[]]@()) }
 $script:captureClock=[Diagnostics.Stopwatch]::StartNew()
 return [Fleetory.Pilot.PublicOwnedSchemaLease]::Capture($M.Context,$M.Store,$M.Client,[Func[bool]]{return $script:alive},$script:captureClock,$read)
}
$cases=@('normal','premature-take','premature-complete','context-copy','client-copy','controller-loss','image-closed','json-copy','duplicate-key','nonboolean','oversize-sql','empty-sql','wrong-kind','repeat-capture','clock-stopped','capture-context-copy','capture-store-copy','capture-client-copy')
foreach($case in $cases){
 $m=Model;$lease=$null;$script:alive=$true;$script:reads=0
 $script:body='{"category":"restore-schema","databaseOpened":false,"httpHostStarted":false,"issuerActivated":false,"sql":"SELECT 1;"}'
 switch($case){
  'duplicate-key'{$script:body=$script:body.Replace('"sql":','"sql":"x","sql":')}
  'nonboolean'{$script:body=$script:body.Replace('"databaseOpened":false','"databaseOpened":"false"')}
  'oversize-sql'{$script:body=$script:body.Replace('SELECT 1;',('x'*131073))}
  'empty-sql'{$script:body=$script:body.Replace('SELECT 1;','')}
  'wrong-kind'{$script:body='[]'}
 }
 try{
  if($case.StartsWith('capture-')){
   $bad=$m.Clone()
   if($case -ceq 'capture-context-copy'){$bad.Context=$m.Context.Clone()}
   elseif($case -ceq 'capture-store-copy'){$bad.Store=$m.Store.Clone()}
   else{$bad.Client=[object]::new()}
   Refuse {Capture $bad} 'copied original capture input accepted'
   Check ($script:reads -eq 0) 'copied capture input invoked native reader'
  }
  if($case -cin @('duplicate-key','nonboolean','oversize-sql','empty-sql','wrong-kind')){
   Refuse {Capture $m} ('invalid native response '+$case)
   Check ($script:reads -eq 1) 'failed capture did not call original reader once'
   Refuse {Capture $m} 'failed native capture repaired'
   Check ($script:reads -eq 1) 'failed capture called reader twice';CloseStore $m;continue
  }
  $lease=Capture $m;Check ($script:reads -eq 1) 'native capture called once'
  if($case -ceq 'repeat-capture'){
   Refuse {Capture $m} 'same live image read twice';Check ($script:reads -eq 1) 'duplicate native reader invoked'
  }
  if($case -ceq 'premature-take'){
   Refuse {$lease.TakeSql($m.Context,$m.Client)} 'premature SQL accepted';CloseStore $m
   Refuse {$lease.Complete()} 'premature take repaired';continue
  }
  if($case -ceq 'premature-complete'){
   Refuse {$lease.Complete()} 'live container accepted';CloseStore $m
   Refuse {$lease.Complete()} 'premature completion repaired';continue
  }
  CloseStore $m;$lease.Complete()
  if($case -ceq 'clock-stopped'){$script:captureClock.Stop()}
  if($case -ceq 'controller-loss'){$script:alive=$false}
  if($case -ceq 'image-closed'){
   [Fleetory.Pilot.AuditImageCustody]::Remove($m.Context,$m.Client,[Func[Tuple[int,byte[],byte[]]]]{[Tuple]::Create(0,[Text.Encoding]::ASCII.GetBytes('Deleted: '+$script:image+"`n"),[byte[]]@())})
   [Fleetory.Pilot.AuditImageCustody]::ConfirmRemoval($m.Context,$m.Client,[Func[Tuple[int,byte[],byte[]]]]{[Tuple]::Create(1,[byte[]]@(),[Text.Encoding]::ASCII.GetBytes('Error: no such image: '+$script:image+"`n"))})
  }
  if($case -ceq 'json-copy'){
   $copy=$lease|ConvertTo-Json -Compress|ConvertFrom-Json
   $take={param([Fleetory.Pilot.PublicOwnedSchemaLease]$Value)$Value.TakeSql($m.Context,$m.Client)}
   Refuse {&$take $copy} 'serialized lease imported'
  }
  if($case -cin @('controller-loss','image-closed','clock-stopped')){
   Refuse {$lease.TakeSql($m.Context,$m.Client)} 'closed original source accepted';continue
  }
  if($case -ceq 'context-copy'){
   Refuse {$lease.TakeSql($m.Context.Clone(),$m.Client)} 'cloned context accepted'
   Refuse {$lease.TakeSql($m.Context,$m.Client)} 'failed context claim repaired';continue
  }
  if($case -ceq 'client-copy'){
   Refuse {$lease.TakeSql($m.Context,[object]::new())} 'substituted client accepted'
   Refuse {$lease.TakeSql($m.Context,$m.Client)} 'failed client claim repaired';continue
  }
  Check ($lease.SqlSha256() -ceq '17db4fd369edb9244b9f91d9aeed145c3d04ad8ba6e95d06247f07a63527d11a') 'public SQL digest mismatch'
  $sql=$lease.TakeSql($m.Context,$m.Client);Check ([Text.Encoding]::UTF8.GetString($sql) -ceq 'SELECT 1;') 'SQL bytes changed'
  Refuse {$lease.TakeSql($m.Context,$m.Client)} 'SQL replay accepted'
 }finally{if($null -ne $lease){$lease.Dispose()}}
}
Write-Output "ORIGINAL SQL LEASE PROTOTYPE PASS: $($cases.Count) cases;$script:checks assertions;native replies modeled;no Docker or original inputs."
