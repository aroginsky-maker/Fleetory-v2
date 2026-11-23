$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot '../../eng/pilot/PublicOwnedRestoreSchema.ps1')
$script:nativeCalls=0
function Invoke-NativeBytes { $script:nativeCalls++;throw 'Unexpected actual native call in refusal fixture.' }
$docker=if($IsWindows){Join-Path ([IO.Path]::GetTempPath()) 'docker.exe'}else{'/tmp/docker'}
$script:fakeId='sha256:'+('d'*64)
function ModelImage {
 $ctx=@{Fixture=[guid]::NewGuid().ToString('D');Root='generated-public';ImageName='generated';ProbeHash=('b'*64);ImageId=$null;ImageClaimed=$false}
 $client={};$reply=[Func[Tuple[int,byte[],byte[]]]]{[Tuple]::Create(0,[Text.Encoding]::ASCII.GetBytes($script:fakeId+"`n"),[byte[]]@())}
 $null=[Fleetory.Pilot.AuditImageCustody]::Build($ctx,$client,[byte[]]@(1,2,3),$reply)
 return @{Context=$ctx;Client=$client;Reply=$reply}
}
$script:cases=0
function Reject([scriptblock]$Call,[string]$Expected,[string]$Config){
 $failed=$false
 try{$null=& $Call}catch{
  $error=$_.Exception.GetBaseException()
  if($Expected -ceq 'duplicate-attempt'){
   if($error -isnot [ArgumentException]){throw}
  }elseif($error.Message -cne $Expected){throw}
  $failed=$true
 }
 if(-not $failed -or $script:nativeCalls -ne 0 -or (Test-Path -LiteralPath $Config)){throw 'Unsafe schema refusal or late native/file work.'}
 $script:cases++
}
$model=ModelImage;$ctx=$model.Context;$client=$model.Client
$config=Join-Path ([IO.Path]::GetTempPath()) ('schema-refused-'+[guid]::NewGuid().ToString('N'))
Reject {Invoke-PublicOwnedRestoreSchema $docker ('a'*64) $config ($ctx.Clone()) $client {return $true}} 'Audit image live custody refused.' $config
Reject {Invoke-PublicOwnedRestoreSchema $docker ('a'*64) $config $ctx {} {return $true}} 'Audit image live custody refused.' $config
Reject {Invoke-PublicOwnedRestoreSchema $docker ('a'*64) $config $ctx $client {return $false}} 'Original schema controller unavailable or expired.' $config
Reject {Invoke-PublicOwnedRestoreSchema $docker ('a'*64) $config $ctx $client {return $true}} 'duplicate-attempt' $config
$model=ModelImage;$ctx=$model.Context;$client=$model.Client
Reject {Invoke-PublicOwnedRestoreSchema $docker ('a'*64) $config $ctx $client {return @($true,$true)}} 'Original schema controller unavailable or expired.' $config
Reject {Invoke-PublicOwnedRestoreSchema $docker ('a'*64) 'relative-config' $ctx $client {return $true}} 'Original schema owner inputs refused.' $config
Reject {Invoke-PublicOwnedRestoreSchema 'other-program' ('a'*64) $config $ctx $client {return $true}} 'Original schema owner inputs refused.' $config
[Fleetory.Pilot.AuditImageCustody]::Remove($ctx,$client,[Func[Tuple[int,byte[],byte[]]]]{[Tuple]::Create(0,[Text.Encoding]::ASCII.GetBytes('Deleted: '+$script:fakeId+"`n"),[byte[]]@())})
[Fleetory.Pilot.AuditImageCustody]::ConfirmRemoval($ctx,$client,[Func[Tuple[int,byte[],byte[]]]]{[Tuple]::Create(1,[byte[]]@(),[Text.Encoding]::ASCII.GetBytes('Error: no such image: '+$script:fakeId+"`n"))})
Reject {Invoke-PublicOwnedRestoreSchema $docker ('a'*64) $config $ctx $client {return $true}} 'Audit image live custody refused.' $config
Write-Output "OWNED SCHEMA REFUSALS PASS: $script:cases cases;0 native calls/config creation; image replies modeled, no Docker/original data/authority."
