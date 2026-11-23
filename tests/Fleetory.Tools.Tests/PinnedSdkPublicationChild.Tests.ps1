param([Parameter(Mandatory)][string]$Python)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'eng/pilot/AuditDataResourceOwnership.ps1')
. (Join-Path $root 'eng/pilot/PilotNativeExecutableLease.ps1')
$script:checks=0
function Check($value,$label){if(-not $value){throw $label};$script:checks++}
function Refuse([scriptblock]$operation,$label){$failed=$false;try{&$operation}catch{$failed=$true};Check $failed $label}
function New-ModelSdk {
 $script:image='sha256:'+('b'*64);$script:cid='c'*64
 $imageContext=@{Fixture=[guid]::NewGuid().ToString('D');Root='public';ImageName='public';SourceContextSha256=('a'*64);SdkImage='sdk';ImageId=$null;ImageClaimed=$false}
 $imageClient=[object]::new();$nativeClient=[object]::new()
 $build=[Func[Tuple[int,byte[],byte[]]]]{[Tuple]::Create(0,[Text.Encoding]::ASCII.GetBytes($script:image+"`n"),[byte[]]@())}
 $null=[Fleetory.Pilot.PublicBuildImageCustody]::Build($imageContext,$imageClient,[byte[]]@(1),$build)
 $store=@{Session=[guid]::NewGuid().ToString('D');Name='generated';Role='public-sdk';Started=$false;Id=$null}
 $stack=@{Fixture='generated';ImageName='generated';ImageId=$script:image;LifetimeSeconds=300;Stores=@($store)}
 $reply=[Func[Tuple[int,byte[],byte[]]]]{[Tuple]::Create(0,[Text.Encoding]::ASCII.GetBytes($script:cid+"`n"),[byte[]]@())}
 $null=[Fleetory.Pilot.AuditContainerCustody]::Create($stack,$store,$nativeClient,$reply)
 $script:raw=[Convert]::FromBase64String($fixture.archive)
 $tar=[Func[Tuple[int,byte[],byte[]]]]{[Tuple]::Create(0,$script:raw,[byte[]]@())}
 $sdk=[Fleetory.Pilot.PublicSdkOutputLease]::Capture($imageContext,$imageClient,$stack,$store,$nativeClient,[Func[bool]]{return $true},[Diagnostics.Stopwatch]::StartNew(),$tar)
 [Fleetory.Pilot.AuditContainerCustody]::Remove($stack,$store,$nativeClient,$reply)
 $absent=[Func[Tuple[int,byte[],byte[]]]]{[Tuple]::Create(1,[byte[]]@(),[Text.Encoding]::ASCII.GetBytes('Error: no such container: '+$script:cid+"`n"))}
 [Fleetory.Pilot.AuditContainerCustody]::ConfirmRemoval($stack,$store,$nativeClient,$absent)
 $sdk.Complete();return $sdk
}
$Python=(Get-Command $Python -CommandType Application).Source
$target=([IO.FileInfo]::new($Python)).ResolveLinkTarget($true)
if($null -ne $target){$Python=$target.FullName}
$hash=(Get-FileHash -LiteralPath $Python -Algorithm SHA256).Hash.ToLowerInvariant()
$fixtureStart=[Diagnostics.ProcessStartInfo]::new($Python)
$fixtureStart.UseShellExecute=$false;$fixtureStart.CreateNoWindow=$true
$fixtureStart.RedirectStandardOutput=$true;$fixtureStart.RedirectStandardError=$true
$fixtureStart.Environment.Clear()
if($IsWindows){$fixtureStart.Environment['SystemRoot']=[Environment]::GetEnvironmentVariable('SystemRoot')}
foreach($a in @('-I','-S','-B',(Join-Path $PSScriptRoot 'sdk_publication_fixture.py'))){$fixtureStart.ArgumentList.Add($a)}
$fixtureChild=[Diagnostics.Process]::Start($fixtureStart)
try{
 $fixtureText=$fixtureChild.StandardOutput.ReadToEndAsync();$fixtureError=$fixtureChild.StandardError.ReadToEndAsync()
 if(-not $fixtureChild.WaitForExit(5000)){$fixtureChild.Kill();$null=$fixtureChild.WaitForExit(5000);throw 'Generated fixture deadline refused'}
 if($fixtureChild.ExitCode -ne 0 -or $fixtureError.GetAwaiter().GetResult() -cne ''){throw 'Generated fixture setup failed'}
 $fixture=$fixtureText.GetAwaiter().GetResult()|ConvertFrom-Json
}finally{$fixtureChild.Dispose()}
foreach($mode in @('normal','copied-sdk','copied-process','context-replay','peer-death','controller-loss','argv-drift','environment-drift')){
 $nonce=[guid]::NewGuid().ToString('N');$temp=Join-Path ([IO.Path]::GetTempPath()) ('fleetory-sdk-publication-'+$nonce)
 $null=[IO.Directory]::CreateDirectory((Join-Path $temp 'controls'))
 $null=[IO.Directory]::CreateDirectory((Join-Path $temp 'repository/artifacts'))
 $plan=[Text.Encoding]::UTF8.GetBytes($fixture.planTemplate.Replace('00000000-0000-0000-0000-000000000001',([guid]::ParseExact($nonce,'N').ToString('D'))))
 $sdk=New-ModelSdk;$lease=[Fleetory.Pilot.NativeExecutableLease]::new($Python,$hash)
 $child=[Diagnostics.Process]::new();$pipe=$null;$copy=$null;$started=$false;$factory=$null
 try{
  $script:alive=$true;$alive=[Func[bool]]{return $script:alive}
  $scope=[Diagnostics.Stopwatch]::StartNew();$age=[Diagnostics.Stopwatch]::StartNew()
  $bootstrap=[IO.File]::ReadAllBytes((Join-Path $root 'eng/pilot/public_build/publication_bootstrap.py'))
  $frame=[Convert]::FromBase64String($fixture.codeFrame)
  # Generated fixture pins only. Production caller must use independent protected commitments.
  $bootstrapPin=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bootstrap)).ToLowerInvariant()
  $framePin=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($frame)).ToLowerInvariant()
  $nativeStart=[Action[Diagnostics.Process]]{param($p)$lease.Start($p)}
  $nativeValidate=[Action[Diagnostics.Process]]{param($p)[Fleetory.Pilot.NativeExecutableLease]::AssertStarted($p)}
  $factory=[Fleetory.Pilot.PublicSdkPublicationChild]::Start($lease.GetLaunchPath(),$bootstrap,$bootstrapPin,$frame,$framePin,$temp,$nonce,$scope,$alive,$nativeStart,$nativeValidate)
  $child.Dispose();$child=$factory.OriginalProcess();$started=$true
  $validate=[Action[Diagnostics.Process]]{param($p)$factory.Assert($p)}
  if($mode -cin @('argv-drift','environment-drift')){
   if($mode -ceq 'argv-drift'){$child.StartInfo.ArgumentList[3]='-m'}else{$child.StartInfo.Environment['PYTHONPATH']='untrusted'}
   Refuse {$null=$factory.Open($sdk,$plan)} 'changed launch request refused before SDK consumption'
   Check ($sdk.GetByteCount() -gt 0) 'launch drift did not consume SDK bytes'
   continue
  }
  if($mode -ceq 'copied-sdk'){
   $copiedSdk=@{Type='Fleetory.Pilot.PublicSdkOutputLease';Bytes=$script:raw} | ConvertTo-Json -Depth 3 -Compress | ConvertFrom-Json
   Refuse {$null=[Fleetory.Pilot.PublicSdkPublicationPipe]::Open($copiedSdk,$child,$scope,$age,$alive,$validate,$nonce,$plan)} 'serialized SDK object refused'
   Check ($sdk.GetByteCount() -gt 0) 'metadata copy did not consume original SDK object'
   Check (-not $child.HasExited) 'metadata copy did not acquire child cleanup'
   continue
  }
  if($mode -ceq 'copied-process'){
   $copy=[Diagnostics.Process]::GetProcessById($child.Id)
   Refuse {$null=[Fleetory.Pilot.PublicSdkPublicationPipe]::Open($sdk,$copy,$scope,$age,$alive,$validate,$nonce,$plan)} 'copied process rejected'
   Check (-not $child.HasExited) 'foreign Process wrapper did not kill original'
   Refuse {$null=[Fleetory.Pilot.PublicSdkPublicationPipe]::Open($sdk,$child,$scope,$age,$alive,$validate,$nonce,$plan)} 'failed admission cannot repair'
   continue
  }
  $pipe=$factory.Open($sdk,$plan)
  Check ($pipe.Manifest().Length -gt 0) 'actual peer manifest'
  Refuse {$null=$sdk.Take()} 'SDK consumed once'
  if($mode -ceq 'peer-death'){$child.Kill();$null=$child.WaitForExit(5000);Refuse {$null=$pipe.Manifest()} 'dead peer refused';continue}
  if($mode -ceq 'controller-loss'){$script:alive=$false;Refuse {$null=$pipe.Manifest()} 'lost controller refused';continue}
  $recipe=[Text.Encoding]::ASCII.GetBytes("FROM separately-approved-generated-fixture`n")
  Check ($pipe.Context($recipe).Length -gt 0) 'actual held-files context'
  if($mode -ceq 'context-replay'){Refuse {$null=$pipe.Context($recipe)} 'context replay refused'}
  # Dispose validates the final ack/exit and then disposes the original Process handle.
  $pipe.Dispose();$pipe=$null
 }finally{
  if($null -ne $pipe){try{$pipe.Dispose()}catch{}}
  if($started){try{if(-not $child.HasExited){$child.Kill();$null=$child.WaitForExit(5000)}}catch{}}
  if($null -ne $copy){$copy.Dispose()};$child.Dispose();if($null -ne $factory){$factory.Dispose()};$lease.Dispose();$sdk.Dispose()
  $expected=Join-Path ([IO.Path]::GetTempPath()) ('fleetory-sdk-publication-'+$nonce)
  if([IO.Path]::GetFullPath($temp) -cne [IO.Path]::GetFullPath($expected)){throw 'Own generated root mismatch'}
  [IO.Directory]::Delete($temp,$true)
 }
}
Write-Output "PINNED SDK PUBLICATION CHILD PASS: $script:checks assertions;8 actual child cases; SDK replies modeled, no Docker/original inputs/native authority."
