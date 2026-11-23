param([Parameter(Mandatory)][string]$Python)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot '../../eng/pilot/PublicOwnedRestoreSchema.ps1')
# A copied public interpreter is only an ordinary, held identity fixture. It is
# never executed: every schema native call is intercepted by the model below.
$fixtureRoot=Join-Path ([IO.Path]::GetTempPath()) ('schema-executable-model-'+[guid]::NewGuid().ToString('N'))
$null=[IO.Directory]::CreateDirectory($fixtureRoot)
$Docker=Join-Path $fixtureRoot $(if($IsWindows){'docker.exe'}else{'docker'})
[IO.File]::Copy((Get-Command $Python -CommandType Application).Source,$Docker,$false)
try {
$pin=(Get-FileHash -LiteralPath $Docker -Algorithm SHA256).Hash.ToLowerInvariant()
$script:fakeImage='sha256:'+('d'*64);$script:fakeContainer='c'*64;$script:checks=0
function Check($Value,$Message){if(-not $Value){throw $Message};$script:checks++}
function Reply([int]$Code,[string]$Out='', [string]$Err=''){
 return @{ExitCode=$Code;StdoutBytes=[Text.Encoding]::UTF8.GetBytes($Out);StderrBytes=[Text.Encoding]::UTF8.GetBytes($Err)}
}
function ModelImage {
 $ctx=@{Fixture=[guid]::NewGuid().ToString('D');Root='generated-public';ImageName='generated';ProbeHash=('b'*64);ImageId=$null;ImageClaimed=$false}
 $client={};$reply=[Func[Tuple[int,byte[],byte[]]]]{[Tuple]::Create(0,[Text.Encoding]::ASCII.GetBytes($script:fakeImage+"`n"),[byte[]]@())}
 $null=[Fleetory.Pilot.AuditImageCustody]::Build($ctx,$client,[byte[]]@(1,2,3),$reply)
 return @{Context=$ctx;Client=$client}
}
function Profile {
 return @{Id=$script:fakeContainer;Image=$script:fakeImage;Config=@{Image=$script:fakeImage;User='3322:3322';Entrypoint=@('dotnet');Cmd=@('/tool/ServerBackendProbe.dll','restore-schema')};State=@{Status='created';Running=$false;Pid=0};Mounts=@();HostConfig=@{NetworkMode='none';ReadonlyRootfs=$true;Privileged=$false;AutoRemove=$false;Memory=268435456;NanoCpus=1000000000;PidsLimit=64;CapDrop=@('ALL');CapAdd=@();PidMode='';IpcMode='private';UTSMode='';Binds=@();Devices=@();DeviceRequests=@();SecurityOpt=@('no-new-privileges:true');RestartPolicy=@{Name='no'};Tmpfs=@{'/tmp'='rw,noexec,nosuid,nodev,size=67108864,uid=3322,gid=3322,mode=0700'}}}
}
function Invoke-NativeBytes($File,[string[]]$Arguments,[int]$TimeoutSeconds,$ObserveProcess,[switch]$DockerClientEnvironment,$ExecutableLease,[int]$OutputLimit){
 Check ($File -ceq $Docker -and $TimeoutSeconds -eq 15 -and $OutputLimit -eq 262144 -and $DockerClientEnvironment -and $null -ne $ExecutableLease) 'fixed native boundary changed'
 Check ($Arguments[0] -ceq '--config' -and $Arguments[1] -ceq $script:config -and $Arguments[2] -ceq '--host') 'private endpoint/config changed'
 $expected=if($IsWindows){'npipe:////./pipe/dockerDesktopLinuxEngine'}else{'unix:///var/run/docker.sock'}
 Check ($Arguments[3] -ceq $expected) 'native endpoint changed'
 $a=$Arguments[4..($Arguments.Count-1)];$script:commands.Add(($a -join '|'))
 if($a[0] -ceq 'create'){
  Check (($a[-3..-1] -join '|') -ceq ($script:fakeImage+'|/tool/ServerBackendProbe.dll|restore-schema')) 'image/schema argv changed'
  Check (($a -contains '--network=none') -and ($a -contains '--read-only') -and ($a -contains '--restart=no') -and ($a -contains '--user=3322:3322')) 'fixed create boundary changed'
  Check ($null -ne $ObserveProcess) 'create observer missing'
  return Reply 0 $script:createReply
 }
 if($a[0] -ceq 'inspect'){
  if($script:removed){return Reply 1 '' ('Error: no such container: '+$script:fakeContainer+"`n")}
  Check ($null -ne $ObserveProcess) 'inspect observer missing'
  return Reply 0 ($script:profile|ConvertTo-Json -Depth 10 -Compress)
 }
 if($a[0] -ceq 'start'){
  Check (($a -join '|') -ceq ('start|--attach|'+$script:fakeContainer)) 'start target changed'
  Check ($null -ne $ObserveProcess) 'start observer missing'
  return Reply $script:runCode $script:runReply $script:runError
 }
 if($a[0] -ceq 'rm'){
  Check (($a -join '|') -ceq ('rm|--force|'+$script:fakeContainer)) 'cleanup target changed'
  Check ($null -eq $ObserveProcess) 'cleanup inherited dead controller observer'
  $script:removed=$true;return Reply 0 ($script:fakeContainer+"`n")
 }
 throw 'Unexpected modeled native operation'
}
$mutations=@{
 'image'={ $script:profile.Image='sha256:'+('e'*64) }
 'config-image'={ $script:profile.Config.Image='alias' }
 'running'={ $script:profile.State.Running=$true }
 'pid'={ $script:profile.State.Pid=1 }
 'status'={ $script:profile.State.Status='exited' }
 'user'={ $script:profile.Config.User='0:0' }
 'entrypoint'={ $script:profile.Config.Entrypoint=@('sh') }
 'command'={ $script:profile.Config.Cmd=@('/tool/ServerBackendProbe.dll','serve') }
 'network'={ $script:profile.HostConfig.NetworkMode='host' }
 'readonly'={ $script:profile.HostConfig.ReadonlyRootfs=$false }
 'privileged'={ $script:profile.HostConfig.Privileged=$true }
 'autoremove'={ $script:profile.HostConfig.AutoRemove=$true }
 'mount'={ $script:profile.Mounts=@(@{Source='/';Destination='/host'}) }
 'memory'={ $script:profile.HostConfig.Memory=268435457 }
 'cpu'={ $script:profile.HostConfig.NanoCpus=1000000001 }
 'pids'={ $script:profile.HostConfig.PidsLimit=65 }
 'cap-drop'={ $script:profile.HostConfig.CapDrop=@() }
 'cap-add'={ $script:profile.HostConfig.CapAdd=@('SYS_ADMIN') }
 'pid-mode'={ $script:profile.HostConfig.PidMode='host' }
 'ipc-mode'={ $script:profile.HostConfig.IpcMode='host' }
 'uts-mode'={ $script:profile.HostConfig.UTSMode='host' }
 'bind'={ $script:profile.HostConfig.Binds=@('/:/host') }
 'device'={ $script:profile.HostConfig.Devices=@('device') }
 'gpu'={ $script:profile.HostConfig.DeviceRequests=@('device') }
 'nnp'={ $script:profile.HostConfig.SecurityOpt=@() }
 'restart'={ $script:profile.HostConfig.RestartPolicy.Name='always' }
 'tmpfs'={ $script:profile.HostConfig.Tmpfs['/tmp']='rw,exec' }
 'extra-tmpfs'={ $script:profile.HostConfig.Tmpfs['/other']='rw' }
 'wrong-id'={ $script:profile.Id='e'*64 }
 'opened-database'={ $script:runReply=$script:runReply.Replace('"databaseOpened":false','"databaseOpened":true') }
 'started-http'={ $script:runReply=$script:runReply.Replace('"httpHostStarted":false','"httpHostStarted":true') }
 'issuer'={ $script:runReply=$script:runReply.Replace('"issuerActivated":false','"issuerActivated":true') }
 'empty-sql'={ $script:runReply=$script:runReply.Replace('SELECT 1;','') }
 'duplicate-key'={ $script:runReply=$script:runReply.Replace('"sql":','"sql":"extra","sql":') }
 'extra-key'={ $script:runReply=$script:runReply.Replace('"sql":','"extra":false,"sql":') }
 'wrong-category'={ $script:runReply=$script:runReply.Replace('restore-schema','serve') }
 'stderr'={ $script:runError='failed' }
 'exit-code'={ $script:runCode=1 }
}
$cases=@('normal','controller-loss','invalid-create')+@($mutations.Keys|Sort-Object)
foreach($case in $cases){
 $model=ModelImage;$script:config=Join-Path ([IO.Path]::GetTempPath()) ('owned-schema-model-'+[guid]::NewGuid().ToString('N'))
 $script:profile=Profile;$script:removed=$false;$script:alive=$true;$script:commands=[Collections.Generic.List[string]]::new()
 $script:createReply=$script:fakeContainer+"`n";$script:runCode=0;$script:runError=''
 $script:runReply='{"category":"restore-schema","databaseOpened":false,"httpHostStarted":false,"issuerActivated":false,"sql":"SELECT 1;"}'
 if($mutations.ContainsKey($case)){$null=& $mutations[$case]}
 if($case -ceq 'invalid-create'){$script:createReply+='extra'}
 $ready={param($Id)if($case -ceq 'controller-loss'){$script:alive=$false}}
 $failed=$false;$result=$null
 try{$result=Invoke-PublicOwnedRestoreSchema $Docker $pin $script:config $model.Context $model.Client {return $script:alive} $ready}catch{$failed=$true}
 Check ($failed -eq ($case -cne 'normal')) ('unexpected result '+$case)
 Check (-not (Test-Path -LiteralPath $script:config)) ('config cleanup '+$case)
 if($case -ceq 'invalid-create'){
  Check (-not $script:removed -and $script:commands.Count -eq 1) 'malformed create acquired cleanup or later native authority'
 }else{
  Check $script:removed ('original known container cleanup '+$case)
  $store=$model.Context.Stores[0]
  Check ([Fleetory.Pilot.AuditContainerCustody]::Closed($model.Context,$store,$model.Client)) ('original removal not confirmed '+$case)
 }
 if($case -ceq 'normal'){Check ($result.verified -and $result.sql -ceq 'SELECT 1;' -and $result.originalContainerClaimClosed) 'normal schema response'}
 if($case -cin @('controller-loss') -or $case -cin $mutations.Keys -and $case -cnotin @('opened-database','started-http','issuer','empty-sql','duplicate-key','extra-key','wrong-category','stderr','exit-code')){
  Check (-not @($script:commands|Where-Object { $_.StartsWith('start|') }).Count) ('late start after refusal '+$case)
 }
 $count=$script:commands.Count;$replayed=$false
 try{$null=Invoke-PublicOwnedRestoreSchema $Docker $pin $script:config $model.Context $model.Client {return $true}}catch{$replayed=$true}
 Check ($replayed -and $script:commands.Count -eq $count) ('attempt repaired or replayed '+$case)
}
Write-Output "OWNED SCHEMA NATIVE REPLIES PASS: $($cases.Count) cases;$script:checks assertions;native replies modeled;no actual Docker calls/original inputs."

}finally{
 if([IO.Path]::GetDirectoryName($Docker) -cne $fixtureRoot){throw 'Own model executable root mismatch'}
 [IO.File]::Delete($Docker)
 [IO.Directory]::Delete($fixtureRoot,$false)
}
