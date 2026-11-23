#requires -Version 7.3
param([Parameter(Mandatory)][string]$Repository,[Parameter(Mandatory)][string]$Python,[ValidateSet('alive','eof','byte')][string]$Case)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
. (Join-Path $Repository 'eng/pilot/ImmuDataRoundtripPolicy.ps1')
. (Join-Path $Repository 'eng/pilot/HistoricalRecoveryInFlight.ps1')
. (Join-Path $Repository 'eng/pilot/historical/RetainedControllerPipe.ps1')
$clock=[Diagnostics.Stopwatch]::StartNew();$context=$null;$refused=0;$snapshot=$null
try{
 $context=New-RetainedControllerPipe $Python $clock
 Assert-RetainedControllerPipe $context
 foreach($fake in @([object]::new(),([pscustomobject]@{ownerId=$PID}),($context|ConvertTo-Json|ConvertFrom-Json))){
  try{$null=Get-RetainedControllerPipeSnapshot $fake;throw 'Copied controller context accepted'}catch{
   if($_.Exception.GetBaseException().Message -cne 'Audit data fixture refused: controller-pipe-original-context'){throw};$refused++
  }
 }
 try{$null=New-RetainedControllerPipe $Python $clock;throw 'Controller stream reused'}catch{
  if($_.Exception.GetBaseException().Message -cne 'Audit data fixture refused: controller-pipe-one-use'){throw};$refused++
 }
 Arm-RetainedControllerPipe $context '01234567-89ab-cdef-0123-456789abcdef'
 if($Case -ceq 'alive'){
  try{Arm-RetainedControllerPipe $context '01234567-89ab-cdef-0123-456789abcdef';throw 'Controller rearmed'}catch{
   if($_.Exception.GetBaseException().Message -cne 'Audit data fixture refused: controller-pipe-arm'){throw};$refused++
  }
 }else{
  $wait=[Diagnostics.Stopwatch]::StartNew();$lost=$false
  while($wait.Elapsed.TotalSeconds -lt 5){
   try{Assert-RetainedControllerPipe $context}catch{
    if($_.Exception.GetBaseException() -isnot [OperationCanceledException]){throw};$lost=$true;break
   }
   Start-Sleep -Milliseconds 20
  }
  if(-not $lost){throw 'Controller input loss was not observed'}
  try{Assert-RetainedControllerPipe $context;throw 'Lost controller readmitted'}catch{
   if($_.Exception.GetBaseException() -isnot [OperationCanceledException]){throw};$refused++
  }
 }
 $snapshot=Get-RetainedControllerPipeSnapshot $context
 if($Case -cne 'alive'){
  $final=Get-RetainedControllerPipeFinalSnapshot $context
  if(-not $final.lossObserved -or $final.parentExited -or $final.lossKind -cne $snapshot.lossKind){throw 'Live-parent EOF final snapshot drift'}
 }
}finally{Close-RetainedControllerPipe $context}
try{$null=Get-RetainedControllerPipeSnapshot $context;throw 'Closed context accepted'}catch{
 if($_.Exception.GetBaseException().Message -cne 'Audit data fixture refused: controller-pipe-original-context'){throw};$refused++
}
if($refused -ne 6){throw 'Controller refusal count drift'}
@{schema='fleetory.controller-pipe-contract.v1';case=$Case;refusals=$refused;snapshot=$snapshot;nativeResourcesCreated=$false;cleanupVerified=$false}|ConvertTo-Json -Compress -Depth 6
exit 0
