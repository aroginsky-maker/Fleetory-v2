param([string]$Repository,[string]$Python)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
. (Join-Path $Repository 'eng/pilot/ImmuDataRoundtripPolicy.ps1')
. (Join-Path $Repository 'eng/pilot/HistoricalRecoveryInFlight.ps1')
. (Join-Path $Repository 'eng/pilot/historical/RetainedControllerPipe.ps1')
$watch=[Diagnostics.Stopwatch]::StartNew();$context=$null
try{
 $context=New-RetainedControllerPipe $Python $watch
 try{$null=Get-RetainedControllerPipeFinalSnapshot $context;throw 'Live final snapshot accepted'}catch{
  if($_.Exception.GetBaseException().Message -cne 'Audit data fixture refused: controller-final-snapshot-requires-loss'){throw}
 }
 Arm-RetainedControllerPipe $context '01234567-89ab-cdef-0123-456789abcdef'
 $deadline=[Diagnostics.Stopwatch]::StartNew();$lost=$false
 while($deadline.ElapsedMilliseconds -lt 5000){
  try{Assert-RetainedControllerPipe $context}catch{
   if($_.Exception.GetBaseException() -isnot [OperationCanceledException]){throw};$lost=$true;break
  }
  Start-Sleep -Milliseconds 1
 }
 if(-not $lost){throw 'Parent loss not observed'}
 $early=Get-RetainedControllerPipeSnapshot $context
 $state=Read-RetainedControllerPipeState $context
 $waited=$state.parent.WaitForExit(1000)
 $late=Get-RetainedControllerPipeFinalSnapshot $context
 if(-not $waited -or -not $late.parentExited -or -not $late.lossObserved){throw 'Held parent final exit not verified'}
 @{schema='fleetory.parent-death-observation-diagnostic.v1';early=$early;late=$late;heldParentWaitReturned=$waited;nativeResourcesCreated=$false}|ConvertTo-Json -Depth 8 -Compress
}finally{Close-RetainedControllerPipe $context}
exit 0
