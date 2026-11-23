param([Parameter(Mandatory)][string]$Python)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot '../../eng/pilot/PilotNativeProcess.ps1')
. (Join-Path $PSScriptRoot '../../eng/pilot/PilotNativeExecutableLease.ps1')
$Python=(Get-Command $Python -CommandType Application).Source
$target=([IO.FileInfo]::new($Python)).ResolveLinkTarget($true);if($null -ne $target){$Python=$target.FullName}
$pin=(Get-FileHash -LiteralPath $Python -Algorithm SHA256).Hash.ToLowerInvariant()
$lease=[Fleetory.Pilot.NativeExecutableLease]::new($Python,$pin)
try{
 foreach($bound in @(0,67108865)){
  $failed=$false
  try{$null=Invoke-NativeBytes $Python @('-I','-S','-B','-c','raise SystemExit(99)') -TimeoutSeconds 5 -DockerClientEnvironment -ExecutableLease $lease -OutputLimit $bound}
  catch{if($_.Exception.GetBaseException().Message -cne 'Native output limit outside original bound.'){throw};$failed=$true}
  if(-not $failed){throw 'Invalid output limit admitted.'}
 }
 $reply=Invoke-NativeBytes $Python @('-I','-S','-B','-c','import os;os.write(1,b"x")') -TimeoutSeconds 5 -DockerClientEnvironment -ExecutableLease $lease -OutputLimit 1
 if($reply.ExitCode -ne 0 -or $reply.StdoutBytes.Length -ne 1 -or $reply.Stdout -cne 'x'){throw 'Exact lower output limit failed.'}
 $failed=$false
 try{$null=Invoke-NativeBytes $Python @('-I','-S','-B','-c','import os;os.write(1,b"x"*1025)') -TimeoutSeconds 5 -DockerClientEnvironment -ExecutableLease $lease -OutputLimit 1024}
 catch{if($_.Exception.GetBaseException().Message -cne 'Bounded native process I/O failed.'){throw};$failed=$true}
 if(-not $failed){throw 'Reduced output limit overflow accepted.'}
}finally{$lease.Dispose()}
Write-Output 'REDUCED NATIVE OUTPUT LIMIT PASS:2 early bound refusals,1 exact-limit child and1 actual overflow child; original64MiB ceiling unchanged.'
