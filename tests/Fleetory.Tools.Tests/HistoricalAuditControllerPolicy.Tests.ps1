#requires -Version 7.3
param([int]$ObserveNativePid=0)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot '../../eng/pilot/ImmuDataRoundtripPolicy.ps1')
. (Join-Path $PSScriptRoot '../../eng/pilot/HistoricalAuditControllerPolicy.ps1')
. (Join-Path $PSScriptRoot '../../eng/pilot/HistoricalRecoveryInFlight.ps1')
if($ObserveNativePid -gt 0){
    $observer=[Diagnostics.Process]::GetProcessById($ObserveNativePid);$null=$observer.Handle
    try{Get-HistoricalNativeBirth $observer|ConvertTo-Json -Compress}
    finally{$observer.Dispose()}
    exit 0
}
$message="rpc error: code = DataLoss desc = transaction checksums don't match"
if(-not (Test-HistoricalArchiveChecksumRefusal @{ExitCode=1;Stdout='';Stderr=$message})){throw 'Typed archive checksum refusal not recognized.'}
if(Test-HistoricalArchiveChecksumRefusal @{ExitCode=0;Stdout='';Stderr=$message}){throw 'Success misclassified as checksum refusal.'}
$count=0
foreach($text in @('connection refused','unexpected EOF','malformed server response','TLS handshake failed',
    "rpc error: code = Unavailable desc = transaction checksums don't match",
    "rpc error: code = Unauthenticated desc = transaction checksums don't match",
    "rpc error: code = PermissionDenied desc = transaction checksums don't match",
    "rpc error: code = DeadlineExceeded desc = transaction checksums don't match")){
    if(Test-HistoricalArchiveChecksumRefusal @{ExitCode=1;Stdout='';Stderr=$text}){throw 'Operational error misclassified as archive checksum refusal.'}
    $count++
}
Write-Output ('HISTORICAL CONTROLLER POLICY PASS:'+ $count +' operational refusals separated;checksum failure andsuccess distinguished.')

$parent='12345678-1234-4123-8123-123456789abc'
$sourceBytes=[Text.Encoding]::UTF8.GetBytes((@{nonce=$parent;knownEvents=@('event-one','event-two')}|ConvertTo-Json -Compress))
$plan=@{schema='fleetory.historical-audit-restore-plan.v2';nonce=$parent;inputs=@{valuesSha256=(Get-ImmuDataHash $sourceBytes)}}
$packet=@{schema='fleetory.historical-audit-restore-packet.v1';planBase64='';valuesBase64=[Convert]::ToBase64String($sourceBytes)}
$beforePlan=ConvertTo-Json $plan -Depth 8 -Compress;$beforePacket=ConvertTo-Json $packet -Depth 8 -Compress
function New-CaseRegistry{return ,([Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal))}
function Case-Nonce([int]$Number){return 'abcdefab-1234-4123-8123-'+('{0:x12}' -f $Number)}
function Refused-Case([scriptblock]$Action,[string]$Category){
    $seen=$false
    try{$null=& $Action}catch{
        if($_.Exception.Message -cne ('Audit data fixture refused: '+$Category)){throw}
        $seen=$true
    }
    if(-not $seen){throw 'Generated controller case accepted invalid preparation.'}
}
$registry=New-CaseRegistry
foreach($n in 1..33){
    $case=New-HistoricalControllerCase $plan $packet (Case-Nonce $n) $registry
    $body=[Text.Encoding]::UTF8.GetString($case.bytes)|ConvertFrom-Json -AsHashtable
    $declared=[Convert]::FromBase64String($body.planBase64)
    $decoded=[Text.Encoding]::UTF8.GetString($declared)|ConvertFrom-Json -AsHashtable
    Assert-ImmuData ($case.nonce -ceq (Case-Nonce $n) -and $decoded.nonce -ceq $case.nonce -and
        $case.planSha256 -ceq (Get-ImmuDataHash $declared) -and $decoded.inputs.valuesSha256 -ceq $plan.inputs.valuesSha256 -and
        $body.valuesBase64 -ceq $packet.valuesBase64 -and
        ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($body.valuesBase64))|ConvertFrom-Json).nonce -ceq $parent) 'case-roundtrip'
}
Assert-ImmuData ($registry.Count -eq 33 -and (ConvertTo-Json $plan -Depth 8 -Compress) -ceq $beforePlan -and
    (ConvertTo-Json $packet -Depth 8 -Compress) -ceq $beforePacket) 'case-parent-unchanged'
Refused-Case {New-HistoricalControllerCase $plan $packet (Case-Nonce 34) $registry} 'controller-case-registry'
foreach($nonce in @($parent,[Guid]::Empty.ToString('D'),(Case-Nonce 1).ToUpperInvariant(),(Case-Nonce 1).Replace('-',''),'bad',$true,42)){
    Refused-Case {New-HistoricalControllerCase $plan $packet $nonce (New-CaseRegistry)} 'controller-case-nonce'
}
$used=New-CaseRegistry;$case=New-HistoricalControllerCase $plan $packet (Case-Nonce 1) $used
$frozen=Get-ImmuDataHash $case.bytes
$changed=($plan|ConvertTo-Json -Depth 8)|ConvertFrom-Json -AsHashtable;$changed.inputs.valuesSha256='0'*64
Refused-Case {New-HistoricalControllerCase $changed $packet (Case-Nonce 1) $used} 'controller-case-replay'
$originalPin=$plan.inputs.valuesSha256;$originalValues=$packet.valuesBase64
$plan.inputs.valuesSha256='changed';$packet.valuesBase64='changed'
Assert-ImmuData ((Get-ImmuDataHash $case.bytes) -ceq $frozen) 'case-frozen'
$plan.inputs.valuesSha256=$originalPin;$packet.valuesBase64=$originalValues
$oversized=$plan.Clone();$oversized.extra='x'*16384;$consumed=New-CaseRegistry
Refused-Case {New-HistoricalControllerCase $oversized $packet (Case-Nonce 2) $consumed} 'controller-case-bound'
Assert-ImmuData ($consumed.Contains((Case-Nonce 2))) 'case-preparation-consumed'
Refused-Case {New-HistoricalControllerCase $plan $packet (Case-Nonce 2) $consumed} 'controller-case-replay'
$oversizedPacket=$packet.Clone();$oversizedPacket.extra='x'*131072
Refused-Case {New-HistoricalControllerCase $plan $oversizedPacket (Case-Nonce 3) (New-CaseRegistry)} 'controller-case-bound'
$wrongRegistry=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
Refused-Case {New-HistoricalControllerCase $plan $packet (Case-Nonce 4) $wrongRegistry} 'controller-case-registry'
foreach($nonce in @([Guid]::Empty.ToString('D'),'BAD')){
    $bad=$plan.Clone();$bad.nonce=$nonce
    Refused-Case {New-HistoricalControllerCase $bad $packet (Case-Nonce 5) (New-CaseRegistry)} 'controller-case-nonce'
}
Write-Output 'HISTORICAL CONTROLLER CASE PASS:33 distinct child nonces;source identity and parent bytes preserved;replay,changed-plan,preparation failure,bounds,canonical identities andregistry refusals verified. Generated-only in-memory consumption;no native launch orauthority.'

# Exercise every wire shape through the same pure guard used before any witness Docker call.
. (Join-Path $PSScriptRoot '../../eng/pilot/HistoricalRecoveryCreateFault.ps1')
$wire=@{fault='lost';fixture=([Guid]::NewGuid().ToString('D'));nonce=([Guid]::NewGuid().ToString('D'));
    session=([Guid]::NewGuid().ToString('D'));imageId=('sha256:'+('a'*64))}
$wireBefore=$wire|ConvertTo-Json -Compress
Assert-HistoricalCreateWitnessRequest $wire
Assert-ImmuData (($wire|ConvertTo-Json -Compress) -ceq $wireBefore) 'witness-request-not-mutated'
$wire.fault='truncated';Assert-HistoricalCreateWitnessRequest $wire
$wire.fault='coordinator-exit';$wire.python=[Environment]::ProcessPath;Assert-HistoricalCreateWitnessRequest $wire
$bad=$wire.Clone();$bad.Remove('python');Refused-Case {Assert-HistoricalCreateWitnessRequest $bad} 'create-witness-request'
$bad=$wire.Clone();$bad.fault='lost';Refused-Case {Assert-HistoricalCreateWitnessRequest $bad} 'create-witness-request'
$bad=$wire.Clone();$bad.python='relative-python';Refused-Case {Assert-HistoricalCreateWitnessRequest $bad} 'inflight-python'
$bad=$wire.Clone();$bad.imageId='local:tag';Refused-Case {Assert-HistoricalCreateWitnessRequest $bad} 'create-witness-request'
$bad=$wire.Clone();$bad.session=[Guid]::Empty.ToString('D');Refused-Case {Assert-HistoricalCreateWitnessRequest $bad} 'create-witness-nonce'
$bad=$wire.Clone();$bad.fault='other';Refused-Case {Assert-HistoricalCreateWitnessRequest $bad} 'create-witness-request'
$bad=$wire.Clone();$bad.extra=$true;Refused-Case {Assert-HistoricalCreateWitnessRequest $bad} 'create-witness-request'
Write-Output 'HISTORICAL CREATE WITNESS INPUT PASS:3 accepted modes;7 malformed shape/identity/path refusals; no native launch.'

# The same live child must have one exact birth token in independent observers.
$launch=[Diagnostics.ProcessStartInfo]::new([Environment]::ProcessPath)
$launch.UseShellExecute=$false;$launch.CreateNoWindow=$true
foreach($part in @('-NoProfile','-NonInteractive','-Command','Start-Sleep -Seconds 20')){$launch.ArgumentList.Add($part)}
$native=[Diagnostics.Process]::Start($launch);$null=$native.Handle
try{
    $birth=Get-HistoricalNativeBirth $native
    $peer=@{nativeObserver=$native;inFlight=@{nativePid=$native.Id;nativeBirthKind=$birth.kind;nativeBirthToken=$birth.token}}
    Assert-HistoricalInFlightClient $peer
    for($n=0;$n -lt 2;$n++){
        $start=[Diagnostics.ProcessStartInfo]::new([Environment]::ProcessPath)
        $start.UseShellExecute=$false;$start.CreateNoWindow=$true
        $start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
        foreach($part in @('-NoProfile','-NonInteractive','-File',$PSCommandPath,'-ObserveNativePid',[string]$native.Id)){$start.ArgumentList.Add($part)}
        $reader=[Diagnostics.Process]::Start($start)
        try{
            if(-not $reader.WaitForExit(8000)){$reader.Kill($true);throw 'Native birth observer deadline exceeded.'}
            $observed=$reader.StandardOutput.ReadToEnd()|ConvertFrom-Json -AsHashtable
            Assert-ImmuData ($reader.ExitCode -eq 0 -and $reader.StandardError.ReadToEnd().Length -eq 0 -and
                $observed.Count -eq 2 -and $observed.kind -ceq $birth.kind -and $observed.token -ceq $birth.token) 'native-birth-independent-observer'
            Assert-HistoricalInFlightClient $peer
        }finally{$reader.Dispose()}
    }
    $bad=$peer.Clone();$bad.inFlight=$peer.inFlight.Clone();$bad.inFlight.nativeBirthToken+='1'
    Refused-Case {Assert-HistoricalInFlightClient $bad} 'inflight-native-birth'
    $bad=$peer.Clone();$bad.inFlight=$peer.inFlight.Clone();$bad.inFlight.nativeBirthKind='untrusted-kind'
    Refused-Case {Assert-HistoricalInFlightClient $bad} 'inflight-native-birth'
    $bad=$peer.Clone();$bad.inFlight=$peer.inFlight.Clone();$bad.inFlight.nativePid++
    Refused-Case {Assert-HistoricalInFlightClient $bad} 'inflight-native-pid'
    $native.Kill($true);$native.WaitForExit()
    Refused-Case {Assert-HistoricalInFlightClient $peer} 'inflight-native-live'
}finally{if(-not $native.HasExited){$native.Kill($true);$native.WaitForExit()};$native.Dispose()}
Write-Output 'HISTORICAL NATIVE BIRTH PASS:2 independent native observers;exact OS birth token;changed birth,kind,PID and exited process refused;no clock tolerance or cleanup authority.'
