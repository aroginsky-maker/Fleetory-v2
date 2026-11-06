#requires -Version 7.3
# Generated datasets only. Uses the common measured, disposable, network-none fixture.
function New-ObservationExpectation($Store,$Setup){
    $receipt=New-ImmudbStateReceipt $Setup.state 'fleetoryaudit' (Public-KeyPath $Store.Role)
    Assert-ImmuData ([int]$receipt.txId -eq 5) 'observation-setup-point'
    return @{schema='fleetory.audit-observation-expectation.v1';nonce=$fixture;point=@{database='fleetoryaudit';tx=5;txHash=$receipt.txHash};knownEvents=$Setup.knownEvents;producer=@{containerId=$Store.Id;imageId=$context.ImageId;probeSha256=$context.ProbeHash}}
}
function Read-Observation($Store,$Expected){
    $script:observationExpectation=$Expected
    $v=Probe $Store 'observation-read'
    foreach($side in @('stateBefore','stateAfter')){
        $receipt=New-ImmudbStateReceipt $v[$side] 'fleetoryaudit' (Public-KeyPath $Store.Role)
        Assert-ImmuData ([int]$receipt.txId -eq 5 -and $receipt.txHash -ceq $Expected.point.txHash) 'observation-signed-point'
    }
    Read-AuditDataStore $context $Store
    $v.producer=@{containerId=$Store.Id;imageId=$context.ImageId;probeSha256=$context.ProbeHash}
    $expectedBytes=[Text.Encoding]::UTF8.GetBytes(($Expected|ConvertTo-Json -Depth 8 -Compress))
    $body=@{expectedBase64=[Convert]::ToBase64String($expectedBytes);expectedSha256=(Get-ImmuDataHash $expectedBytes);observedBase64=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($v|ConvertTo-Json -Depth 12 -Compress)))}
    $r=Invoke-NativeBytes $Python @('-B',(Join-Path $repo 'eng/pilot/audit_observation.py')) ([Text.Encoding]::UTF8.GetBytes(($body|ConvertTo-Json -Compress))) 10
    Assert-ImmuData ($r.ExitCode -eq 0 -and [string]::IsNullOrWhiteSpace($r.Stderr)) 'observation-decoder'
    $parsed=$r.Stdout|ConvertFrom-Json -AsHashtable
    Assert-ImmuData ($parsed.knownEvents -eq 4 -and $parsed.nativeTransactions -eq 5 -and $parsed.pointMatched -eq $true -and $parsed.knownEventBindingsMatched -eq $true -and $parsed.additionalStateReviewed -eq $false -and $parsed.wholeKeyspaceVerified -eq $false -and $parsed.startupAuthorized -eq $false -and $parsed.signaturesVerified -eq $false -and $parsed.producerMeasurementAuthenticated -eq $false) 'observation-report'
    return @{Parsed=$parsed;Native=$v}
}
function Restart-ObservationStore($Store){
    Read-AuditDataStore $context $Store
    $pidText=(Invoke-Docker @('exec',$Store.Id,'/bin/cat','/tmp/immudb.pid')).Stdout.Trim()
    Assert-ImmuData ($pidText -cmatch '^[1-9][0-9]{0,7}\z') 'observation-server-pid'
    $null=Invoke-Docker @('exec',$Store.Id,'/bin/kill','-TERM',$pidText);$stopped=$false
    for($n=0;$n -lt 40;$n++){$r=Invoke-Docker @('exec',$Store.Id,'/bin/kill','-0',$pidText) -AllowFailure;if($r.ExitCode -ne 0){$stopped=$true;break};Start-Sleep -Milliseconds 200}
    Assert-ImmuData $stopped 'observation-stop';Start-AuditDataServer $context $Store
}
function Invoke-NativeAuditObservationWorkflow($Source,$Target){
    $script:stage='observation-setup'
    $null=Probe $Source 'observation-seed';$a=Probe $Source 'observation-zset';$expectedA=New-ObservationExpectation $Source $a
    $null=Probe $Target 'observation-seed';$b=Probe $Target 'observation-kv';$expectedB=New-ObservationExpectation $Target $b
    $script:stage='observation-read'
    $sourceRead=Read-Observation $Source $expectedA;$targetRead=Read-Observation $Target $expectedB
    Assert-ImmuData ($sourceRead.Parsed.currentKvKeys -eq 4 -and $sourceRead.Parsed.unknownCurrentKvKeys -eq 0 -and $sourceRead.Parsed.unreviewedRawEntries -eq 1 -and $sourceRead.Parsed.unreviewedPrefixes['1'] -eq 1) 'observation-sorted-set'
    Assert-ImmuData ($targetRead.Parsed.currentKvKeys -eq 5 -and $targetRead.Parsed.unknownCurrentKvKeys -eq 1 -and $targetRead.Parsed.unreviewedRawEntries -eq 1 -and $targetRead.Parsed.unreviewedPrefixes['0'] -eq 1) 'observation-extra-kv'
    foreach($store in @($Source,$Target)){$null=Probe $store 'observation-reader-denial'}
    $script:stage='observation-authentication'
    $script:observationExpectation=$expectedA;$null=Probe $Source 'observation-read' 'authentication' -WrongPassword
    $script:stage='observation-crypto'
    Crypto-Refused $sourceRead.Native.stateAfter (Public-KeyPath 'target') 'immudb state public key does not match the pinned key.'
    Crypto-Refused $targetRead.Native.stateAfter (Public-KeyPath 'source') 'immudb state public key does not match the pinned key.'
    $script:stage='observation-point-refusal'
    $bad=($expectedA|ConvertTo-Json -Depth 8)|ConvertFrom-Json -AsHashtable;$bad.point.txHash=[Convert]::ToBase64String([byte[]]::new(32))
    $script:observationExpectation=$bad;$null=Probe $Source 'observation-read' 'AuditObservationPointException'
    $script:stage='observation-revision-refusal'
    $corrupt=New-AuditDataStore $context 'corrupt';$null=Probe $corrupt 'observation-seed';$setup=Probe $corrupt 'observation-rewrite'
    $script:observationExpectation=New-ObservationExpectation $corrupt $setup;$null=Probe $corrupt 'observation-read' 'AuditObservationBindingException';Remove-AuditDataStore $context $corrupt
    $script:stage='observation-bound-refusal'
    $corrupt=New-AuditDataStore $context 'corrupt';$null=Probe $corrupt 'observation-seed';$setup=Probe $corrupt 'observation-many'
    $script:observationExpectation=New-ObservationExpectation $corrupt $setup;$null=Probe $corrupt 'observation-read' 'AuditObservationBoundException';Remove-AuditDataStore $context $corrupt
    $script:stage='observation-restart'
    Restart-ObservationStore $Target
    $again=Read-Observation $Target $expectedB
    Assert-ImmuData ($again.Parsed.observationSha256 -ceq $targetRead.Parsed.observationSha256) 'observation-restart-fingerprint'
    $againSource=Read-Observation $Source $expectedA
    Assert-ImmuData ($againSource.Parsed.observationSha256 -ceq $sourceRead.Parsed.observationSha256) 'observation-source-unchanged'
    return @{schema='fleetory.generated-audit-observation.v1';verified=$true;scope='generated-only';knownEvents=4;nativeTransactions=5;sortedSetDatasetKvKeys=4;extraKvDatasetKvKeys=5;unreviewedEntriesPerDataset=1;nativeDataRefusals=3;readerWriteRefusals=2;wrongPasswordRefusedSeparately=$true;ownPinSignaturesVerified=$true;wrongPinRefusals=2;allRawTransactionKindsObserved=$true;wholeKeyspaceVerified=$false;additionalStateReviewed=$false;restartPreservedObservation=$true;sourceObservationUnchanged=$true;observationSha256=$targetRead.Parsed.observationSha256;probeSha256=$context.ProbeHash;originalInputsRead=$false;sourceVpsAccessed=$false;originalPkiOrProviderUsed=$false;serverApplicationStarted=$false;issuerActivated=$false;startupAuthorized=$false;executionAuthorized=$false;independentInclusionProofsVerified=$false;fullSystemRecoveryVerified=$false;phase7Complete=$false}
}
