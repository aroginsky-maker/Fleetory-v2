#requires -Version 7.3
# Generated-only historical source, independent expectations, restore and scoped observation.
function New-HistoricalObservationExpectation($Store,$Setup,$Values=$null){
    if($null -eq $Values){$Values=$Setup.comparisonExpectations}
    $receipt=New-ImmudbStateReceipt $Setup.state 'fleetoryaudit' (Public-KeyPath 'source')
    Assert-ImmuData ([int]$receipt.txId -eq 5 -and $Setup.expectationsFromAuditGet -eq $false -and $Setup.generatedOnly -eq $true) 'historical-independent-source'
    $bytes=[Text.Encoding]::UTF8.GetBytes(($Values|ConvertTo-Json -Depth 8 -Compress))
    $body=@{sourceBase64=[Convert]::ToBase64String($bytes);sourceSha256=(Get-ImmuDataHash $bytes);nonce=$fixture;
        point=@{database='fleetoryaudit';tx=5;txHash=$receipt.txHash};producer=@{containerId=$Store.Id;imageId=$context.ImageId;probeSha256=$context.ProbeHash}}
    $r=Invoke-NativeBytes $Python @('-B',(Join-Path $repo 'eng/pilot/historical_audit_observation.py'),'build') ([Text.Encoding]::UTF8.GetBytes(($body|ConvertTo-Json -Depth 8 -Compress))) 10
    Assert-ImmuData ($r.ExitCode -eq 0 -and [string]::IsNullOrWhiteSpace($r.Stderr)) 'historical-frame-builder'
    return $r.Stdout|ConvertFrom-Json -AsHashtable -Depth 12
}
function Read-HistoricalObservation($Store,$Expected){
    $script:observationExpectation=$Expected
    $v=Probe $Store 'observation-history-read'
    foreach($side in @('stateBefore','stateAfter')){
        $receipt=New-ImmudbStateReceipt $v[$side] 'fleetoryaudit' (Public-KeyPath $Store.Role)
        Assert-ImmuData ([int]$receipt.txId -eq 5 -and $receipt.txHash -ceq $Expected.point.txHash) 'historical-signed-point'
    }
    Read-AuditDataStore $context $Store
    $v.producer=@{containerId=$Store.Id;imageId=$context.ImageId;probeSha256=$context.ProbeHash}
    $bytes=[Text.Encoding]::UTF8.GetBytes(($Expected|ConvertTo-Json -Depth 8 -Compress))
    $body=@{expectedBase64=[Convert]::ToBase64String($bytes);expectedSha256=(Get-ImmuDataHash $bytes);
        observedBase64=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($v|ConvertTo-Json -Depth 12 -Compress)))}
    $r=Invoke-NativeBytes $Python @('-B',(Join-Path $repo 'eng/pilot/historical_audit_observation.py'),'observe') ([Text.Encoding]::UTF8.GetBytes(($body|ConvertTo-Json -Compress))) 10
    Assert-ImmuData ($r.ExitCode -eq 0 -and [string]::IsNullOrWhiteSpace($r.Stderr)) 'historical-observer-policy'
    $parsed=$r.Stdout|ConvertFrom-Json -AsHashtable
    Assert-ImmuData ($parsed.knownEvents -eq 4 -and $parsed.nativeTransactions -eq 5 -and $parsed.currentKvKeys -eq 4 -and
        $parsed.historicalComparisonOnly -eq $true -and $parsed.writerAdmissionVerified -eq $false -and $parsed.originalStrictExpectationsAccepted -eq $false -and
        $parsed.additionalStateReviewed -eq $false -and $parsed.wholeKeyspaceVerified -eq $false -and $parsed.executionAuthorized -eq $false -and
        $parsed.comparison.profile -ceq 'historical-one-null-member-readonly.v1' -and $parsed.comparison.nullContextMembersPreserved -eq 1 -and
        $parsed.unreviewedRawEntries -eq 1 -and $parsed.unreviewedPrefixes['1'] -eq 1) 'historical-observation-report'
    return @{Parsed=$parsed;Native=$v}
}
function Invoke-NativeHistoricalObservationWorkflow($Source,$Target){
    $script:stage='historical-seed'
    $setup=Probe $Source 'observation-history-seed'
    $expectedSource=New-HistoricalObservationExpectation $Source $setup
    $sourceRead=Read-HistoricalObservation $Source $expectedSource
    $script:stage='historical-capture-restore'
    Read-AuditDataStore $context $Source
    $backup=(Invoke-Docker (Get-ImmuDataCliArguments $Source.Id 'backup')).StdoutBytes
    $backupPin=Get-ImmuDataHash $backup
    Assert-ImmuDataPacket $backup $backupPin
    Read-AuditDataStore $context $Target
    $null=Invoke-Docker (Get-ImmuDataCliArguments $Target.Id 'verify') $backup
    $null=Invoke-Docker (Get-ImmuDataCliArguments $Target.Id 'restore') $backup
    $null=Probe $Target 'history-users'
    $expectedTarget=New-HistoricalObservationExpectation $Target $setup
    $targetRead=Read-HistoricalObservation $Target $expectedTarget
    Assert-ImmuData ($targetRead.Parsed.observationSha256 -ceq $sourceRead.Parsed.observationSha256) 'historical-restored-data'
    $script:stage='historical-scope-refusals'
    $script:observationExpectation=$expectedTarget
    $null=Probe $Target 'observation-read' 'AuditObservationBindingException'
    $null=Probe $Target 'observation-history-read' 'authentication' -WrongPassword
    $bad=($expectedTarget|ConvertTo-Json -Depth 8)|ConvertFrom-Json -AsHashtable
    $bad.comparison.writerAdmissionVerified=$true;$script:observationExpectation=$bad
    $null=Probe $Target 'observation-history-read' 'AuditObservationBindingException'
    $bad=($expectedTarget|ConvertTo-Json -Depth 8)|ConvertFrom-Json -AsHashtable
    $bad.comparison.knownValuesCommitment='0'*64;$script:observationExpectation=$bad
    $null=Probe $Target 'observation-history-read' 'AuditObservationBindingException'
    $bad=($expectedTarget|ConvertTo-Json -Depth 8)|ConvertFrom-Json -AsHashtable
    $bad.point.txHash=[Convert]::ToBase64String([byte[]]::new(32));$script:observationExpectation=$bad
    $null=Probe $Target 'observation-history-read' 'AuditObservationPointException'
    $values=($setup.comparisonExpectations|ConvertTo-Json -Depth 8)|ConvertFrom-Json -AsHashtable
    $values.knownEvents[0].valueSha256='0'*64
    $script:observationExpectation=New-HistoricalObservationExpectation $Target $setup $values
    $null=Probe $Target 'observation-history-read' 'AuditObservationBindingException'
    foreach($store in @($Source,$Target)){$null=Probe $store 'observation-reader-denial'}
    $script:stage='historical-signatures-restart'
    Crypto-Refused $sourceRead.Native.stateAfter (Public-KeyPath 'target') 'immudb state public key does not match the pinned key.'
    Crypto-Refused $targetRead.Native.stateAfter (Public-KeyPath 'source') 'immudb state public key does not match the pinned key.'
    Restart-ObservationStore $Target
    $again=Read-HistoricalObservation $Target $expectedTarget
    $sourceAgain=Read-HistoricalObservation $Source $expectedSource
    Assert-ImmuData ($again.Parsed.observationSha256 -ceq $targetRead.Parsed.observationSha256 -and
        $sourceAgain.Parsed.observationSha256 -ceq $sourceRead.Parsed.observationSha256) 'historical-stable-observation'
    $backup=$null
    return @{schema='fleetory.generated-historical-audit-observation.v1';verified=$true;scope='generated-only';knownEvents=4;
        nullMembersPreserved=1;nativeTransactions=5;currentKvKeys=4;nativeRestores=1;expectationsFromAuditGet=$false;
        historicalComparisonOnly=$true;writerAdmissionVerified=$false;originalStrictExpectationsAccepted=$false;
        strictModeProjectionRefused=$true;authorityAndCommitmentRefusals=2;wrongPointRefused=$true;wrongValueRefused=$true;
        wrongPasswordRefusedSeparately=$true;readerWriteRefusals=2;ownPinSignaturesVerified=$true;wrongPinRefusals=2;
        restartPreservedObservation=$true;sourceObservationUnchanged=$true;unknownEntries=1;additionalStateReviewed=$false;
        wholeKeyspaceVerified=$false;profileCarriedAcrossEnvelopes=$true;probeSha256=$context.ProbeHash;
        originalInputsRead=$false;originalPkiOrProviderUsed=$false;sourceVpsAccessed=$false;executionAuthorized=$false;
        fullSystemRecoveryVerified=$false;phase7Complete=$false}
}
