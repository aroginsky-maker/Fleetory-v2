#requires -Version 7.3
# Generated setup only. Retained admission derives values from the separate PG snapshot, not this model.
function Invoke-RetainedHistoricalSourceProbe($Side,[string]$Mode,$Body=$null,[string[]]$Extra=@(),[byte[]]$Raw=$null){
    Read-PairStore $state $Side 'postgres';Read-PairStore $state $Side.Audit 'audit'
    $bytes=if($null -ne $Raw){$Raw}else{[Text.Encoding]::UTF8.GetBytes(($Body|ConvertTo-Json -Depth 12 -Compress))}
    $r=Invoke-Docker (@('exec','-i','-e','SSL_CERT_FILE=/tmp/ca.pem','-e','SSL_CERT_DIR=/tmp/empty-ca-dir',
        $Side.Audit.Id,'dotnet','/tool/ServerBackendProbe.dll',$Mode)+$Extra) $bytes -AllowFailure
    Assert-Pair ($r.ExitCode -eq 0 -and [string]::IsNullOrWhiteSpace($r.Stderr)) 'historical-generated-source-probe'
    return $r.Stdout|ConvertFrom-Json -AsHashtable -Depth 20
}
function Get-RetainedHistoricalSourcePoint($Side){
    $pg=@{};foreach($db in @('fleetory','fleetory_signer')){$pg[$db]=V2-Read $Side $db}
    $sql=Invoke-NativeBytes $Python @('-B',(Join-Path $PSScriptRoot 'native_retained_pg_inputs.py'),'sql') -TimeoutSeconds 10
    Assert-Pair ($sql.ExitCode -eq 0 -and [string]::IsNullOrWhiteSpace($sql.Stderr)) 'historical-source-snapshot-sql'
    $snapshot=(V2-Sql $Side 'fleetory' $sql.Stdout).StdoutBytes;$pin=Get-ImmuDataHash $snapshot
    $values=Invoke-RetainedHistoricalSourceProbe $Side 'audit-history-expectations' -Extra @($pin,$fixture) -Raw $snapshot
    $valueBytes=[Text.Encoding]::UTF8.GetBytes(($values|ConvertTo-Json -Depth 10 -Compress))
    $producer=@{containerId=$Side.Audit.Id;imageId=$state.ImageId;probeSha256=$state.ProbeHash}
    $body=@{sourceBase64=[Convert]::ToBase64String($valueBytes);sourceSha256=(Get-ImmuDataHash $valueBytes);nonce=$fixture;
        point=@{database='fleetoryaudit';tx=5;txHash=$script:retainedHistoricalSourceReceipt.txHash};producer=$producer}
    $expected=Invoke-NativeBytes $Python @('-B',(Join-Path $repo 'eng/pilot/historical_audit_observation.py'),'build') ([Text.Encoding]::UTF8.GetBytes(($body|ConvertTo-Json -Depth 10 -Compress))) 10
    Assert-Pair ($expected.ExitCode -eq 0 -and [string]::IsNullOrWhiteSpace($expected.Stderr)) 'historical-source-expectation'
    $frame=$expected.Stdout|ConvertFrom-Json -AsHashtable -Depth 14
    $observed=Invoke-RetainedHistoricalSourceProbe $Side 'observation-history-read' @{fixture=$fixture;reader=$Side.Secrets.reader;observation=$frame}
    foreach($name in @('stateBefore','stateAfter')){
        $receipt=New-ImmudbStateReceipt $observed[$name] 'fleetoryaudit' (Join-Path $root ($Side.Role+'-public.pem'))
        Assert-Pair ($receipt.txId -eq 5 -and $receipt.txHash -ceq $script:retainedHistoricalSourceReceipt.txHash) 'historical-source-signed-point'
    }
    $observed.producer=$producer
    $frameBytes=[Text.Encoding]::UTF8.GetBytes(($frame|ConvertTo-Json -Depth 12 -Compress))
    $body=@{expectedBase64=[Convert]::ToBase64String($frameBytes);expectedSha256=(Get-ImmuDataHash $frameBytes);
        observedBase64=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($observed|ConvertTo-Json -Depth 18 -Compress)))}
    $parsed=Invoke-NativeBytes $Python @('-B',(Join-Path $repo 'eng/pilot/historical_audit_observation.py'),'observe') ([Text.Encoding]::UTF8.GetBytes(($body|ConvertTo-Json -Compress))) 10
    Assert-Pair ($parsed.ExitCode -eq 0 -and [string]::IsNullOrWhiteSpace($parsed.Stderr)) 'historical-source-observation'
    $report=$parsed.Stdout|ConvertFrom-Json -AsHashtable -Depth 14
    Assert-Pair ($report.knownEvents -eq 4 -and $report.nativeTransactions -eq 5 -and $report.comparison.nullContextMembersPreserved -eq 1 -and
        $report.historicalComparisonOnly -and -not $report.writerAdmissionVerified -and -not $report.wholeKeyspaceVerified -and
        $report.unreviewedRawEntries -eq 1 -and $report.unreviewedPrefixes['1'] -eq 1) 'historical-source-observation-scope'
    return @{schema='fleetory.generated-historical-retained-source-point.v1';postgres=$pg;
        audit=@{database='fleetoryaudit';tx=5;txHash=[Convert]::ToHexString([Convert]::FromBase64String($script:retainedHistoricalSourceReceipt.txHash));
            keyFingerprint=$script:retainedHistoricalSourceReceipt.publicKeySha256;observationSha256=$report.observationSha256;
            knownEvents=4;nativeTransactions=5;historicalNullMembers=1;wholeKeyspaceVerified=$false;writerAdmissionVerified=$false}}
}
function Initialize-RetainedHistoricalSource($Side,[string]$EventId){
    Assert-Pair ([Guid]::ParseExact($EventId,'D').ToString('D') -ceq $EventId) 'historical-generated-source-event-id'
    $null=V2-Sql $Side 'fleetory' ("UPDATE platform.audit_events SET context_json='"+'{"Optional":null,"Text":"generated"}'+"'::jsonb WHERE event_id='"+$EventId+"';")
    $seed=Invoke-PairProbe $state $Side 'observation-history-seed'
    Assert-Pair ($seed.generatedOnly -and -not $seed.expectationsFromAuditGet) 'historical-generated-seed'
    $script:retainedHistoricalSourceReceipt=New-ImmudbStateReceipt $seed.state 'fleetoryaudit' (Join-Path $root ($Side.Role+'-public.pem'))
    Assert-Pair ($script:retainedHistoricalSourceReceipt.txId -eq 5) 'historical-generated-source-tip'
}
