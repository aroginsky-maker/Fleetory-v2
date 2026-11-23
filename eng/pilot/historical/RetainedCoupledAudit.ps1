#requires -Version 7.3
function Get-RetainedAuditStartArguments([string]$Identifier){
    return @('exec','-d','-e','SSL_CERT_FILE=/tmp/ca.pem','-e','SSL_CERT_DIR=/tmp/empty-ca-dir',$Identifier,
        '/usr/sbin/immudb','--config=/tmp/immudb.toml','--dir=/data','--address=127.0.0.1','--port=3322',
        '--auth=true','--devmode=false','--web-server=true','--web-server-port=8090','--pgsql-server=false','--metrics-server=false',
        '--certificate=/tmp/server.crt','--pkey=/tmp/server.key','--clientcas=/tmp/ca.pem','--signingKey=/tmp/state.key',
        '--pidfile=/tmp/immudb.pid','--logdir=/tmp','--logfile=fixture.log','--max-active-databases=3')
}
# Called only inside the live retained PG owner. Frozen packets and live CWT handles stay in that process.
function Invoke-RetainedCoupledAudit($Namespace,$AuditStore,$Material,[byte[]]$Archive,[byte[]]$Snapshot,[string]$Nonce,$Point,$ImageContext,[bool]$Historical=$false){
    $id=[Fleetory.Pilot.AuditContainerCustody]::Id($Namespace,$AuditStore,${function:Invoke-Docker})
    function Invoke-CoupledProbe([string]$Mode,$Body=$null,[string[]]$Extra=@(),[byte[]]$Raw=$null,[string]$ExpectedType=''){
        $data=if($null -ne $Raw){$Raw}elseif($null -ne $Body){[Text.Encoding]::UTF8.GetBytes(($Body|ConvertTo-Json -Depth 12 -Compress))}else{$null}
        $r=Invoke-RetainedAuditNative (@('exec','-i','-e','SSL_CERT_FILE=/tmp/ca.pem','-e','SSL_CERT_DIR=/tmp/empty-ca-dir',
            $id,'dotnet','/tool/ServerBackendProbe.dll',$Mode)+$Extra) $data -AllowFailure
        $value=$r.Stdout|ConvertFrom-Json -AsHashtable -Depth 20
        if($ExpectedType){
            Assert-ImmuData ($r.ExitCode -eq 1 -and $value.category -ceq 'unexpected' -and $value.errorType -ceq $ExpectedType) 'retained-coupled-strict-refusal'
            return $value
        }
        Assert-ImmuData ($r.ExitCode -eq 0) 'retained-coupled-probe-exit'
        return $value
    }
    function Write-CoupledSlot([string]$Path,[string]$Value){
        Write-RetainedConfiguredFile 'audit' $Path $Value
    }
    Assert-ImmuData ((Invoke-RetainedAuditNative @('exec',$id,'sha256sum','/tool/ServerBackendProbe.dll')).Stdout.Split(' ')[0] -ceq $ImageContext.ProbeHash) 'retained-coupled-probe-pin'
    $null=Invoke-RetainedAuditNative @('exec',$id,'/bin/mkdir','-m','700','/tmp/empty-ca-dir')
    foreach($entry in @(@('/tmp/ca.pem',$Material.Tls.RootCertificatePem),@('/tmp/server.crt',$Material.Tls.ServerCertificatePem),
        @('/tmp/server.key',$Material.Tls.ServerPrivateKeyPem),@('/tmp/client.crt',$Material.Tls.ClientCertificatePem),
        @('/tmp/client.key',$Material.Tls.ClientPrivateKeyPem),@('/tmp/state.key',$Material.SigningPem))){Write-CoupledSlot $entry[0] $entry[1]}
    Write-CoupledSlot '/tmp/immudb.toml' ('admin-password = "'+$Material.Secrets.admin+'"'+"`n")
    Write-CoupledSlot '/tmp/cli.toml' $configuration.Values['audit:/tmp/cli.toml']
    $null=Invoke-RetainedAuditNative (Get-RetainedAuditStartArguments $id)
    $ready=$false
    for($n=0;$n -lt 20;$n++){
        try{$health=Invoke-CoupledProbe 'audit-health';if($health.category -ceq 'audit-health'){$ready=$true;break}}catch{Start-Sleep -Milliseconds 200}
    }
    Assert-ImmuData $ready 'retained-coupled-audit-ready'
    foreach($name in @('admin','reader','writer')){Assert-RetainedConfigurationValue $configuration ('credential:audit/'+$name) $Material.Secrets[$name]}
    $login=Invoke-RetainedAuditNative (Get-ImmuDataCliArguments $id 'login') ([Text.Encoding]::UTF8.GetBytes($Material.Secrets.admin))
    Assert-ImmuData ($login.ExitCode -eq 0 -and $login.Stdout -match 'logged in') 'retained-coupled-cli-login'
    Assert-ImmuDataPacket $Archive (Get-ImmuDataHash $Archive)
    $null=Invoke-RetainedAuditNative (Get-ImmuDataCliArguments $id 'verify') $Archive
    $null=Invoke-RetainedAuditNative (Get-ImmuDataCliArguments $id 'restore') $Archive
    $body=@{fixture=$Nonce;admin=$Material.Secrets.admin;reader=$Material.Secrets.reader;writer=$Material.Secrets.writer}
    $users=Invoke-CoupledProbe 'history-users' $body
    Assert-ImmuData ($users.targetOnlyUsersCreated -eq $true) 'retained-coupled-fresh-users'
    $pin=Get-ImmuDataHash $Snapshot
    $strictRefused=$false
    if($Historical){
        $null=Invoke-CoupledProbe 'audit-expectations' $null @($pin,$Nonce) $Snapshot -ExpectedType 'AuditExpectationInputException'
        $strictRefused=$true
    }
    $mode=if($Historical){'audit-history-expectations'}else{'audit-expectations'}
    $schema=if($Historical){'fleetory.audit-historical-expectations.v1'}else{'fleetory.audit-event-expectations.v1'}
    $values=Invoke-CoupledProbe $mode $null @($pin,$Nonce) $Snapshot
    Assert-ImmuData ($values.schema -ceq $schema -and $values.nonce -ceq $Nonce -and
        $values.snapshotSha256 -ceq $pin -and $values.productionSinkSerializationUsed -eq $true -and $values.realBackendContacted -eq $false -and
        $values.executionAuthorized -eq $false -and @($values.knownEvents).Count -eq 4) 'retained-coupled-pg-expectations'
    Assert-ImmuData ($Point.database -ceq 'fleetoryaudit' -and $Point.tx -eq 5 -and $Point.txHash -cmatch '^[A-F0-9]{64}\z') 'retained-coupled-source-point'
    $expected=@{schema='fleetory.audit-observation-expectation.v1';nonce=$Nonce;
        point=@{database='fleetoryaudit';tx=5;txHash=[Convert]::ToBase64String([Convert]::FromHexString($Point.txHash))};
        knownEvents=$values.knownEvents;producer=@{containerId=$id;imageId=$ImageContext.ImageId;probeSha256=$ImageContext.ProbeHash}}
    if($Historical){
        $valueBytes=[Text.Encoding]::UTF8.GetBytes(($values|ConvertTo-Json -Depth 10 -Compress))
        $body=@{sourceBase64=[Convert]::ToBase64String($valueBytes);sourceSha256=(Get-ImmuDataHash $valueBytes);nonce=$Nonce;
            point=$expected.point;producer=$expected.producer}
        $built=Invoke-NativeBytes $comparisonPython @('-I','-S','-B',(Join-Path $pilot 'historical/retained_source_bootstrap.py'),'historical-observation','build') ([Text.Encoding]::UTF8.GetBytes(($body|ConvertTo-Json -Depth 10 -Compress))) 10
        Assert-ImmuData ($built.ExitCode -eq 0 -and [string]::IsNullOrWhiteSpace($built.Stderr)) 'retained-historical-frame'
        $expected=$built.Stdout|ConvertFrom-Json -AsHashtable -Depth 14
    }
    $mode=if($Historical){'observation-history-read'}else{'observation-read'}
    $native=Invoke-CoupledProbe $mode @{fixture=$Nonce;reader=$Material.Secrets.reader;observation=$expected}
    foreach($side in @('stateBefore','stateAfter')){
        $receipt=New-ImmudbStateReceipt $native[$side] 'fleetoryaudit' $Material.PublicKeyPath
        Assert-ImmuData ($receipt.txId -eq 5 -and $receipt.txHash -ceq $expected.point.txHash) 'retained-coupled-signed-point'
    }
    $native.producer=$expected.producer
    $expectedBytes=[Text.Encoding]::UTF8.GetBytes(($expected|ConvertTo-Json -Depth 10 -Compress))
    $frame=@{expectedBase64=[Convert]::ToBase64String($expectedBytes);expectedSha256=(Get-ImmuDataHash $expectedBytes);
        observedBase64=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($native|ConvertTo-Json -Depth 16 -Compress)))}
    $arguments=if($Historical){@('-I','-S','-B',(Join-Path $pilot 'historical/retained_source_bootstrap.py'),'historical-observation','observe')}else{@('-I','-S','-B',(Join-Path $pilot 'historical/retained_source_bootstrap.py'),'observation')}
    $parsed=Invoke-NativeBytes $comparisonPython $arguments ([Text.Encoding]::UTF8.GetBytes(($frame|ConvertTo-Json -Compress))) 10
    Assert-ImmuData ($parsed.ExitCode -eq 0 -and [string]::IsNullOrWhiteSpace($parsed.Stderr)) 'retained-coupled-audit-comparison'
    $report=$parsed.Stdout|ConvertFrom-Json -AsHashtable
    Assert-ImmuData ($report.knownEvents -eq 4 -and $report.nativeTransactions -eq 5 -and $report.pointMatched -eq $true -and
        $report.knownEventBindingsMatched -eq $true -and $report.wholeKeyspaceVerified -eq $false -and $report.startupAuthorized -eq $false) 'retained-coupled-comparison-report'
    if($Historical){
        Assert-ImmuData ($strictRefused -and $report.comparison.nullContextMembersPreserved -eq 1 -and $report.historicalComparisonOnly -and
            -not $report.writerAdmissionVerified -and -not $report.originalStrictExpectationsAccepted -and $report.unreviewedRawEntries -eq 1 -and
            $report.unreviewedPrefixes['1'] -eq 1) 'retained-historical-readonly-scope'
    }
    return @{nativeAuditRestores=1;pgExportExpectationsUsed=$true;snapshotSha256=$pin;observation=$report;observationExpectation=$expected;
        targetSignaturesVerified=$true;sourcePointAuthenticated=$false;historicalNullProfileVerified=$Historical;strictWriterRefused=$strictRefused;serverStarted=$false}
}
