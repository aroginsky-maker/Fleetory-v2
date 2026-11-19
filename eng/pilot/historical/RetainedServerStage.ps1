#requires -Version 7.3
function Invoke-RetainedServerStage($Namespace,$AuditStore,$Material,[byte[]]$Snapshot,[string]$Nonce,$AuditExpectation,[bool]$Historical=$false){
    $id=[Fleetory.Pilot.AuditContainerCustody]::Id($Namespace,$AuditStore,${function:Invoke-Docker})
    function Write-RetainedServerSlot([string]$Name,[string]$Value){
        Write-RetainedConfiguredFile 'audit' ('/run/fleetory-native/server/'+$Name) $Value
    }
    function Invoke-RetainedServerProbe([string]$Mode,$Body=$null,[string]$ExpectedType='',[string[]]$Extra=@(),[byte[]]$Raw=$null){
        $bytes=if($null -ne $Raw){$Raw}elseif($null -ne $Body){[Text.Encoding]::UTF8.GetBytes(($Body|ConvertTo-Json -Depth 14 -Compress))}else{$null}
        $r=Invoke-RetainedAuditNative (@('exec','-i','-e','SSL_CERT_FILE=/tmp/ca.pem','-e','SSL_CERT_DIR=/tmp/empty-ca-dir',
            $id,'dotnet','/tool/ServerBackendProbe.dll',$Mode)+$Extra) $bytes -AllowFailure
        $value=$r.Stdout|ConvertFrom-Json -AsHashtable -Depth 20
        if($ExpectedType){
            Assert-ImmuData ($r.ExitCode -eq 1 -and $value.category -ceq 'unexpected' -and $value.errorType -ceq $ExpectedType) 'retained-server-typed-refusal'
            return $value
        }
        if($r.ExitCode -ne 0){
            foreach($field in @('errorType','causeType','location')){
                if($value.ContainsKey($field) -and $value[$field] -cmatch '^[A-Za-z0-9_]{1,80}\z'){[Console]::Error.WriteLine('Retained Server '+$Mode+': '+$field+'='+$value[$field])}
            }
        }
        Assert-ImmuData ($r.ExitCode -eq 0 -and $value.category -ceq $Mode) 'retained-server-probe'
        return $value
    }
    $null=Invoke-RetainedAuditNative @('exec',$id,'/bin/mkdir','-m','700','/run/fleetory-native/server')
    $slots=Get-RetainedServerSlots $Material
    foreach($name in $slots.Keys){Write-RetainedServerSlot $name $slots[$name]}
    $runtime=Invoke-RetainedServerProbe 'retained-runtime'
    Assert-ImmuData ($runtime.runtimeTlsLogins -eq 2 -and $runtime.wrongPasswordRefusals -eq 2 -and
        $runtime.plaintextRefusals -eq 2 -and $runtime.boundedRuntimePrivilegesVerified -and -not $runtime.httpHostStarted) 'retained-runtime-role-proof'
    $frame=@{fixture=$Nonce;snapshotBase64=[Convert]::ToBase64String($Snapshot);snapshotSha256=(Get-ImmuDataHash $Snapshot);
        profile=$(if($Historical){'historical-one-null-readonly'}else{'strict-readonly'});observation=$AuditExpectation}
    $refused=0
    foreach($mutation in @('snapshot-pin','known-value','coherent-wrong-snapshot')){
        $bad=($frame|ConvertTo-Json -Depth 14 -Compress)|ConvertFrom-Json -AsHashtable -Depth 20
        if($mutation -ceq 'snapshot-pin'){$bad.snapshotSha256='0'*64}
        elseif($mutation -ceq 'known-value'){$bad.observation.knownEvents[0].valueSha256='0'*64}
        else{
            $altered=[System.Text.Json.Nodes.JsonNode]::Parse([Text.Encoding]::UTF8.GetString($Snapshot))
            $altered['events'][0]['action']=[System.Text.Json.Nodes.JsonNode]::Parse('"Generated.Preflight.Refused"')
            $raw=[Text.Encoding]::UTF8.GetBytes($altered.ToJsonString())
            $pin=Get-ImmuDataHash $raw
            $mode=if($Historical){'audit-history-expectations'}else{'audit-expectations'}
            $derived=Invoke-RetainedServerProbe $mode -Extra @($pin,$Nonce) -Raw $raw
            Assert-ImmuData ($derived.snapshotSha256 -ceq $pin -and $derived.realBackendContacted -eq $false) 'retained-server-negative-independent-values'
            $bad.snapshotBase64=[Convert]::ToBase64String($raw);$bad.snapshotSha256=$pin;$bad.observation.knownEvents=$derived.knownEvents
            if($Historical){
                $sourceBytes=[Text.Encoding]::UTF8.GetBytes(($derived|ConvertTo-Json -Depth 10 -Compress))
                $body=@{sourceBase64=[Convert]::ToBase64String($sourceBytes);sourceSha256=(Get-ImmuDataHash $sourceBytes);nonce=$Nonce;
                    point=$AuditExpectation.point;producer=$AuditExpectation.producer}
                $built=Invoke-NativeBytes $comparisonPython @('-B',(Join-Path $pilot 'historical_audit_observation.py'),'build') ([Text.Encoding]::UTF8.GetBytes(($body|ConvertTo-Json -Depth 10 -Compress))) 10
                Assert-ImmuData ($built.ExitCode -eq 0 -and [string]::IsNullOrWhiteSpace($built.Stderr)) 'retained-historical-negative-consistent-frame'
                $bad.observation=$built.Stdout|ConvertFrom-Json -AsHashtable -Depth 14
            }
        }
        $null=Invoke-RetainedServerProbe 'retained-readonly-host' $bad -ExpectedType 'AuditExpectationInputException'
        $closed=Invoke-RetainedServerProbe 'pair-closed' @{fixture=$Nonce}
        Assert-ImmuData ($closed.closedPorts -eq 3) 'retained-server-refused-ports'
        $refused++
    }
    $hostResult=Invoke-RetainedServerProbe 'retained-readonly-host' $frame
    Assert-ImmuData ($hostResult.applicationStarts -eq 1 -and $hostResult.applicationStops -eq 1 -and $hostResult.workerStopped -and
        $hostResult.readiness -ceq 'Healthy' -and $hostResult.postgresSnapshotMatched -and $hostResult.nonemptyDataUnchanged -and
        $hostResult.readOnlyAuditCredentialUsed -and -not $hostResult.writerAdmissionVerified -and -not $hostResult.fixtureDerivedIdentityAdmissionUsed -and
        $hostResult.historicalNullMembersPreserved -eq $(if($Historical){1}else{0}) -and $hostResult.knownEvents -eq 4 -and $hostResult.nativeTransactions -eq 5) 'retained-server-host-proof'
    foreach($name in @('stateBefore','stateAfter')){
        $receipt=New-ImmudbStateReceipt $hostResult[$name] 'fleetoryaudit' $Material.PublicKeyPath
        Assert-ImmuData ($receipt.txId -eq 5 -and $receipt.txHash -ceq $AuditExpectation.point.txHash) 'retained-server-signed-state'
    }
    return @{runtime=$runtime;host=$hostResult;serverStarted=$true;runtimeLoginVerified=$true;historicalNullProfileVerified=$Historical;
        postHostAuditSignaturesVerified=$true;hostAdmissionRefusals=$refused;refusedPortsClosed=$true;
        originalUseAuthenticated=$false;fullSystemRecoveryVerified=$false;phase7Complete=$false}
}
