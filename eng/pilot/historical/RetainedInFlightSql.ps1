#requires -Version 7.3
# Private functions run in the live retained owner's scope. No serialized process/resource claim is accepted.
function Assert-RetainedObservedWorkArguments([string[]]$Arguments,[string]$ExpectedIdentifier='',[ValidateSet('','postgres','audit')][string]$ExpectedRole=''){
    Assert-ImmuData ($null -ne $Arguments -and $Arguments.Count -ge 3 -and $Arguments[0] -ceq 'exec') 'observed-client-exec-only'
    $index=1;$environments=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    while($index -lt $Arguments.Count -and $Arguments[$index].StartsWith('-',[StringComparison]::Ordinal)){
        $option=$Arguments[$index];$index++
        if($option -ceq '-e'){
            Assert-ImmuData ($index -lt $Arguments.Count -and $Arguments[$index] -cmatch '^[A-Z][A-Z0-9_]*=[^\x00\r\n]{0,4096}\z') 'observed-client-environment-shape'
            $pair=$Arguments[$index].Split('=',2);$key=$pair[0];$value=$pair[1]
            Assert-ImmuData ($environments.Add($key)) 'observed-client-environment-duplicate'
            $fixed=@{HOME='/tmp';PGCLIENTENCODING='UTF8';SSL_CERT_FILE='/tmp/ca.pem';SSL_CERT_DIR='/tmp/empty-ca-dir'}
            $allowed=if($key -ceq 'PGAPPNAME'){$value -cmatch '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\z'}
                else{$fixed.ContainsKey($key) -and $value -ceq $fixed[$key]}
            Assert-ImmuData $allowed 'observed-client-environment-purpose'
            $index++
        }else{Assert-ImmuData ($option -cin @('-i','-d')) 'observed-client-option'}
    }
    Assert-ImmuData ($index+1 -lt $Arguments.Count -and $Arguments[$index] -cmatch '^[a-f0-9]{64}\z') 'observed-client-target-shape'
    if($ExpectedIdentifier){
        Assert-ImmuData ($ExpectedIdentifier -cmatch '^[a-f0-9]{64}\z' -and $Arguments[$index] -ceq $ExpectedIdentifier) 'observed-client-owned-target'
    }
    $index++;$program=$Arguments[$index]
    Assert-ImmuData ($program -cin @('postgres','pg_isready','psql','pg_restore','initdb','pg_ctl','dotnet','sha256sum',
        '/bin/mkdir','/bin/cat','/bin/kill','/usr/sbin/immudb','/usr/local/bin/immuadmin','/bin/sh')) 'observed-client-program'
    if($ExpectedRole){
        Assert-ImmuData (-not [string]::IsNullOrEmpty($ExpectedIdentifier)) 'observed-client-role-owner-required'
        $allowed=if($ExpectedRole -ceq 'postgres'){$program -cin @('postgres','pg_isready','psql','pg_restore','initdb','pg_ctl','/bin/sh')}
            else{$program -cin @('dotnet','sha256sum','/bin/mkdir','/bin/cat','/bin/kill','/usr/sbin/immudb','/usr/local/bin/immuadmin','/bin/sh')}
        Assert-ImmuData $allowed 'observed-client-role-program'
    }
    if($program -ceq 'dotnet'){
        Assert-ImmuData ($index+1 -lt $Arguments.Count -and $Arguments[$index+1] -ceq '/tool/ServerBackendProbe.dll') 'observed-client-probe-entry'
    }
    if($program -ceq '/bin/sh'){
        Assert-ImmuData ($Arguments.Count -eq $index+5 -and $Arguments[$index+1] -ceq '-c' -and
            $Arguments[$index+2] -ceq 'set -eu; umask 077; test ! -L "$1"; cat > "$1"; stat -c %a:%u:%h "$1"; sha256sum "$1"' -and
            $Arguments[$index+3] -ceq 'fixture') 'observed-client-fixed-shell'
    }
    if($program -ceq 'sha256sum'){
        Assert-ImmuData ($Arguments.Count -eq $index+2 -and $Arguments[$index+1] -ceq '/tool/ServerBackendProbe.dll') 'observed-client-hash-path'
    }
    if($program -ceq '/bin/cat'){
        Assert-ImmuData ($Arguments.Count -eq $index+2 -and $Arguments[$index+1] -ceq '/tmp/immudb.pid') 'observed-client-pid-path'
    }
    if($program -ceq '/bin/mkdir'){
        Assert-ImmuData ($Arguments.Count -eq $index+4 -and $Arguments[$index+1] -ceq '-m' -and $Arguments[$index+2] -ceq '700' -and
            $Arguments[$index+3] -cin @('/tmp/empty-ca-dir','/run/fleetory-native/server')) 'observed-client-directory-path'
    }
    if($program -ceq '/bin/kill'){
        Assert-ImmuData ($Arguments.Count -eq $index+3 -and $Arguments[$index+1] -cin @('-TERM','-0') -and
            $Arguments[$index+2] -cmatch '^[1-9][0-9]{0,7}\z') 'observed-client-signal-purpose'
    }
    if($program -ceq '/bin/sh'){
        $path=$Arguments[$index+4]
        $temporary=$path -cin @('/tmp/ca.pem','/tmp/server.crt','/tmp/server.key','/tmp/client.crt','/tmp/client.key',
            '/tmp/state.key','/tmp/immudb.toml','/tmp/cli.toml','/tmp/hba.conf')
        $server=$path -cmatch '^/run/fleetory-native/server/(infrastructure-ca|audit-immudb-password|fleetory-postgresql|fleetory-signer-postgresql|(agent|admin)-gateway-(root-ca|server-cert|server-key))\z'
        Assert-ImmuData ($temporary -or $server) 'observed-client-configuration-path'
        if($ExpectedRole){
            $rolePath=if($ExpectedRole -ceq 'postgres'){$path -cin @('/tmp/ca.pem','/tmp/server.crt','/tmp/server.key','/tmp/hba.conf')}
                else{$path -cne '/tmp/hba.conf'}
            Assert-ImmuData $rolePath 'observed-client-role-configuration-path'
        }
    }
    if($program -cin @('postgres','initdb','pg_isready','pg_ctl','pg_restore')){
        $tail=@($Arguments | Select-Object -Skip ($index+1));$catalog=@()
        switch -CaseSensitive ($program){
            'postgres' {
                $base=@('-D','/var/lib/postgresql/18/recovery','-c','listen_addresses=','-c','unix_socket_directories=/var/run/postgresql',
                    '-c','shared_buffers=32MB','-c','max_connections=20','-c','password_encryption=scram-sha-256',
                    '-c','log_statement=none','-c','log_min_error_statement=panic')
                $catalog+=,$base
                $tls=[string[]]$base.Clone();$tls[3]='listen_addresses=127.0.0.1'
                $catalog+=,@($tls+@('-c','hba_file=/tmp/hba.conf','-c','ssl=on','-c','ssl_cert_file=/tmp/server.crt',
                    '-c','ssl_key_file=/tmp/server.key','-c','ssl_min_protocol_version=TLSv1.2'))
            }
            'initdb' {$catalog+=,@('-D','/var/lib/postgresql/18/recovery','--auth-local=peer','--auth-host=reject','--no-instructions')}
            'pg_isready' {$catalog+=,@('-q','-U','postgres')}
            'pg_ctl' {$catalog+=,@('-D','/var/lib/postgresql/18/recovery','stop','-m','fast','-w','-t','5')}
            'pg_restore' {
                foreach($pair in @(@('fleetory','fleetory_migrator'),@('fleetory_signer','fleetory_signer_owner'))){
                    $catalog+=,@('--exit-on-error','--single-transaction','--no-password',('--role='+$pair[1]),'--username=postgres',('--dbname='+$pair[0]))
                }
                foreach($mode in @('--section=pre-data','--data-only')){
                    $catalog+=,@($mode,'--exit-on-error','--single-transaction','--no-password','--role=fleetory_migrator','--username=postgres','--dbname=fleetory')
                }
            }
        }
        $matched=$false
        foreach($expected in $catalog){
            if($tail.Count -eq $expected.Count -and ($tail -join "`0") -ceq ($expected -join "`0")){$matched=$true;break}
        }
        Assert-ImmuData $matched 'observed-client-postgres-purpose'
    }
    if($program -cin @('/usr/sbin/immudb','/usr/local/bin/immuadmin')){
        $identifier=$Arguments[$index-1];$catalog=@()
        if($program -ceq '/usr/sbin/immudb'){$catalog+=,@(Get-RetainedAuditStartArguments $identifier)}else{
            foreach($mode in @('login','backup','verify','restore')){$catalog+=,@(Get-ImmuDataCliArguments $identifier $mode)}
        }
        $matched=$false
        foreach($expected in $catalog){
            if($Arguments.Count -eq $expected.Count -and ($Arguments -join "`0") -ceq ($expected -join "`0")){$matched=$true;break}
        }
        Assert-ImmuData $matched 'observed-client-immudb-purpose'
    }
    if($program -ceq 'dotnet'){
        $prefix=@('exec','-i','-e','SSL_CERT_FILE=/tmp/ca.pem','-e','SSL_CERT_DIR=/tmp/empty-ca-dir',
            $Arguments[$index-1],'dotnet','/tool/ServerBackendProbe.dll')
        Assert-ImmuData ($index -eq 7 -and $Arguments.Count -ge 10 -and
            ($Arguments[0..8] -join "`0") -ceq ($prefix -join "`0")) 'observed-client-probe-prefix'
        $mode=$Arguments[9]
        $plain=$mode -cin @('audit-health','history-users','observation-read','observation-history-read','retained-runtime','retained-readonly-host','pair-closed')
        $expectation=$mode -cin @('audit-expectations','audit-history-expectations')
        $allowed=($plain -and $Arguments.Count -eq 10)
        if($expectation -and $Arguments.Count -eq 12){
            $allowed=$Arguments[10] -cmatch '^[a-f0-9]{64}\z' -and
                $Arguments[11] -cmatch '^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\z'
        }
        Assert-ImmuData $allowed 'observed-client-probe-mode'
    }
    if($program -ceq 'psql'){
        $tail=@($Arguments | Select-Object -Skip ($index+1));$catalog=@()
        foreach($database in @('postgres','fleetory','fleetory_signer')){$catalog+=,@('-XqAt','-v','ON_ERROR_STOP=1','-U','postgres','-d',$database)}
        $catalog+=,@('-XqAt','-U','postgres','-d','postgres')
        $catalog+=,@('-XqAt','-v','ON_ERROR_STOP=1','-U','postgres','-d','fleetory','-c',
            'BEGIN; LOCK TABLE platform.audit_events IN ACCESS EXCLUSIVE MODE; SELECT pg_sleep(30); ROLLBACK;')
        $matched=$false
        foreach($expected in $catalog){
            if($tail.Count -eq $expected.Count -and ($tail -join "`0") -ceq ($expected -join "`0")){$matched=$true;break}
        }
        Assert-ImmuData $matched 'observed-client-psql-purpose'
    }
    # This is a command-shape boundary, never resource custody or full argv/runtime provenance.

}
function Observe-RetainedNativeProcess([Diagnostics.Process]$Process,[Threading.CancellationToken]$Token){
    $meter.processObservationChecks++
    Confirm-RetainedLiveWork $Token
    if($meter.inflightPending){Interrupt-RetainedActiveNative $Process $Token}
}
function Interrupt-RetainedActiveNative([Diagnostics.Process]$Process,[Threading.CancellationToken]$Token){
    Assert-ImmuData ($Flow -cin @('inflight-sql-exit','inflight-restore-exit') -and $meter.inflightPending -and -not $meter.inflightObserved -and
        $Token.CanBeCanceled -and -not $Process.HasExited -and $meter.inflightWatch.Elapsed.TotalSeconds -lt 8) 'retained-inflight-fault-scope'
    [Fleetory.Pilot.NativeExecutableLease]::AssertStarted($Process)
    $Token.ThrowIfCancellationRequested()
    $id=[Fleetory.Pilot.AuditContainerCustody]::Id($context,$store,$client)
    $meter.inflightObserver=[Diagnostics.Process]::GetProcessById($Process.Id)
    $null=$meter.inflightObserver.Handle
    $birth=Get-HistoricalNativeBirth $Process
    $other=Get-HistoricalNativeBirth $meter.inflightObserver
    Assert-ImmuData ($birth.kind -ceq $other.kind -and $birth.token -ceq $other.token) 'retained-inflight-client-birth'
    $meter.inflightBirth=$birth;$meter.inflightNativePid=$Process.Id
    $observation=if($Flow -ceq 'inflight-restore-exit'){Get-RetainedRestoreObservation}else{
        @{Database='postgres';Sql=("SELECT count(*) FROM pg_stat_activity WHERE datname='postgres' AND usename='postgres' AND application_name='"+
            $meter.inflightApplication+"' AND state='active' AND wait_event_type='Timeout' AND wait_event='PgSleep' AND query='"+$meter.inflightSql+"';")}
    }
    $meter.inflightObservationCalls++
    $reply=Invoke-Docker @('exec','-i',$id,'psql','-XqAt','-v','ON_ERROR_STOP=1','-U','postgres','-d',$observation.Database) ([Text.Encoding]::UTF8.GetBytes($observation.Sql)) 2
    Assert-ImmuData ($reply.ExitCode -eq 0 -and $reply.Stdout.Trim() -ceq '1' -and [string]::IsNullOrWhiteSpace($reply.Stderr) -and
        -not $Process.HasExited) 'retained-inflight-query-actually-active'
    $Token.ThrowIfCancellationRequested()
    $meter.inflightObserved=$true
    $meter.dispatchesAtInterruption=$meter.nativeDispatches
    if($null -ne (Get-Variable -Name externalController -ValueOnly -ErrorAction SilentlyContinue) -and $externalSql){
        Assert-ImmuData ($Flow -ceq 'inflight-sql-exit') 'external-controller-fixed-readonly-sql'
        Arm-RetainedControllerPipe $externalController $plan.nonce $Process
        try{Wait-RetainedControllerLoss $externalController $Token $clock}catch{
            if($_.Exception.GetBaseException() -isnot [OperationCanceledException]){throw}
            Assert-ImmuData (-not $Process.HasExited) 'external-loss-before-native-client-exit'
            $meter.inflightAliveAtExternalLoss=$true
            throw
        }
        throw 'External SQL fault unexpectedly returned.'
    }
    $prefix=if($Flow -ceq 'inflight-restore-exit'){'interrupt-restore:'}else{'interrupt-inflight:'}
    Send-IndependentFrame $peer.input ([Text.Encoding]::ASCII.GetBytes($prefix+$peer.projection)) $Token
    $frame=Read-IndependentFrame $peer.output $Token 2048
    $peer.input.Dispose()
    $meter.workLossProof=Receive-HistoricalCoordinatorCompletion $peer 'terminate' $frame -Token $Token
    $meter.controllerLossObserved=$true
    throw [OperationCanceledException]::new('Retained coordinator exited during native work.', $Token)
}
function Invoke-RetainedInFlightSql{
    Assert-ImmuData ($Flow -ceq 'inflight-sql-exit' -and $null -ne $auditProof -and $meter.restores -eq 2) 'retained-inflight-restored-scope'
    $meter.inflightApplication='fleetory-inflight-'+$plan.nonce
    Assert-ImmuData ($meter.inflightApplication -cmatch '^fleetory-inflight-[a-f0-9-]{36}\z') 'retained-inflight-application'
    $meter.inflightSql='SELECT pg_sleep(10) /* '+$meter.inflightApplication+' */;'
    $id=[Fleetory.Pilot.AuditContainerCustody]::Id($context,$store,$client)
    $meter.inflightPending=$true;$meter.inflightWatch=[Diagnostics.Stopwatch]::StartNew()
    try{
        $null=Invoke-RetainedPgNative @('exec','-i','-e',('PGAPPNAME='+$meter.inflightApplication),$id,'psql','-XqAt',
            '-v','ON_ERROR_STOP=1','-U','postgres','-d','postgres') ([Text.Encoding]::UTF8.GetBytes($meter.inflightSql))
        throw 'Retained in-flight fault did not interrupt the native operation.'
    }finally{$meter.inflightPending=$false}
}
function Confirm-RetainedInterruptedNative{
    Assert-ImmuData ($meter.inflightObserved -and $meter.controllerLossObserved -and $meter.inflightObservationCalls -eq 1 -and
        $null -ne $meter.inflightObserver -and $meter.inflightObserver.HasExited -and $peer.holder.HasExited -and
        $meter.workLossProof.coordinatorExitCode -ne 0 -and $meter.workLossProof.membersAbsent -and
        $meter.nativeDispatches -eq $meter.dispatchesAtInterruption) 'retained-inflight-native-client-cancelled'
    $meter.inflightClientExited=$true
    $before=$meter.nativeDispatches
    try{
        $id=[Fleetory.Pilot.AuditContainerCustody]::Id($context,$store,$client)
        $null=Invoke-RetainedPgNative @('exec','-i',$id,'psql','-XqAt','-U','postgres','-d','postgres') ([Text.Encoding]::UTF8.GetBytes('SELECT 1;'))
    }catch{
        if($_.Exception.GetBaseException().Message -cne 'Audit data fixture refused: retained-work-window'){throw}
        $meter.lateWorkRefusals++
    }
    Assert-ImmuData ($meter.lateWorkRefusals -eq 1 -and $meter.nativeDispatches -eq $before) 'retained-inflight-no-late-work'
}
