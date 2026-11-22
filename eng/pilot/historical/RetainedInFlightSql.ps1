#requires -Version 7.3
# Private functions run in the live retained owner's scope. No serialized process/resource claim is accepted.
function Assert-RetainedObservedWorkArguments([string[]]$Arguments,[string]$ExpectedIdentifier=''){
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
        $Token.CanBeCanceled -and -not $Process.HasExited -and $Process.ProcessName -ceq 'docker' -and $meter.inflightWatch.Elapsed.TotalSeconds -lt 8) 'retained-inflight-fault-scope'
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
