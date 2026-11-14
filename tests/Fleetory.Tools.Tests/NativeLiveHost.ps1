#requires -Version 7.3
# Fixed non-secret coordination in the already owned worker tmpfs. Owner DB access stays in the caller.
function Get-NativeLiveControlArguments([string]$Id,[string]$Operation){
    if($Id -cnotmatch '^[0-9a-f]{64}$'){throw 'Invalid live worker identity.'}
    $directory='/run/fleetory-native/live'
    switch -CaseSensitive ($Operation){
        'setup' {return @('exec',$Id,'/bin/mkdir','-m','700',$directory)}
        'start' {
            $command='umask 077; set -C; dotnet /tool/ServerBackendProbe.dll host-live > /run/fleetory-native/live/result 2> /run/fleetory-native/live/error; native_status=$?; printf %s "$native_status" > /run/fleetory-native/live/exit-staging && mv -T /run/fleetory-native/live/exit-staging /run/fleetory-native/live/exit'
            return @('exec','-d','-e','SSL_CERT_FILE=/tmp/ca.pem',$Id,'/bin/sh','-c',$command)
        }
        'commit' {
            $command='umask 077; set -C; test ! -e /run/fleetory-native/live/revoked && printf revoked > /run/fleetory-native/live/revoked-staging && mv -T /run/fleetory-native/live/revoked-staging /run/fleetory-native/live/revoked'
            return @('exec',$Id,'/bin/sh','-c',$command)
        }
        default {
            $limits=@{ready=8;exit=3;result=8192;error=1024}
            if($Operation -cnotin @('ready','exit','result','error')){throw 'Unknown live control operation.'}
            $command='if [ ! -e "$1" ]; then exit 10; fi; test ! -L "$1" && test -f "$1" && test "$(stat -c %a:%u:%h "$1")" = 600:1654:1 || exit 11; exec head -c "$2" -- "$1"'
            return @('exec',$Id,'/bin/sh','-c',$command,'fixed-live-slot',($directory+'/'+$Operation),[string]($limits[$Operation]+1))
        }
    }
}
function Read-NativeLiveControlValue([string]$Operation,$Result){
    $limits=@{ready=8;exit=3;result=8192;error=1024}
    if($Operation -cnotin @('ready','exit','result','error') -or -not [string]::IsNullOrEmpty($Result.Stderr)){throw 'Invalid live control result.'}
    if($Result.ExitCode -eq 10 -and $Operation -cin @('ready','exit') -and $Result.StdoutBytes.Length -eq 0){return $null}
    if($Result.ExitCode -ne 0 -or $Result.StdoutBytes.Length -gt $limits[$Operation]){throw 'Live control operation failed or exceeded bounds.'}
    $value=[Text.UTF8Encoding]::new($false,$true).GetString($Result.StdoutBytes)
    if($Operation -ceq 'ready' -and $value -cne 'admitted'){throw 'Live ready marker mismatch.'}
    if($Operation -ceq 'exit' -and ($value -cnotmatch '^(0|[1-9][0-9]{0,2})$' -or [int]$value -gt 255)){throw 'Live exit marker mismatch.'}
    return $value
}
function Invoke-NativeLiveControl([string]$Operation){
    Read-NativeWorkerContext $worker
    $r=Invoke-Docker (Get-NativeLiveControlArguments $worker.Id $Operation) -TimeoutSeconds 3 -AllowFailure
    if($Operation -cin @('ready','exit','result','error')){return Read-NativeLiveControlValue $Operation $r}
    Assert-True ($r.ExitCode -eq 0 -and $r.StdoutBytes.Length -eq 0 -and $r.StderrBytes.Length -eq 0) 'Live control mutation failed.'
}
function Wait-NativeLiveControl([string]$Operation,[Diagnostics.Stopwatch]$Clock){
    do{
        Assert-True ($Operation -cin @('ready','exit') -and $Clock.Elapsed.TotalSeconds -lt 25) 'Live control wait deadline exceeded.'
        $value=Invoke-NativeLiveControl $Operation
        if($null -ne $value){return $value}
        Start-Sleep -Milliseconds 50
    }while($true)
}
function Invoke-NativeLiveHost([hashtable]$Seed,[string[]]$PriorEvents){
    Read-Store 'postgres';Read-Store 'audit'
    Invoke-NativeLiveControl 'setup'
    $clock=[Diagnostics.Stopwatch]::StartNew()
    try{
        Invoke-NativeLiveControl 'start'
        $null=Wait-NativeLiveControl 'ready' $clock
        Assert-WorkerQueue 6 0
        $oidcEvent=Get-PipelineEventJson 'admin.oidc.denied'
        Assert-WorkerAudit (@($PriorEvents)+@($oidcEvent))
        Revoke-NativeFixtureIdentity $Seed
        Invoke-NativeLiveControl 'commit'
        $exit=Wait-NativeLiveControl 'exit' $clock
        $output=Invoke-NativeLiveControl 'result';$errors=Invoke-NativeLiveControl 'error'
        foreach($value in $canaries){Assert-True ($value.Length -lt 12 -or -not ($output+$errors).Contains($value,[StringComparison]::Ordinal)) 'Live output canary detected.'}
        $record=Read-ServerProbeRecord ([pscustomobject]@{ExitCode=[int]$exit;Stdout=$output;Stderr=$errors}) 'host-live' 'host-live'
        $record.acceptedOidcEvent=$oidcEvent
        return $record
    }finally{$clock.Stop()}
}
