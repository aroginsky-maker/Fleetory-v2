#requires -Version 7.3
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
function Require($Condition,[string]$Category){if(-not $Condition){throw $Category}}
. (Join-Path $PSScriptRoot '../../eng/pilot/ImmuDataRoundtripPolicy.ps1')
. (Join-Path $PSScriptRoot '../../eng/pilot/historical/RetainedInFlightSql.ps1')
Assert-RetainedObservedWorkArguments @('exec',('a'*64),'pg_isready','-q','-U','postgres')
$purposeRefusals=0
foreach($arguments in @($null,([string[]]@()),@('EXEC','target','command'),@('create','target','image'),@('run','target','image'),@('build','target','image'),@('exec'),@('exec','target'))){
    try{Assert-RetainedObservedWorkArguments $arguments}catch{
        if($_.Exception.GetBaseException().Message -cne 'Audit data fixture refused: observed-client-exec-only'){throw}
        $purposeRefusals++;continue
    }
    throw 'Observed creation/build or incomplete exec purpose accepted.'
}
Require ($purposeRefusals-eq8) 'observed-exec-purpose-only-no-resource-authority'
$commandRefusals=0
foreach($arguments in @(@('exec',('a'*64),'/bin/true'),@('exec',('a'*64),'/bin/sh','-c','unlisted'),
    @('exec',('a'*64),'dotnet','/tmp/other.dll'),@('exec','--privileged',('a'*64),'psql'),
    @('exec','target','psql'),@('exec','-e','broken',('a'*64),'psql'))){
    try{Assert-RetainedObservedWorkArguments $arguments;throw 'Unlisted native command shape accepted.'}catch{
        if($_.Exception.Message -notmatch '^Audit data fixture refused: observed-client-'){throw}
        $commandRefusals++
    }
}
Require ($commandRefusals -eq 6) 'observed-command-boundary-refusals'
. (Join-Path $PSScriptRoot '../../eng/pilot/historical/RetainedCoupledAudit.ps1')
$id='a'*64
Assert-RetainedObservedWorkArguments (Get-RetainedAuditStartArguments $id)
foreach($mode in @('login','backup','verify','restore')){Assert-RetainedObservedWorkArguments (Get-ImmuDataCliArguments $id $mode)}
Assert-RetainedObservedWorkArguments @('exec','-i','-e','PGCLIENTENCODING=UTF8',$id,'psql','-XqAt','-U','postgres','-d','postgres')
Assert-RetainedObservedWorkArguments @('exec','-i','-e','PGAPPNAME=fleetory-generated-lock-123',$id,'pg_restore','--data-only')
Assert-RetainedObservedWorkArguments @('exec','-i',$id,'/bin/sh','-c','set -eu; umask 077; test ! -L "$1"; cat > "$1"; stat -c %a:%u:%h "$1"; sha256sum "$1"','fixture','/tmp/server.crt')
$environmentRefusals=0
foreach($entry in @('LD_PRELOAD=/tmp/library','PATH=/tmp','HOME=/root','SSL_CERT_FILE=/tmp/foreign','SSL_CERT_DIR=/etc/ssl','PGCLIENTENCODING=LATIN1','PGAPPNAME=contains space')){
    try{Assert-RetainedObservedWorkArguments @('exec','-e',$entry,$id,'psql');throw 'Unknown environment accepted.'}catch{
        if($_.Exception.Message -cne 'Audit data fixture refused: observed-client-environment-purpose'){throw}
        $environmentRefusals++
    }
}
try{Assert-RetainedObservedWorkArguments @('exec','-e','HOME=/tmp','-e','HOME=/tmp',$id,'psql');throw 'Duplicate environment accepted.'}catch{
    if($_.Exception.Message -cne 'Audit data fixture refused: observed-client-environment-duplicate'){throw}
    $environmentRefusals++
}
Require ($environmentRefusals -eq 8) 'observed-environment-purpose-refusals'


Write-Output 'OBSERVED COMMAND PURPOSE PASS:8 real-builder positives,6 command refusals,8 environment refusals; no Docker invocation.'

# The expected ID comes from the live owner, never from the argument packet.
Assert-RetainedObservedWorkArguments @('exec',$id,'pg_isready','-q','-U','postgres') -ExpectedIdentifier $id
Assert-RetainedObservedWorkArguments @('exec','-i','-e','PGCLIENTENCODING=UTF8',$id,'psql','-XqAt') -ExpectedIdentifier $id
$foreign='b'*64;$ownedTargetRefusals=0
foreach($arguments in @(@('exec',$foreign,'psql','-XqAt','-v',$id),@('exec','-i',$foreign,'psql',$id),
    @('exec','-e',('PGAPPNAME='+$id),$foreign,'psql'),@('exec',$foreign,'dotnet','/tool/ServerBackendProbe.dll',$id))){
    Require ($arguments -ccontains $id -or $arguments -ccontains ('PGAPPNAME='+$id)) 'owned-id-reproduction'
    try{Assert-RetainedObservedWorkArguments $arguments -ExpectedIdentifier $id;throw 'Foreign target with owned ID elsewhere accepted.'}catch{
        if($_.Exception.GetBaseException().Message -cne 'Audit data fixture refused: observed-client-owned-target'){throw}
        $ownedTargetRefusals++
    }
}
Require ($ownedTargetRefusals -eq 4) 'observed-owned-target-refusals'
Write-Output 'OBSERVED OWNED TARGET PASS:2 exact-target positives and 4 misplaced-owned-ID refusals; no Docker invocation.'
