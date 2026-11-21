#requires -Version 7.3
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot '../../eng/pilot/ProviderRecoveryCredential.ps1')
. (Join-Path $PSScriptRoot 'NativeSignerFixture.ps1')
. (Join-Path $PSScriptRoot 'NativeWorkerRuntime.ps1')
$session=[Guid]::NewGuid().ToString('D');$provider='a'*64;$id='b'*64;$imageId='sha256:'+('c'*64)
$image=@{Id=$imageId;Config=@{Env=@('PATH=/bin')}}
$directory=[IO.Path]::GetFullPath((Join-Path ([IO.Path]::GetTempPath()) 'generated-probe'))
$script:removed=0;$script:scenario='lost-response'
function Invoke-Docker([string[]]$Arguments,[switch]$AllowFailure){
    if($Arguments[0] -ceq 'rm'){
        if(($Arguments -join '|') -cne ('rm|-f|-v|'+$id)){throw 'Cleanup escaped owned ID.'}
        $script:removed++;return @{ExitCode=0;Stdout='';Stderr=''}
    }
    if($Arguments[0] -cne 'inspect'){throw 'Unexpected fixture operation.'}
    if($script:scenario -ceq 'error'){return @{ExitCode=1;Stdout='';Stderr='permission denied'}}
    if($script:scenario -ceq 'gone' -or $script:removed -gt 0){return @{ExitCode=1;Stdout='';Stderr='No such object: owned'}}
    $found=@{Id=$id;Name=('/fleetory-native-signer-'+$session.Replace('-',''));Image=$imageId;Created=[DateTimeOffset]::UtcNow.ToString('O');
        Config=@{Image=$script:nativeSignerImage;Labels=@{'fleetory.native-signer.session'=$session;'fleetory.native-signer.role'='worker'}}}
    if($script:scenario -ceq 'foreign'){$found.Config.Labels['fleetory.native-signer.session']=[Guid]::NewGuid().ToString('D')}
    if($script:scenario -ceq 'source'){$found.Id=$provider}
    return @{ExitCode=0;Stdout=($found|ConvertTo-Json -Depth 6);Stderr=''}
}
function New-CleanupContext{
    $ctx=New-NativeWorkerContext $session $provider $directory $image
    $ctx.RunClaimed=$true;$ctx.Started=[DateTimeOffset]::UtcNow.AddSeconds(-1)
    return $ctx
}
Remove-NativeWorker (New-CleanupContext)
if($script:removed -ne 1){throw 'Lost run response did not reclaim the positively owned worker.'}
$refused=0
foreach($case in @('foreign','source','error')){
    $script:scenario=$case;$script:removed=0
    try{Remove-NativeWorker (New-CleanupContext)}
    catch{if($_.Exception.Message -cnotmatch '^Native signer fixture refused: '){throw};if($script:removed -ne 0){throw 'Unowned removal attempted.'};$refused++;continue}
    throw 'Unsafe cleanup result accepted.'
}
$script:scenario='gone';$script:removed=0;Remove-NativeWorker (New-CleanupContext)
if($script:removed -ne 0){throw 'Already absent worker was removed again.'}
foreach($operation in @(
    {Invoke-NativeWorker $null 'source' 'ready' $null @()},
    {Invoke-NativeWorker $null 'SignerJournalProbe' '../source' $null @()},
    {Invoke-NativeWorker $null 'SignerJournalProbe' 'ready' ([byte[]]::new(16386)) @()},
    {Write-NativeWorkerFile $null '/operator/key' ([byte[]]@(1))},
    {Write-NativeWorkerFile $null '/run/fleetory-native/signer/signer-postgresql' ([byte[]]::new(16385))},
    {Publish-NativeProbe '' 'source' ''}
)){
    try{& $operation}
    catch{if($_.Exception.Message -cnotmatch '^Native signer fixture refused: '){throw};$refused++;continue}
    throw 'Unsafe worker input accepted.'
}
if($refused -ne 9){throw 'Shared worker refusal cases incomplete.'}
Write-Host 'NATIVE WORKER CONTRACT PASS: lost-response and absent cleanup; 9 refusals; no Docker or original inputs.'
