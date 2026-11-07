#requires -Version 7.3
# Generated-only native component acceptance. No operator paths, SSH or retained key inputs.
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
& (Join-Path $PSScriptRoot 'NativeSignerBoundary.Tests.ps1')
$repoRoot=Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
. (Join-Path $PSScriptRoot 'PilotNativeProcess.ps1')
. (Join-Path $PSScriptRoot '../../eng/pilot/ProviderRecoveryTransport.ps1')
. (Join-Path $PSScriptRoot '../../eng/pilot/ProviderRecoveryPolicy.ps1')
. (Join-Path $PSScriptRoot 'PilotDisposableTls.ps1')
. (Join-Path $PSScriptRoot 'NativeSignerFixture.ps1')
. (Join-Path $PSScriptRoot 'NativeWorkerRuntime.ps1')
$image='ghcr.io/openbao/openbao:2.7.1@sha256:6d2b93856e3fcf7b18ad855a0b51eaba474dc8b79cf554379ea32034797d2acf'
$session=[Guid]::NewGuid().ToString('D');$records=[Collections.Generic.List[object]]::new()
$providerTransitKey='fleetory-recovery-fixture';$providerAuditName='fixture-file'
$script:forceRestoreClaimed=$false;$script:credentialCanaries=[Collections.Generic.List[string]]::new()
$workerContext=$null;$providerId=$null;$public=$null
$root=$share=$signerToken=$readonlyToken=$expiredToken=$revokedToken=$null
$material=$wrongMaterial=$null;$stage='publish';$proof=$null
$publicRoot=Join-Path $repoRoot ('artifacts/native-signer-'+$session)
$published=Join-Path $publicRoot 'publish'
function Assert-True([bool]$Condition,[string]$Message){if(-not $Condition){throw $Message}}
function Invoke-Docker([string[]]$Arguments,[byte[]]$InputBytes=$null,[int]$TimeoutSeconds=90,[switch]$AllowFailure){
    $result=if($IsLinux){Invoke-NativeBytes '/bin/sh' @('-c',(Get-ProviderDockerShellCommand $Arguments)) $InputBytes $TimeoutSeconds}
        else{Invoke-NativeBytes 'docker' (@('--context','desktop-linux')+$Arguments) $InputBytes $TimeoutSeconds}
    if(-not $AllowFailure -and $result.ExitCode -ne 0){throw 'Native signer Docker operation failed.'}
    return $result
}
. (Join-Path $PSScriptRoot '../../eng/pilot/ProviderRecoveryRuntime.ps1')
function Write-NativePublicFile([string]$Path,[string]$Value){
    Assert-True ($Path -cin @('/tmp/ca.pem','/tmp/wrong-ca.pem')) 'Unknown public file slot.'
    Write-NativeWorkerFile $workerContext $Path ([Text.Encoding]::UTF8.GetBytes($Value))
}
function New-NativeToken([string]$Policy,[int]$Seconds){
    $r=Invoke-AuthenticatedJson $providerId $root @('write','-format=json','auth/token/create-orphan',
        ('policies='+$Policy),'no_default_policy=true',('ttl='+$Seconds+'s'),('explicit_max_ttl='+$Seconds+'s'),'renewable=false')
    $value=[string]$r.auth.client_token
    Assert-True ($value.Length -gt 16) 'Fixture token missing.'
    $script:credentialCanaries.Add($value)
    return $value
}
function Invoke-NativeProbe([string]$Mode,[string]$Token,[string]$Category,[switch]$WrongTrust,[byte[]]$Packet=$null,[int]$ExpectedExit=0){
    if($null -eq $Packet){$Packet=[Text.Encoding]::UTF8.GetBytes((@{token=$Token;publicKey=[Convert]::ToBase64String($public.Spki)}|ConvertTo-Json -Compress))}
    $r=Invoke-NativeWorker $workerContext 'SignerBackendProbe' $Mode $Packet $script:credentialCanaries.ToArray() -WrongTrust:$WrongTrust
    $record=Get-Json $r.Stdout
    if($r.ExitCode -ne $ExpectedExit -or -not [string]::IsNullOrWhiteSpace($r.Stderr) -or $record.category -cne $Category){
        $safeCategory=if($record.category -cmatch '^[a-z0-9-]{1,32}$'){$record.category}else{'invalid'}
        throw ('Native probe mismatch: '+$Mode+';category='+$safeCategory+';exit='+[string]$r.ExitCode)
    }
    Assert-True ($record.category -ceq $Category -and $record.agentCommandDispatched -eq $false) 'Native probe category mismatch.'
}
try{
    $null=New-Item -ItemType Directory -Path $publicRoot
    $published=Publish-NativeProbe $repoRoot 'SignerBackendProbe' $publicRoot
    $stage='images'
    foreach($candidate in @($image,$script:nativeSignerImage)){
        $inspect=Invoke-Docker @('image','inspect',$candidate) -AllowFailure
        if($inspect.ExitCode -ne 0){$null=Invoke-Docker @('pull',$candidate) -TimeoutSeconds 120}
    }
    $runtime=@(Get-Json (Invoke-Docker @('image','inspect',$script:nativeSignerImage)).Stdout)[0]
    $stage='provider'
    $material=New-PilotDisposableTlsMaterial;$wrongMaterial=New-PilotDisposableTlsMaterial
    $providerId=New-Container 'source';$null=Assert-Owned $providerId 'source'
    Write-ContainerFile $providerId '/tmp/ca.pem' ([Text.Encoding]::UTF8.GetBytes($material.RootCertificatePem))
    Write-ContainerFile $providerId '/tmp/server.crt' ([Text.Encoding]::UTF8.GetBytes($material.ServerCertificatePem))
    Write-ContainerFile $providerId '/tmp/server.key' ([Text.Encoding]::UTF8.GetBytes($material.ServerPrivateKeyPem))
    Start-Bao $providerId 'source'
    $init=Get-Json (Invoke-Bao $providerId @('operator','init','-key-shares=1','-key-threshold=1','-format=json')).Stdout
    $root=[string]$init.root_token;$share=[string]$init.unseal_keys_b64[0]
    $script:credentialCanaries.Add($root);$script:credentialCanaries.Add($share)
    $null=Invoke-Unseal $providerId $share;$null=Wait-Active $providerId
    $null=Invoke-Bao $providerId @('secrets','enable','transit') $root
    $null=Invoke-Bao $providerId @('write',('transit/keys/'+$providerTransitKey),'type=ecdsa-p256','exportable=false','allow_plaintext_backup=false') $root
    $public=Get-TransitPublic $providerId $root
    $policy='path "transit/sign/fleetory-recovery-fixture/sha2-256" { capabilities = ["update"] }'+"`n"+
        'path "auth/token/lookup-self" { capabilities = ["read"] }'+"`n"+'path "auth/token/revoke-self" { capabilities = ["update"] }'
    $readonly='path "auth/token/lookup-self" { capabilities = ["read"] }'+"`n"+'path "auth/token/revoke-self" { capabilities = ["update"] }'
    $null=Invoke-Bao $providerId @('policy','write','fixture-native-signer','-') $root ([Text.Encoding]::UTF8.GetBytes($policy))
    $null=Invoke-Bao $providerId @('policy','write','fixture-native-readonly','-') $root ([Text.Encoding]::UTF8.GetBytes($readonly))
    $signerToken=New-NativeToken 'fixture-native-signer' 300;$readonlyToken=New-NativeToken 'fixture-native-readonly' 300
    $revokedToken=New-NativeToken 'fixture-native-signer' 300
    $expiredToken=New-NativeToken 'fixture-native-signer' 1
    $null=Invoke-Bao $providerId @('token','revoke','-self') $revokedToken
    $null=Invoke-Bao $providerId @('token','revoke','-self') $root
    Assert-Forbidden $providerId $root @('read',('transit/keys/'+$providerTransitKey)) 'Revoked fixture root'
    $stage='worker'
    $null=Assert-Owned $providerId 'source'
    $workerContext=New-NativeWorkerContext $session $providerId $published $runtime
    Start-NativeWorkerContext $workerContext
    $null=Invoke-Docker @('exec',$workerContext.Id,'/bin/mkdir','-m','700','/tmp/empty-ca-dir')
    Write-NativePublicFile '/tmp/ca.pem' $material.RootCertificatePem
    Write-NativePublicFile '/tmp/wrong-ca.pem' $wrongMaterial.RootCertificatePem
    $stage='native'
    Invoke-NativeProbe 'accepted' $signerToken 'accepted'
    Invoke-NativeProbe 'wrong-key' $signerToken 'key-pin'
    Invoke-NativeProbe 'wrong-version' $signerToken 'key-version-500'
    Invoke-NativeProbe 'denied' $readonlyToken 'forbidden'
    Invoke-NativeProbe 'denied' ('invalid-fixture-'+$session) 'forbidden'
    Invoke-NativeProbe 'denied' $revokedToken 'forbidden'
    Start-Sleep -Seconds 2
    Invoke-NativeProbe 'denied' $expiredToken 'forbidden'
    Invoke-NativeProbe 'tls-denied' $signerToken 'tls' -WrongTrust
    $null=Invoke-Bao $providerId @('token','revoke','-self') $signerToken
    Invoke-NativeProbe 'denied' $signerToken 'forbidden'
    $null=Invoke-Bao $providerId @('token','revoke','-self') $readonlyToken
    foreach($packet in @('{}','{"token":"a","token":"b","publicKey":"a"}','{"token":"x","publicKey":"x","endpoint":"source"}')){
        Invoke-NativeProbe 'accepted' '' 'invalid-input' -Packet ([Text.Encoding]::UTF8.GetBytes($packet)) -ExpectedExit 64
    }
    $proof=[ordered]@{schema='fleetory.native-signer-backend.v1';verified=$true;nativeSignatureVerified=$true;
        backendRefusals=8;unsupportedVersionHttpStatus=500;inputRefusals=3;boundaryMutationsRefused=23;rootRevokedBeforeProbe=$true;
        workerOnlyLoopbackInterface=$true;workerSharesOnlyOwnedNetworkNoneProvider=$true;publishedPorts=0;
        sourceVpsAccessed=$false;originalMaterialUsed=$false;retainedKeyContinuityVerified=$false;
        fullSignerHostStarted=$false;agentCommandDispatched=$false;fullSystemRecoveryVerified=$false;phase7Complete=$false}
}
catch{
    if($_.Exception.Message -cmatch '^Native probe mismatch: ([a-z-]+;category=[a-z0-9-]+;exit=[0-9]+)$'){
        [Console]::Error.WriteLine('Native probe diagnostic: '+$Matches[1])
    }
    [Console]::Error.WriteLine('Generated native signer fixture failed at '+$stage+'; type='+$_.Exception.GetType().Name+'; line='+$_.InvocationInfo.ScriptLineNumber+'. No raw response or credential emitted.')
    throw 'Generated native signer fixture did not pass.'
}
finally{
    $cleanupFailures=[Collections.Generic.List[string]]::new()
    try{Remove-NativeWorker $workerContext}catch{$cleanupFailures.Add('worker')}
    try{
        Remove-OwnedContainers
        foreach($record in $records){$lookup=if($record.Id){$record.Id}else{$record.Name};$gone=Invoke-Docker @('inspect',$lookup) -AllowFailure;Assert-True ($gone.ExitCode -ne 0 -and ($gone.Stderr+$gone.Stdout) -match '(?i)no such (object|container)') 'Provider cleanup unverified.'}
    }catch{$cleanupFailures.Add('provider')}
    if($public){$public.Key.Dispose()}
    $root=$share=$signerToken=$readonlyToken=$expiredToken=$revokedToken=$null
    $script:credentialCanaries.Clear();$material=$wrongMaterial=$null
    try{
        Remove-NativePublicPayload $repoRoot $publicRoot
    }catch{$cleanupFailures.Add('public-payload')}
    if($cleanupFailures.Count -ne 0){throw ('Native fixture cleanup unverified: '+($cleanupFailures -join ','))}
}
if($proof){$proof.cleanupVerified=$true;$proof|ConvertTo-Json -Compress}
