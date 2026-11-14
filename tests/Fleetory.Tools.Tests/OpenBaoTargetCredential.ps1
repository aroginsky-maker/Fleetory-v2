#requires -Version 7.3
. (Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'eng/pilot/ProviderRecoveryCredential.ps1')
function Test-RestoredTargetCredential([string] $Id, [string] $SourceId, [string] $Cluster, [string] $Share,
    [string] $ExpiredToken, $ExpiredLease, $Public, [string] $Challenge) {
    $script:credentialRecoveryStage = 'default-window-guard'
    Assert-RecoveryCredentialTarget $Id 'restore'
    Assert-RecoveryEndpointDisabled $Id
    Assert-RecoveryEndpointDisabled $SourceId
    $deadline = (ConvertTo-ProviderTimestamp $ExpiredLease.expire_time).AddSeconds(1)
    Assert-True ($deadline -le [DateTimeOffset]::UtcNow.AddSeconds(30)) 'Short captured credential expiry is outside the fixture wait bound.'
    while ([DateTimeOffset]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 200 }
    $script:credentialRecoveryStage = 'expired-token-denials'
    Assert-Forbidden $Id $ExpiredToken @('read','transit/keys/fleetory-recovery-fixture') 'Expired captured signer read'
    Assert-Forbidden $Id $ExpiredToken @('write','-force','auth/token/renew-self') 'Expired captured signer renewal'
    $root = $token = $null
    $rootRevoked = $tokenRevoked = $false
    $publicAfter = $null
    try {
        $script:credentialRecoveryStage = 'open-target-window'
        Restart-RecoveryCredentialTarget $Id $Cluster $Share -RecoveryWindow
        $root = Get-RecoveredTargetRoot $Id $Share
        Assert-RecoveryEndpointDisabled $SourceId
        $script:credentialRecoveryStage = 'create-restricted-target-token'
        $policy = "path `"transit/keys/fleetory-recovery-fixture`" { capabilities = [`"read`"] }`npath `"transit/sign/fleetory-recovery-fixture/sha2-256`" { capabilities = [`"update`"] }`npath `"auth/token/lookup-self`" { capabilities = [`"read`"] }`npath `"auth/token/revoke-self`" { capabilities = [`"update`"] }"
        $null = Invoke-Bao $Id @('policy','write','fixture-recovered-signer','-') $root ([Text.Encoding]::UTF8.GetBytes($policy))
        $createdAfter = [DateTimeOffset]::UtcNow
        $created = Invoke-AuthenticatedJson $Id $root @('write','-format=json','auth/token/create-orphan',
            'policies=fixture-recovered-signer','no_default_policy=true','ttl=300s','explicit_max_ttl=300s','renewable=false')
        $token = [string]$created.auth.client_token
        Assert-True ($token.Length -gt 20 -and $token -cne $ExpiredToken) 'Fresh target credential was missing or reused the expired credential.'
        $script:credentialCanaries.Add($token)
        $script:credentialRecoveryStage = 'target-lease-before'
        $leaseBefore = Get-Data $Id $token @('read','-format=json','auth/token/lookup-self')
        Assert-TargetCredentialLease $leaseBefore $createdAfter
        $null = Invoke-Bao $Id @('token','revoke','-self') $root
        $rootRevoked = $true
        Assert-Forbidden $Id $root @('read','transit/keys/fleetory-recovery-fixture') 'Recovered target root after revocation'
        $script:credentialRecoveryStage = 'close-target-window'
        Restart-RecoveryCredentialTarget $Id $Cluster $Share
        Assert-RecoveryEndpointDisabled $Id
        Assert-RecoveryEndpointDisabled $SourceId
        $leaseAfter = Get-Data $Id $token @('read','-format=json','auth/token/lookup-self')
        $script:credentialRecoveryStage = 'target-lease-after'
        Assert-TargetCredentialLease $leaseAfter $createdAfter
        Assert-True ($leaseBefore.id -ceq $leaseAfter.id -and $leaseBefore.accessor -ceq $leaseAfter.accessor -and
            $leaseBefore.creation_time -eq $leaseAfter.creation_time -and $leaseBefore.expire_time -ceq $leaseAfter.expire_time -and
            $leaseAfter.ttl -le $leaseBefore.ttl) 'Closing the recovery window changed the target token identity or extended its expiry.'
        $script:credentialRecoveryStage = 'management-denials'
        Assert-Forbidden $Id $root @('read','transit/keys/fleetory-recovery-fixture') 'Revoked target root after restart'
        Assert-Forbidden $Id $token @('write','transit/keys/forbidden-fixture','type=ecdsa-p256') 'Recovered signer key management'
        Assert-Forbidden $Id $token @('write','-force','auth/token/create-orphan') 'Recovered signer token issuance'
        Assert-Forbidden $Id $token @('write','sys/policies/acl/forbidden-fixture','policy=') 'Recovered signer policy management'
        Assert-Forbidden $Id $token @('write','-force','auth/token/renew-self') 'Nonrenewable recovered signer renewal'
        $script:credentialRecoveryStage = 'key-and-signature'
        $publicAfter = Get-TransitPublic $Id $token
        Assert-True ([Security.Cryptography.CryptographicOperations]::FixedTimeEquals($publicAfter.Spki,$Public.Spki) -and
            $publicAfter.Version -eq $Public.Version -and $publicAfter.Flags -ceq $Public.Flags) 'Fresh credential changed the retained signing key.'
        Assert-Signature $Id $token $publicAfter ($Challenge+'-fresh-target-credential-noncommand')
        $script:credentialRecoveryStage = 'source-denials-and-revocation'
        Assert-Forbidden $SourceId $token @('read','transit/keys/fleetory-recovery-fixture') 'Target-only credential on synthetic source'
        Assert-Forbidden $SourceId $root @('read','transit/keys/fleetory-recovery-fixture') 'Recovered target root on synthetic source'
        $null = Invoke-Bao $Id @('token','revoke','-self') $token
        $tokenRevoked = $true
        Assert-Forbidden $Id $token @('read','transit/keys/fleetory-recovery-fixture') 'Revoked recovered signer'
        return [pscustomobject]@{expiredCapturedCredentialDenied403=$true;expiredRenewalDenied403=$true;
            targetRootRevokedBeforeProbe=$true;legacyRootWindowClosed405=$true;sourceRootWindowStayedClosed405=$true;
            freshOrphanTokenMaxTtlSeconds=300;freshTokenIdentityExpiryPreservedAcrossRestart=$true;
            managementDenials403=4;targetCredentialsDeniedOnSyntheticSource403=2;freshNonCommandSignatureVerified=$true;
            retainedSigningKeyPreserved=$true;freshProbeTokenRevoked403=$true;originalProviderMaterialUsed=$false}
    }
    finally {
        if ($root -and -not $rootRevoked) { $null = Invoke-Bao $Id @('token','revoke','-self') $root -AllowFailure }
        if ($token -and -not $tokenRevoked) { $null = Invoke-Bao $Id @('token','revoke','-self') $token -AllowFailure }
        if ($null -ne $publicAfter) { $publicAfter.Key.Dispose() }
        $root=$null; $token=$null
    }
}
