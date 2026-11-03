#requires -Version 7.3
# Synthetic fixture helpers only. Callers provide an already-owned restored target.
function Assert-RecoveryCredentialTarget([string] $Id, [string] $Role) {
    if ($Role -cne 'restore' -or -not $script:forceRestoreClaimed) {
        throw 'Credential recovery requires the already-restored fixture target.'
    }
    $null = Assert-Owned $Id 'restore'
}

function Restart-RecoveryCredentialTarget([string] $Id, [string] $Cluster, [string] $Share, [switch] $RecoveryWindow) {
    Assert-RecoveryCredentialTarget $Id 'restore'
    Assert-True ((Get-Status $Id).cluster_id -ceq $Cluster) 'Credential recovery target cluster changed.'
    $null = Invoke-Docker @('exec',$Id,'/bin/busybox','killall','bao')
    Start-Sleep -Milliseconds 300
    Start-Bao $Id 'restore' -RecoveryWindow:$RecoveryWindow
    $null = Invoke-Unseal $Id $Share
    Assert-True ((Wait-Active $Id).cluster_id -ceq $Cluster) 'Credential recovery restart changed the restored cluster.'
}

function Assert-RecoveryEndpointDisabled([string] $Id) {
    $result = Invoke-Bao $Id @('write','-format=json','-force','sys/generate-root/attempt') -AllowFailure
    Assert-True ($result.ExitCode -ne 0 -and ($result.Stdout+$result.Stderr) -match '(?i)Code:\s*405') 'Legacy root recovery endpoint did not explicitly deny the closed window.'
}

function Get-RecoveryGenerationJson([string] $Id, [string] $Path, [hashtable] $Body) {
    $bytes = [Text.Encoding]::UTF8.GetBytes(($Body | ConvertTo-Json -Compress))
    $result = Invoke-Bao $Id @('write','-format=json',$Path,'-') -Body $bytes
    $json = Get-Json $result.Stdout
    if ($json.ContainsKey('data') -and $null -ne $json.data) { return $json.data }
    return $json
}

function Get-SyntheticRecoveredRoot([string] $Id, [string] $Share) {
    $script:credentialRecoveryStage = 'root-init'
    Assert-RecoveryCredentialTarget $Id 'restore'
    $init = Get-RecoveryGenerationJson $Id 'sys/generate-root/attempt' @{}
    $otp = [string]$init.otp
    Assert-True ($init.started -eq $true -and $init.complete -eq $false -and $init.required -eq 1 -and
        $init.progress -eq 0 -and $otp -cmatch '^[A-Za-z0-9]{20,128}$' -and $otp.Length -eq $init.otp_length) 'Synthetic root generation initialization was invalid.'
    $script:credentialCanaries.Add($otp)
    $script:credentialRecoveryStage = 'root-update'
    $finished = Get-RecoveryGenerationJson $Id 'sys/generate-root/update' @{key=$Share;nonce=[string]$init.nonce}
    Assert-True ($finished.complete -eq $true -and $finished.progress -eq 1 -and $finished.nonce -ceq $init.nonce) 'Synthetic root generation did not complete the expected one-share attempt.'
    $script:credentialRecoveryStage = 'root-decode'
    $encoded = [string]$finished.encoded_token
    Assert-True ($encoded -cmatch '^[A-Za-z0-9+/]{20,256}$') 'Synthetic root encoding was invalid.'
    while (($encoded.Length % 4) -ne 0) { $encoded += '=' }
    $bytes = [Convert]::FromBase64String($encoded)
    $mask = [Text.Encoding]::UTF8.GetBytes($otp)
    Assert-True ($bytes.Length -eq $mask.Length) 'Synthetic root encoding lengths differ.'
    for ($index=0; $index -lt $bytes.Length; $index++) { $bytes[$index] = $bytes[$index] -bxor $mask[$index] }
    $root = [Text.Encoding]::UTF8.GetString($bytes)
    Assert-True ($root -cmatch '^[A-Za-z0-9._-]{20,128}$') 'Decoded synthetic root format was invalid.'
    $script:credentialCanaries.Add($root)
    return $root
}

function Assert-TargetCredentialLease($Lease, [DateTimeOffset] $NotBefore) {
    $expiry = [DateTimeOffset]::Parse([string]$Lease.expire_time)
    $issued = [DateTimeOffset]::Parse([string]$Lease.issue_time)
    $script:credentialLeaseDiagnostic = [ordered]@{orphan=$Lease.orphan;renewable=$Lease.renewable;
        explicitMaxTtl=$Lease.explicit_max_ttl;creationTtl=$Lease.creation_ttl;ttl=$Lease.ttl;
        expectedPolicy=(@($Lease.policies) -join '|') -ceq 'fixture-recovered-signer';
        lifetimeTicks=($expiry-$issued).Ticks;creationAfterRequest=[int64]$Lease.creation_time -ge $NotBefore.ToUnixTimeSeconds()}
    Assert-True ($Lease.orphan -eq $true -and $Lease.renewable -eq $false -and
        $Lease.explicit_max_ttl -eq 300 -and $Lease.creation_ttl -eq 300 -and
        $Lease.ttl -gt 0 -and $Lease.ttl -le 300 -and [int64]$Lease.creation_time -ge $NotBefore.ToUnixTimeSeconds() -and
        ($expiry-$issued).Ticks -gt 0 -and ($expiry-$issued).Ticks -le [TimeSpan]::FromSeconds(300).Ticks -and
        $expiry -gt [DateTimeOffset]::UtcNow -and
        (@($Lease.policies) -join '|') -ceq 'fixture-recovered-signer') 'Recovered target credential identity or bounded lease was invalid.'
}

function Test-RestoredTargetCredential([string] $Id, [string] $SourceId, [string] $Cluster, [string] $Share,
    [string] $ExpiredToken, $ExpiredLease, $Public, [string] $Challenge) {
    $script:credentialRecoveryStage = 'default-window-guard'
    Assert-RecoveryCredentialTarget $Id 'restore'
    Assert-RecoveryEndpointDisabled $Id
    Assert-RecoveryEndpointDisabled $SourceId
    $deadline = [DateTimeOffset]::Parse([string]$ExpiredLease.expire_time).AddSeconds(1)
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
        $root = Get-SyntheticRecoveredRoot $Id $Share
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
