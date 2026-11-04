#requires -Version 7.3
# Shared target-only credential primitives; the caller must enforce an owned restored target.
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

function Get-RecoveredTargetRoot([string] $Id, [string] $Share) {
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
