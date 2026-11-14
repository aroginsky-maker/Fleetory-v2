#requires -Version 7.3
# Shared target-only credential primitives; the caller must enforce an owned restored target.
function ConvertTo-ProviderTimestamp($Value) {
    if($Value -is [DateTimeOffset]){return $Value.ToUniversalTime()}
    if($Value -is [DateTime]){
        if($Value.Kind -eq [DateTimeKind]::Unspecified){throw 'Provider recovery timestamp lacks a timezone.'}
        return [DateTimeOffset]::new($Value).ToUniversalTime()
    }
    if($Value -isnot [string] -or $Value -cnotmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$'){
        throw 'Provider recovery timestamp is not explicit ISO-8601.'
    }
    return [DateTimeOffset]::Parse($Value,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::AdjustToUniversal)
}
function Assert-RecoveryCredentialTarget([string] $Id, [string] $Role) {
    if ($Role -cne 'restore' -or -not $script:forceRestoreClaimed) {
        throw 'Credential recovery requires the already-restored fixture target.'
    }
    $null = Assert-Owned $Id 'restore'
}

function Wait-RecoveryBaoExit([string] $Id,[int] $TimeoutMilliseconds=30000) {
    Assert-True ($TimeoutMilliseconds -ge 1 -and $TimeoutMilliseconds -le 30000) 'Invalid shutdown deadline.'
    $watch=[Diagnostics.Stopwatch]::StartNew()
    while($watch.ElapsedMilliseconds -lt $TimeoutMilliseconds){
        $remaining=$TimeoutMilliseconds-$watch.ElapsedMilliseconds
        $requestSeconds=[int][Math]::Max(1,[Math]::Ceiling($remaining/1000.0))
        $probe=Invoke-Docker @('exec',$Id,'/bin/busybox','pidof','bao') -TimeoutSeconds $requestSeconds -AllowFailure
        if($watch.ElapsedMilliseconds -ge $TimeoutMilliseconds){break}
        if($probe.ExitCode -eq 1 -and [string]::IsNullOrWhiteSpace($probe.Stdout) -and
            [string]::IsNullOrWhiteSpace($probe.Stderr)){return}
        Assert-True ($probe.ExitCode -eq 0 -and [string]::IsNullOrWhiteSpace($probe.Stderr) -and
            $probe.Stdout.Trim() -cmatch '^[1-9][0-9]*(?:[ \t]+[1-9][0-9]*)*$') 'OpenBao shutdown probe was invalid.'
        $remaining=$TimeoutMilliseconds-$watch.ElapsedMilliseconds
        if($remaining -gt 0){Start-Sleep -Milliseconds ([int][Math]::Min(100,$remaining))}
    }
    throw 'OpenBao did not stop within its shutdown deadline.'
}

function Restart-RecoveryCredentialTarget([string] $Id, [string] $Cluster, [string] $Share, [switch] $RecoveryWindow) {
    Assert-RecoveryCredentialTarget $Id 'restore'
    Assert-True ((Get-Status $Id).cluster_id -ceq $Cluster) 'Credential recovery target cluster changed.'
    $null = Invoke-Docker @('exec',$Id,'/bin/busybox','killall','bao')
    Wait-RecoveryBaoExit $Id
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
    $expiry = ConvertTo-ProviderTimestamp $Lease.expire_time
    $issued = ConvertTo-ProviderTimestamp $Lease.issue_time
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
