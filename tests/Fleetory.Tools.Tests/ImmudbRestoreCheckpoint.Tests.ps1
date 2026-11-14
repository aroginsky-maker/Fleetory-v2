# Real receipt cryptography and local anchor writes; only remote reads are simulated.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$stateSource = Join-Path $repoRoot 'eng/verify-immudb-state.ps1'
$restoreSource = Join-Path $repoRoot 'eng/verify-immudb-restore.ps1'
. (Join-Path $PSScriptRoot 'TestProvisionerHelpers.ps1') -Source $stateSource -Names @(
    'ConvertFrom-Base64Strict', 'Get-ImmudbSha256', 'ConvertTo-ImmudbUpperHex',
    'Test-ImmudbAbsolutePath', 'Get-ImmudbState', 'New-ImmudbStateSigningPayload',
    'ConvertTo-ImmudbPublicKeyPoint', 'Read-ImmudbDerInteger', 'ConvertFrom-ImmudbDerSignature',
    'Invoke-ImmudbSignatureVerification', 'Get-PinnedImmudbPublicKeyBytes', 'New-ImmudbStateReceipt',
    'Get-ExistingImmudbReceipts', 'Get-ImmudbReceiptCanonicalJson', 'Get-ImmudbReceiptSha256',
    'Test-ImmudbReceiptChain', 'Write-ImmudbStateReceipt', 'Get-VerifiedImmudbStateReceipt',
    'Invoke-ImmudbStateVerification')
. (Join-Path $repoRoot 'eng/immudb-receipt-verification.ps1')
. (Join-Path $PSScriptRoot 'TestProvisionerHelpers.ps1') -Source $restoreSource -Names @(
    'ConvertTo-ImmudbRestoreEventKey', 'ConvertFrom-ImmudbRestoreBase64Strict',
    'Get-ImmudbRestoreDatabaseToken', 'Get-ImmudbAuditReadback',
    'Test-ImmudbRestoredEvent', 'Get-ImmudbRestorePoint', 'Invoke-ImmudbRestoreAcceptance')
$work = Join-Path $repoRoot ('artifacts/restore-checkpoint-test-' + [Guid]::NewGuid().ToString('N'))
$key = $null
$publicKey = Join-Path $work 'public.pem'
$anchor = Join-Path $work 'accepted.ndjson'
$checkpoint = Join-Path $work 'approved.json'
$checkpointAnchor = Join-Path $work 'approved.ndjson'
$approvedDigest = ''
$eventId = [Guid]::Parse('9b6c4eaf-7152-4ed6-95fc-7f5e4d3ad1b2')
$script:value = [byte[]](1..16)
$script:badEvent = $true
$script:states = @()
$script:stateReads = 0
$script:databaseCalls = 0
$script:httpReads = 0
$script:eventRevision = '1'
$script:eventFailure = $false
$script:wrongEventKey = $false
$script:rejections = 0

function Get-ImmudbState([uri] $Origin, [string] $Token) {
    if ($Token -cne 'selected-read-token') { throw 'The state read used an unselected credential.' }
    $index = [Math]::Min($script:stateReads, $script:states.Count - 1)
    $script:stateReads++
    return $script:states[$index]
}
function Invoke-ImmudbRestoreGetJson([uri] $Origin, [string] $Token, [string] $Path, [string] $Failure) {
    $script:httpReads++
    if ($Path -ceq 'api/db/use/defaultdb') {
        if ($Token -cne 'read-only-token') { throw 'The database selection credential changed.' }
        $script:databaseCalls++
        return [pscustomobject]@{ token = 'selected-read-token' }
    }
    if (-not $Path.StartsWith('api/db/get/') -or $Token -cne 'selected-read-token') {
        throw 'The readback route or database-scoped credential changed.'
    }
    if ($script:eventFailure) { throw 'Simulated readback failure.' }
    $key = [uri]::UnescapeDataString($Path.Substring('api/db/get/'.Length))
    if ($script:wrongEventKey) { $key = 'wrong-key' }
    $bytes = if ($script:badEvent) { [byte[]](2..17) } else { $script:value }
    return [pscustomobject]@{ key = $key; value = [Convert]::ToBase64String($bytes); revision = $script:eventRevision }
}

function ConvertTo-RemoteState($Receipt) {
    return [pscustomobject]@{
        db = $Receipt.database; txId = $Receipt.txId; txHash = $Receipt.txHash
        signature = [pscustomobject]@{
            publicKey = [Convert]::ToBase64String($material.Point); signature = $Receipt.signature
        }
    }
}
function Reset-Scenario($Before, $After = $Before) {
    $script:states = @($Before, $After)
    $script:stateReads = 0; $script:databaseCalls = 0; $script:httpReads = 0
    $script:badEvent = $false; $script:eventRevision = '1'
    $script:eventFailure = $false; $script:wrongEventKey = $false
}
function Invoke-TestAcceptance([switch] $UseCheckpoint, [string] $Digest = $approvedDigest, [string] $Database = 'defaultdb') {
    $parameters = @{
        Origin = [uri]'https://restore.example/'; PublicKeyPath = $publicKey; AnchorPath = $anchor
        ExpectedDatabase = $Database; EventId = $eventId; ExpectedRevision = 1
        ExpectedValueSha256 = $valueHash; ReadOnlyToken = 'read-only-token'
    }
    if ($UseCheckpoint) {
        $parameters.CheckpointPath = $checkpoint
        $parameters.ExpectedCheckpointSha256 = $Digest
    }
    return Invoke-ImmudbRestoreAcceptance @parameters
}
function Assert-FailedAcceptance([scriptblock] $Action, [string] $Expected, [switch] $NoNetwork) {
    $before = if (Test-Path -LiteralPath $anchor) { (Get-FileHash $anchor -Algorithm SHA256).Hash } else { $null }
    try { & $Action | Out-Null; throw 'Restore was unexpectedly accepted.' } catch {
        if ($_.Exception.Message -notlike "*$Expected*") { throw }
    }
    $after = if (Test-Path -LiteralPath $anchor) { (Get-FileHash $anchor -Algorithm SHA256).Hash } else { $null }
    if ($before -cne $after) { throw 'Rejected restore mutated its acceptance anchor.' }
    if ($NoNetwork -and ($script:httpReads -ne 0 -or $script:stateReads -ne 0)) {
        throw 'An invalid local checkpoint caused a remote request.'
    }
    $script:rejections++
}

try {
    New-Item -ItemType Directory -Path $work -Force | Out-Null
    $key = [Security.Cryptography.ECDsa]::Create([Security.Cryptography.ECCurve]::CreateFromFriendlyName('nistP256'))
    $material = ConvertTo-P256PublicKeyMaterial $key
    [IO.File]::WriteAllText($publicKey, $material.Pem)
    $first = New-SignedReceipt $key $material.Point 76 ''
    $receipt = New-SignedReceipt $key $material.Point 77 $first.receiptSha256
    $newer = New-SignedReceipt $key $material.Point 78 $receipt.receiptSha256
    $state = ConvertTo-RemoteState $receipt
    $olderState = ConvertTo-RemoteState $first
    $newerState = ConvertTo-RemoteState $newer
    $valueHash = ConvertTo-ImmudbUpperHex (Get-ImmudbSha256 $script:value)
    Reset-Scenario $state
    $script:badEvent = $true
    Assert-FailedAcceptance { Invoke-TestAcceptance } 'value hash'
    if (Test-Path -LiteralPath $anchor) { throw 'A failed restore created an anchor.' }

    $lines = @($first, $receipt) | ForEach-Object { $_ | ConvertTo-Json -Compress -Depth 4 }
    [IO.File]::WriteAllText($checkpointAnchor, ($lines -join "`n") + "`n", [Text.UTF8Encoding]::new($false))
    $null = & (Join-Path $repoRoot 'eng/export-immudb-receipt-anchor.ps1') `
        -AnchorPath $checkpointAnchor -ExportPath $checkpoint
    $approvedDigest = (Get-FileHash $checkpoint -Algorithm SHA256).Hash
    [IO.File]::WriteAllText($anchor, $lines[0] + "`n", [Text.UTF8Encoding]::new($false))

    foreach ($failure in @('value', 'revision', 'key', 'network')) {
        Reset-Scenario $state
        switch ($failure) {
            'value' { $script:badEvent = $true; $expected = 'value hash' }
            'revision' { $script:eventRevision = '2'; $expected = 'unexpected revision' }
            'key' { $script:wrongEventKey = $true; $expected = 'known EventId' }
            'network' { $script:eventFailure = $true; $expected = 'Simulated readback failure' }
        }
        Assert-FailedAcceptance { Invoke-TestAcceptance -UseCheckpoint } $expected
    }
    foreach ($wrongState in @($olderState, $newerState,
        (ConvertTo-RemoteState (New-SignedReceipt $key $material.Point 77 '' -HashSeed 100)))) {
        Reset-Scenario $wrongState
        Assert-FailedAcceptance { Invoke-TestAcceptance -UseCheckpoint } 'approved restore point'
        if ($script:httpReads -ne 1) { throw 'A state mismatch reached event readback.' }
    }
    foreach ($changed in @($newerState,
        (ConvertTo-RemoteState (New-SignedReceipt $key $material.Point 77 '' -HashSeed 100)))) {
        Reset-Scenario $state $changed
        Assert-FailedAcceptance { Invoke-TestAcceptance -UseCheckpoint } 'changed during acceptance'
        if ($script:stateReads -ne 2) { throw 'Acceptance did not recheck the signed state.' }
    }
    $invalid = ConvertTo-RemoteState $receipt
    $der = [Convert]::FromBase64String($invalid.signature.signature)
    $der[-1] = $der[-1] -bxor 1
    $invalid.signature.signature = [Convert]::ToBase64String($der)
    Reset-Scenario $invalid
    Assert-FailedAcceptance { Invoke-TestAcceptance -UseCheckpoint } 'signature is invalid'
    Reset-Scenario $state
    Assert-FailedAcceptance { Invoke-TestAcceptance -UseCheckpoint -Digest ('B' * 64) } 'approved digest' -NoNetwork
    Reset-Scenario $state
    Assert-FailedAcceptance { Invoke-TestAcceptance -UseCheckpoint -Database 'otherdb' } 'different database' -NoNetwork
    Reset-Scenario $state
    Assert-FailedAcceptance { Invoke-TestAcceptance -UseCheckpoint -Digest '' } 'both its path' -NoNetwork
    Reset-Scenario $state
    Assert-FailedAcceptance {
        Invoke-ImmudbRestoreAcceptance ([uri]'https://restore.example/') $publicKey $anchor `
            'defaultdb' $eventId 1 $valueHash 'read-only-token' -ExpectedCheckpointSha256 $approvedDigest
    } 'both its path' -NoNetwork

    Reset-Scenario $state
    $accepted = Invoke-TestAcceptance -UseCheckpoint
    if ($accepted.checkpointVerified -ne $true -or $accepted.checkpointExportSha256 -cne $approvedDigest -or
        $accepted.receiptTxId -ne 77 -or $accepted.receiptTxHash -cne $receipt.txHash -or
        $script:databaseCalls -ne 1 -or $script:stateReads -ne 2) {
        throw 'The exact approved restore point was not accepted and recorded.'
    }
    $acceptedHash = (Get-FileHash $anchor -Algorithm SHA256).Hash
    Reset-Scenario $state
    [void](Invoke-TestAcceptance -UseCheckpoint)
    if ((Get-FileHash $anchor -Algorithm SHA256).Hash -cne $acceptedHash) {
        throw 'Repeated successful acceptance was not idempotent.'
    }
    if ((Get-FileHash $checkpoint -Algorithm SHA256).Hash -cne $approvedDigest) {
        throw 'Restore acceptance modified its approved checkpoint.'
    }
    Write-Host "IMMUDB RESTORE CHECKPOINT TESTS PASS: $script:rejections negative cases, exact restore point, stable signed state, scoped read token, deferred anchor and idempotence."
}
finally {
    if ($null -ne $key) { $key.Dispose() }
    Remove-FleetoryTestArtifacts $work $repoRoot
}
