# UTF-8 with BOM keeps this PowerShell test usable on Windows PowerShell 5.1.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$source = Join-Path $repoRoot 'eng/verify-immudb-restore.ps1'
. (Join-Path $PSScriptRoot 'TestProvisionerHelpers.ps1') -Source $source `
    -Names @(
        'ConvertTo-ImmudbRestoreEventKey', 'ConvertFrom-ImmudbRestoreBase64Strict',
        'Get-ImmudbAuditReadback',
        'Test-ImmudbRestoredEvent', 'Invoke-ImmudbRestoreAcceptance')
. (Join-Path $PSScriptRoot 'TestProvisionerHelpers.ps1') `
    -Source (Join-Path $repoRoot 'eng/verify-immudb-state.ps1') `
    -Names @('Get-ImmudbSha256', 'ConvertTo-ImmudbUpperHex')

$work = Join-Path $repoRoot ('artifacts/immudb-restore-test-' +
    [Guid]::NewGuid().ToString('N'))
$keyPath = Join-Path $work 'immudb-state-public.pem'
$anchor = Join-Path $work 'receipts.ndjson'
$eventId = [Guid]::Parse('9b6c4eaf-7152-4ed6-95fc-7f5e4d3ad1b2')
$valueBytes = [byte[]](1..16)
$valueHash = ConvertTo-ImmudbUpperHex (Get-ImmudbSha256 $valueBytes)
$knownKey = ConvertTo-ImmudbRestoreEventKey $eventId

function Assert-Throws([scriptblock] $Action, [string] $Message) {
    $thrown = $false
    try { & $Action } catch { $thrown = $true }
    if (-not $thrown) { throw $Message }
}

try {
    New-Item -ItemType Directory -Path $work -Force | Out-Null
    [IO.File]::WriteAllText($keyPath, 'unused in mocked acceptance')
    $realReadback = (Get-Command Get-ImmudbAuditReadback -CommandType Function).ScriptBlock
    $script:seenToken = $null
    $script:seenStateArgs = $null
    function Invoke-ImmudbStateVerification(
        [uri] $Origin,
        [string] $PublicKeyPath,
        [string] $AnchorPath,
        [string] $ExpectedDatabase,
        [string] $Token) {
        $script:seenStateArgs = @($Origin.AbsoluteUri, $PublicKeyPath,
            $AnchorPath, $ExpectedDatabase)
        $script:seenToken = $Token
        return [pscustomobject]@{ txId = 77 }
    }
    function Get-ImmudbAuditReadback([uri] $Origin, [string] $Token, [string] $Key) {
        $script:seenToken = $Token
        if ($Key -cne $knownKey) { throw 'The test requested an unexpected audit key.' }
        return [pscustomobject]@{
            key = $Key
            value = [Convert]::ToBase64String($valueBytes)
            revision = '1'
        }
    }

    $result = Invoke-ImmudbRestoreAcceptance ([uri]'https://restored.example/') `
        $keyPath $anchor 'defaultdb' $eventId 1 $valueHash 'read-only-restore-token'
    if ($result.schema -ne 'fleetory.immudb-restore-acceptance.v1' -or
        $result.receiptTxId -ne 77 -or $result.knownEventId -ne $eventId.ToString('N') -or
        $result.revision -ne 1 -or $result.valueSha256 -ne $valueHash) {
        throw 'Restore acceptance result normalization failed.'
    }
    if ($script:seenToken -ne 'read-only-restore-token' -or
        $script:seenStateArgs[3] -cne 'defaultdb') {
        throw 'Restore acceptance did not use the read-only token and database.'
    }

    $wrongRevision = [pscustomobject]@{
        key = $knownKey
        value = [Convert]::ToBase64String($valueBytes)
        revision = '2'
    }
    Assert-Throws { Test-ImmudbRestoredEvent $wrongRevision $eventId 1 $valueHash } `
        'A restored event at the wrong revision was accepted.'
    $wrongValue = [pscustomobject]@{
        key = $knownKey
        value = [Convert]::ToBase64String([byte[]](2..17))
        revision = '1'
    }
    Assert-Throws { Test-ImmudbRestoredEvent $wrongValue $eventId 1 $valueHash } `
        'A restored event with a changed value was accepted.'
    $wrongKey = [pscustomobject]@{
        key = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('other'))
        value = [Convert]::ToBase64String($valueBytes)
        revision = '1'
    }
    Assert-Throws { Test-ImmudbRestoredEvent $wrongKey $eventId 1 $valueHash } `
        'A restored event for another EventId was accepted.'
    Remove-Item Function:\Get-ImmudbAuditReadback -Force
    Set-Item Function:\Get-ImmudbAuditReadback $realReadback
    Assert-Throws {
        Get-ImmudbAuditReadback ([uri]'http://restored.example/') 'token' $knownKey
    } 'An insecure restore endpoint was accepted.'
    Assert-Throws {
        Test-ImmudbRestoredEvent $wrongRevision $eventId 0 $valueHash
    } 'An invalid expected revision was accepted.'

    Write-Host 'IMMUDB RESTORE TESTS PASS: read-only token separation, known EventId, revision, hash and fail-closed validation.'
}
finally {
    Remove-FleetoryTestArtifacts $work $repoRoot
}
