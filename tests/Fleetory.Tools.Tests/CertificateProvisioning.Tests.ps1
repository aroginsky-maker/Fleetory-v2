$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$source = Join-Path $repoRoot 'eng/provision-security-lab-certificates.ps1'
$syntaxErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(
    $source, [ref] $null, [ref] $syntaxErrors)
if ($syntaxErrors.Count -ne 0) { throw 'Certificate provisioner has a syntax error.' }
foreach ($name in @('Protect-LabCertificateDirectory', 'Issue-LabCertificate')) {
    $definition = $ast.Find({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -eq $name
    }, $true)
    if ($null -eq $definition) { throw "Missing provisioner function $name." }
    . ([scriptblock]::Create($definition.Extent.Text))
}

$work = Join-Path $repoRoot ('artifacts/certificate-provisioning-test-' +
    [Guid]::NewGuid().ToString('N'))
$certDirectory = Join-Path $work 'certs'
$envPath = Join-Path $work 'unused.env'
$composePath = Join-Path $work 'unused.yaml'
$script:failKeyCopy = $false
$script:nextCertificate = ''
$script:nextPrivateKey = ''

function docker {
    $toolArguments = @($args)
    $global:LASTEXITCODE = 0
    if ($toolArguments[0] -eq 'compose') { return }
    if ($toolArguments[0] -eq 'exec') { return }
    if ($toolArguments[0] -ne 'cp') { throw 'Unexpected Docker call.' }
    if ($toolArguments[1].EndsWith('.key')) {
        if ($script:failKeyCopy) { $global:LASTEXITCODE = 1; return }
        Copy-Item -LiteralPath $script:nextPrivateKey -Destination $toolArguments[2]
    }
    else {
        Copy-Item -LiteralPath $script:nextCertificate -Destination $toolArguments[2]
    }
}

function New-TestPair([string] $Stem) {
    $key = [Security.Cryptography.ECDsa]::Create(
        [Security.Cryptography.ECCurve]::CreateFromFriendlyName('nistP256'))
    try {
        $request = [Security.Cryptography.X509Certificates.CertificateRequest]::new(
            "CN=$Stem", $key, [Security.Cryptography.HashAlgorithmName]::SHA256)
        $certificate = $request.CreateSelfSigned(
            [DateTimeOffset]::UtcNow.AddMinutes(-1),
            [DateTimeOffset]::UtcNow.AddHours(1))
        try {
            [IO.File]::WriteAllText((Join-Path $work "$Stem.crt"),
                $certificate.ExportCertificatePem())
            [IO.File]::WriteAllText((Join-Path $work "$Stem.key"),
                $key.ExportECPrivateKeyPem())
        }
        finally { $certificate.Dispose() }
    }
    finally { $key.Dispose() }
}

try {
    New-Item -ItemType Directory -Path $certDirectory -Force | Out-Null
    Protect-LabCertificateDirectory $certDirectory
    New-TestPair 'old'
    New-TestPair 'new'
    $activeCrt = Join-Path $certDirectory 'agent-client.crt'
    $activeKey = Join-Path $certDirectory 'agent-client.key'
    Copy-Item -LiteralPath (Join-Path $work 'old.crt') -Destination $activeCrt
    Copy-Item -LiteralPath (Join-Path $work 'old.key') -Destination $activeKey
    Protect-LabCertificateDirectory $certDirectory

    $script:nextCertificate = Join-Path $work 'new.crt'
    $script:nextPrivateKey = Join-Path $work 'new.key'
    Issue-LabCertificate -Service 'agent-ca' -Provisioner 'test' -Subject 'test' `
        -San @() -Stem 'agent-client'

    $oldCertificate = [IO.File]::ReadAllText((Join-Path $work 'old.crt'))
    $oldKey = [IO.File]::ReadAllText((Join-Path $work 'old.key'))
    $newCertificate = [IO.File]::ReadAllText((Join-Path $work 'new.crt'))
    $newKey = [IO.File]::ReadAllText((Join-Path $work 'new.key'))
    $history = @(Get-ChildItem -LiteralPath (Join-Path $certDirectory 'history') -Directory)
    if ($history.Count -ne 1 -or
        [IO.File]::ReadAllText((Join-Path $history[0].FullName 'agent-client.crt')) -ne
            $oldCertificate -or
        [IO.File]::ReadAllText((Join-Path $history[0].FullName 'agent-client.key')) -ne
            $oldKey -or
        [IO.File]::ReadAllText($activeCrt) -ne $newCertificate -or
        [IO.File]::ReadAllText($activeKey) -ne $newKey) {
        throw 'Renewal did not preserve the old pair and activate the new pair.'
    }

    $script:failKeyCopy = $true
    $failedAsExpected = $false
    try {
        Issue-LabCertificate -Service 'agent-ca' -Provisioner 'test' -Subject 'test' `
            -San @() -Stem 'agent-client'
    }
    catch {
        $failedAsExpected = $_.Exception.Message -like 'Key copy failed*'
    }
    if (-not $failedAsExpected -or
        [IO.File]::ReadAllText($activeCrt) -ne $newCertificate -or
        [IO.File]::ReadAllText($activeKey) -ne $newKey -or
        @(Get-ChildItem -LiteralPath (Join-Path $certDirectory 'history') -Directory).Count -ne 1) {
        throw 'Failed issuance changed the active certificate pair.'
    }

    $script:failKeyCopy = $false
    $script:nextCertificate = Join-Path $work 'old.crt'
    $mismatchRejected = $false
    try {
        Issue-LabCertificate -Service 'agent-ca' -Provisioner 'test' -Subject 'test' `
            -San @() -Stem 'agent-client'
    }
    catch { $mismatchRejected = $true }
    if (-not $mismatchRejected -or
        [IO.File]::ReadAllText($activeCrt) -ne $newCertificate -or
        [IO.File]::ReadAllText($activeKey) -ne $newKey -or
        @(Get-ChildItem -LiteralPath (Join-Path $certDirectory 'history') -Directory).Count -ne 1) {
        throw 'Mismatched certificate/key pair changed the active files.'
    }
    Write-Host 'CERTIFICATE PROVISIONING TESTS PASS: rotation archive, failed-copy rollback and mismatched-key rejection.'
}
finally {
    $absoluteWork = [IO.Path]::GetFullPath($work)
    $absoluteArtifacts = [IO.Path]::GetFullPath((Join-Path $repoRoot 'artifacts')) +
        [IO.Path]::DirectorySeparatorChar
    if (-not $absoluteWork.StartsWith($absoluteArtifacts,
        [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Unsafe certificate test cleanup path.'
    }
    if (Test-Path -LiteralPath $absoluteWork) {
        Remove-Item -LiteralPath $absoluteWork -Recurse -Force
    }
}
