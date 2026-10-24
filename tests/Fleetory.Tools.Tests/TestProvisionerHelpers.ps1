param(
    [Parameter(Mandatory)][string] $Source,
    [Parameter(Mandatory)][string[]] $Names
)

$syntaxErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(
    $Source, [ref] $null, [ref] $syntaxErrors)
if ($syntaxErrors.Count -ne 0) {
    throw "Provisioner has a syntax error: $Source"
}
foreach ($name in $Names) {
    $definition = $ast.Find({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -eq $name
    }, $true)
    if ($null -eq $definition) { throw "Missing provisioner function $name." }
    . ([scriptblock]::Create($definition.Extent.Text))
}

function Remove-FleetoryTestArtifacts([string] $Work, [string] $RepoRoot) {
    $target = [IO.Path]::GetFullPath($Work)
    $artifactsRoot = [IO.Path]::GetFullPath(
        (Join-Path $RepoRoot 'artifacts')).TrimEnd([IO.Path]::DirectorySeparatorChar) +
        [IO.Path]::DirectorySeparatorChar
    $comparison = if ($env:OS -eq 'Windows_NT') {
        [StringComparison]::OrdinalIgnoreCase
    }
    else { [StringComparison]::Ordinal }
    if (-not $target.StartsWith($artifactsRoot, $comparison)) {
        throw 'Test cleanup path escaped the Fleetory artifacts directory.'
    }
    if (Test-Path -LiteralPath $target) {
        Remove-Item -LiteralPath $target -Recurse -Force
    }
}

function ConvertTo-P256PublicKeyMaterial([Security.Cryptography.ECDsa] $Key) {
    $parameters = $Key.ExportParameters($false)
    $point = New-Object byte[] 65
    $point[0] = 4
    [Buffer]::BlockCopy($parameters.Q.X, 0, $point, 1, 32)
    [Buffer]::BlockCopy($parameters.Q.Y, 0, $point, 33, 32)
    $prefix = [byte[]](0x30,0x59,0x30,0x13,0x06,0x07,0x2A,0x86,0x48,
        0xCE,0x3D,0x02,0x01,0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,
        0x01,0x07,0x03,0x42,0x00)
    $der = New-Object byte[] ($prefix.Length + $point.Length)
    [Buffer]::BlockCopy($prefix, 0, $der, 0, $prefix.Length)
    [Buffer]::BlockCopy($point, 0, $der, $prefix.Length, $point.Length)
    $base64 = [Convert]::ToBase64String($der)
    $lines = for ($offset = 0; $offset -lt $base64.Length; $offset += 64) {
        $length = [Math]::Min(64, $base64.Length - $offset)
        $base64.Substring($offset, $length)
    }
    return [pscustomobject]@{
        Pem = "-----BEGIN PUBLIC KEY-----`r`n$($lines -join "`r`n")`r`n-----END PUBLIC KEY-----`r`n"
        Point = $point
    }
}

function ConvertTo-DerEcdsaSignature([byte[]] $P1363) {
    if ($null -eq $P1363 -or $P1363.Length -ne 64) {
        throw 'The test ECDSA signature must contain two 32-byte components.'
    }
    $components = @()
    foreach ($offset in @(0, 32)) {
        $start = $offset
        while ($start -lt ($offset + 31) -and $P1363[$start] -eq 0) { $start++ }
        $componentLength = $offset + 32 - $start
        $leadingZero = if (($P1363[$start] -band 0x80) -ne 0) { 1 } else { 0 }
        $component = New-Object byte[] ($componentLength + $leadingZero + 2)
        $component[0] = 0x02
        $component[1] = $componentLength + $leadingZero
        if ($leadingZero -eq 1) { $component[2] = 0 }
        [Buffer]::BlockCopy($P1363, $start, $component, 2 + $leadingZero, $componentLength)
        $components += ,$component
    }
    $sequenceLength = $components[0].Length + $components[1].Length
    $der = New-Object byte[] ($sequenceLength + 2)
    $der[0] = 0x30
    $der[1] = $sequenceLength
    [Buffer]::BlockCopy($components[0], 0, $der, 2, $components[0].Length)
    [Buffer]::BlockCopy($components[1], 0, $der, 2 + $components[0].Length,
        $components[1].Length)
    return $der
}
