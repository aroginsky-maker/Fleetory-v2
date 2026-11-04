#requires -Version 7.3
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string] $PlanPath,
    [Parameter(Mandatory)][string] $PlanSha256,
    [Parameter(Mandatory)][string] $GrantPath
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'ProviderRecoveryController.ps1')
$planStream=$grantStream=$pinStream=$null
$codeStreams=[Collections.Generic.List[object]]::new()
$exitCode=1
try {
    # Real material is supported only from this Windows operator; Linux exercises use generated fixtures.
    Assert-ProviderCondition $IsWindows 'operator-platform'
    Assert-ProviderCondition ($PlanSha256 -cmatch '^[0-9a-f]{64}$') 'plan-pin'
    $stateDirectory=Split-Path ([IO.Path]::GetFullPath($PlanPath)) -Parent
    $repoDirectory=Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    Assert-ProviderCondition (-not $stateDirectory.StartsWith($repoDirectory,[StringComparison]::OrdinalIgnoreCase)) 'operator-outside-git'
    foreach($path in @($stateDirectory,$PlanPath,$GrantPath)){Assert-PrivateOperatorAcl $path}
    $planLength=(Get-Item -LiteralPath $PlanPath).Length
    $planStream=Open-ProviderInput $PlanPath $planLength 65536
    $planBytes=[byte[]]::new([int]$planLength);$planStream.ReadExactly($planBytes)
    Assert-ProviderCondition ([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($planBytes)).ToLowerInvariant() -ceq $PlanSha256) 'plan-pin'
    $plan=[Text.UTF8Encoding]::new($false,$true).GetString($planBytes)|ConvertFrom-Json -AsHashtable -Depth 16
    $grantLength=(Get-Item -LiteralPath $GrantPath).Length
    $grantStream=Open-ProviderInput $GrantPath $grantLength 8192
    $grantBytes=[byte[]]::new([int]$grantLength);$grantStream.ReadExactly($grantBytes)
    $grant=[Text.UTF8Encoding]::new($false,$true).GetString($grantBytes)|ConvertFrom-Json -AsHashtable -Depth 8
    Assert-ProviderPlan $plan $grant $PlanSha256 'retained-provider' ([DateTimeOffset]::UtcNow)
    foreach($name in (Get-ProviderCodePins).Keys){
        $codePath=Join-Path $PSScriptRoot $name
        $codeStreams.Add((Open-ProviderInput $codePath (Get-Item -LiteralPath $codePath).Length 1048576))
    }
    # Recheck and reload after acquiring read locks; another local writer cannot alter runtime modules.
    Assert-ProviderPlan $plan $grant $PlanSha256 'retained-provider' ([DateTimeOffset]::UtcNow)
    . (Join-Path $PSScriptRoot 'ProviderRecoveryController.ps1')
    Assert-ProviderCondition ($grant.evidenceRef.StartsWith('user-explicit:',[StringComparison]::Ordinal)) 'explicit-human-grant-reference'
    Assert-PrivateOperatorAcl $plan.ssh.KnownHostsFile
    # Windows sharing denies write/delete of this exact host ledger throughout every SSH request.
    $pinLength=(Get-Item -LiteralPath $plan.ssh.KnownHostsFile).Length
    $pinStream=Open-ProviderInput $plan.ssh.KnownHostsFile $pinLength 1024
    $proof=Invoke-ProviderRecoveryController $plan $grant $PlanSha256 $stateDirectory $null $null 'retained-provider'
    $proof|ConvertTo-Json -Depth 8 -Compress
    if($proof.verified){$exitCode=0}
}
catch { [Console]::Error.WriteLine('Provider recovery refused or failed before a verified result. No credential or raw response is emitted.') }
finally { foreach($stream in (@($pinStream,$grantStream,$planStream)+$codeStreams.ToArray())){if($null -ne $stream){$stream.Dispose()}} }
exit $exitCode
