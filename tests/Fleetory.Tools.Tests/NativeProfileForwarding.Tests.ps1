#requires -Version 7.3
param([Parameter(Mandatory)][string]$Python)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'NativeServerPair.Tests.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Native profile source parse failed'}
$nodes=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.IfStatementAst] -and $n.Extent.Text.StartsWith('if($IsLinux -and -not $PrivateRuntimeChild',[StringComparison]::Ordinal)},$true))
if($nodes.Count -ne 1){throw 'Fixed Linux forwarding branch missing or duplicated'}
$source=$nodes[0].Clauses[0].Item2.Extent.Text
$body=$source.Substring(1,$source.Length-2).Replace("`r`n","`n")
# Preserve the literal source expression rather than expanding this test's directory.
$needle="(Join-Path "+'$PSScriptRoot'+" 'run_native_service_use_profile.py')"
if(-not $body.Contains($needle,[StringComparison]::Ordinal)){throw 'Fixed native wrapper target missing'}
$body=$body.Replace($needle,'$sink')
$sink=Join-Path ([IO.Path]::GetTempPath()) ('fleetory-native-argv-'+[guid]::NewGuid().ToString('N')+'.py')
$bytes=[Text.Encoding]::UTF8.GetBytes('import json,sys;print(json.dumps(sys.argv[1:]))')
$stream=[IO.FileStream]::new($sink,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
try{$stream.Write($bytes);$stream.Flush($true)}finally{$stream.Dispose()}
try{
    $cases=0
    foreach($Profile in @('v2-retained-service-use','v2-retained-service-use-loss','v2-retained-service-use-expiry')){
        foreach($FailurePoint in @('none','after-stores')){
            foreach($OriginalPurpose in @($false,$true)){
                $output=@(& ([scriptblock]::Create($body)))
                if($output.Count -ne 1){throw 'Unexpected native argv output'}
                $arguments=@($output[0]|ConvertFrom-Json)
                $expected=@('--powershell',[Environment]::ProcessPath,'--profile',$Profile,'--failure-point',$FailurePoint)
                if($OriginalPurpose){$expected+=@('--original-purpose')}
                if(($arguments|ConvertTo-Json -Compress) -cne ($expected|ConvertTo-Json -Compress)){throw 'Native profile argv changed'}
                $cases++
            }
        }
    }
    $fixed=@'
$originalArgs=@()
    if($OriginalPurpose){$originalArgs=@('--original-purpose')}
'@
    $old=@'
$originalArgs=if($OriginalPurpose){@('--original-purpose')}else{@()}
'@
    $fixed=$fixed.Replace("`r`n","`n")
    if(-not $body.Contains($fixed,[StringComparison]::Ordinal)){throw 'Explicit array source missing'}
    $OriginalPurpose=$true;$Profile='v2-retained-service-use';$FailurePoint='none'
    $mutant=$body.Replace($fixed,$old)
    $broken=@((& ([scriptblock]::Create($mutant)))|ConvertFrom-Json)
    if($broken.Count -le 7 -or $broken -ccontains '--original-purpose'){throw 'Old scalar-splat counterexample not reproduced'}
    if($cases -ne 12){throw 'Forwarding cases missing'}
    Write-Output 'NATIVE PROFILE FORWARDING PASS:12 actual argv cases; old scalar-splat mutant refused; no Docker or databases.'
}finally{
    if([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([IO.File]::ReadAllBytes($sink))) -cne [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes))){throw 'Own argv sink changed'}
    [IO.File]::Delete($sink)
}
