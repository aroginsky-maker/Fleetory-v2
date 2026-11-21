$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot '../../eng/pilot/PublicBuildImageTransaction.ps1')
$bytes=[byte[]]@(1,2,3)
$sha=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
$id='sha256:'+('d'*64)
$checks=0
function Check($Value,$Name){if(-not $Value){throw $Name};$script:checks++}
foreach($fault in @('none','before-build','after-build','use-throws','after-use','unknown-build','remove-throws','wrong-absence')){
    $script:model=@{Fault=$fault;Builds=0;Removes=0;Inspects=0;Uses=0;Alive=0;Instance=$null}
    $native={param([string[]]$Arguments,[byte[]]$InputBytes)
        $m=$script:model
        if($Arguments[0] -ceq 'build'){
            $m.Builds++
            Check ($Arguments.Count -eq 8 -and $Arguments[6] -cmatch '^fleetory\.public-build\.instance=[a-f0-9-]{36}$') 'closed-build-args'
            Check ($null -ne $InputBytes -and $InputBytes.Length -eq 3) 'original-build-bytes'
            $m.Instance=$Arguments[6]
            if($m.Fault -ceq 'unknown-build'){return [Tuple]::Create(0,[Text.Encoding]::ASCII.GetBytes('truncated'),[byte[]]@())}
            return [Tuple]::Create(0,[Text.Encoding]::ASCII.GetBytes($id+"`n"),[byte[]]@())
        }
        Check ($null -eq $InputBytes) 'cleanup-no-input'
        if($Arguments[1] -ceq 'rm'){
            $m.Removes++
            Check (($Arguments -join '|') -ceq ('image|rm|--no-prune|'+$id)) 'exact-own-remove'
            if($m.Fault -ceq 'remove-throws'){throw 'Modeled native removal failure'}
            return [Tuple]::Create(0,[Text.Encoding]::ASCII.GetBytes('Deleted: '+$id+"`n"),[byte[]]@())
        }
        $m.Inspects++
        Check (($Arguments -join '|') -ceq ('image|inspect|'+$id)) 'exact-own-absence'
        $absent=if($m.Fault -ceq 'wrong-absence'){'sha256:'+('e'*64)}else{$id}
        return [Tuple]::Create(1,[byte[]]@(),[Text.Encoding]::ASCII.GetBytes('Error: no such image: '+$absent+"`n"))
    }
    $alive={
        $m=$script:model;$m.Alive++
        return -not (($m.Fault -ceq 'before-build' -and $m.Alive -eq 1) -or
            ($m.Fault -ceq 'after-build' -and $m.Alive -eq 2) -or ($m.Fault -ceq 'after-use' -and $m.Alive -eq 3))
    }
    $use={param($Context,$Client)
        $script:model.Uses++
        Check ([Fleetory.Pilot.PublicBuildImageCustody]::Id($Context,$Client) -ceq $id) 'live-worker-use'
        if($script:model.Fault -ceq 'use-throws'){throw 'Modeled SDK-stage failure'}
        return 'held-result'
    }
    $failed=$false
    try{$value=Invoke-PublicBuildImageTransaction $bytes $sha $native $alive $use}catch{$failed=$true}
    Check ($failed -eq ($fault -cne 'none')) ('outcome-'+$fault)
    Check ($script:model.Builds -eq $(if($fault -ceq 'before-build'){0}else{1})) ('sole-build-'+$fault)
    Check ($script:model.Removes -eq $(if($fault -cin @('before-build','unknown-build')){0}else{1})) ('sole-own-removal-'+$fault)
    if($fault -cin @('before-build','after-build','unknown-build')){Check ($script:model.Uses -eq 0) 'no-use-after-loss-or-unknown'}
    if($fault -ceq 'none'){Check ($value.imageClosed -and $value.result -ceq 'held-result' -and -not $value.controllerDeathVerified) 'bounded-model-only-result'}
}
Write-Output "PASS $checks public build transaction assertions; modeled link loss only, no child-process or Docker execution."

$global:LASTEXITCODE=0
