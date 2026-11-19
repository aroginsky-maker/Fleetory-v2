#requires -Version 7.3
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$repo=Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
. (Join-Path $repo 'eng/pilot/historical/RetainedDataStageHost.ps1')
$script:opens=0;$script:callbacks=0;$checks=0
function Assert-ImmuData($Condition,[string]$Category){if(-not $Condition){throw $Category}}
function Open-RetainedServiceUsePeer {$script:opens++;throw 'unexpected-peer-open'}
function Close-RetainedServiceUsePeer {}
$outside=@(
    (Join-Path $repo '../offline/retained-inputs'),
    (Join-Path $repo 'artifacts/not-a-native-pair/retained-inputs'),
    (Join-Path $repo 'artifacts/native-pair-00000000-0000-0000-0000-000000000000/provider-inputs'),
    (Join-Path $repo 'artifacts/native-pair-00000000-0000-0000-0000-000000000000/../retained-inputs'),
    (Join-Path $repo 'artifacts/native-pair-00000000-0000-0000-0000-000000000000/retained-inputs/extra')
)
foreach($mode in @('normal','exit-on-request','expire-after-restore')){
    foreach($path in $outside){
        try{
            $null=Invoke-RetainedDataStageHost $repo 'unused' $path @{} @{} @{} $null @{ImageClaimed=$false} $null -Mode $mode -GeneratedAfterCapture {$script:callbacks++}
            throw 'outside-callback-accepted'
        }catch{
            if($_.Exception.Message -cne 'retained-host-generated-callback-root'){throw}
        }
        $checks++
    }
}
if($script:opens -ne 0 -or $script:callbacks -ne 0){throw 'boundary-performed-work'}
@{schema='fleetory.retained-data-host-callback-boundary.v1';rejected=$checks;peerOpens=0;callbackCalls=0;originalInputsRead=$false;verified=$true}|ConvertTo-Json -Compress
