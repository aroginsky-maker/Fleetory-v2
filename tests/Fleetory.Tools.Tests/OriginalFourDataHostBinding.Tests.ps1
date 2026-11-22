$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$repo=Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
. (Join-Path $repo 'eng/pilot/historical/RetainedDataStageHost.ps1')
$script:opens=0;$script:native=0;$checks=0
function Assert-ImmuData($Condition,[string]$Category){if(-not $Condition){throw $Category}}
function Open-OriginalFourServiceUsePeer {$script:opens++;throw 'unexpected-peer-open'}
function Open-RetainedServiceUsePeer {$script:opens++;throw 'unexpected-legacy-peer-open'}
function Invoke-RetainedPostgresTarget {$script:native++;throw 'unexpected-native-call'}
function Close-RetainedServiceUsePeer {}
$commit=@{revision=('1'*40);imageId=('sha256:'+'2'*64);probeSha256=('3'*64);configurationSha256=('4'*64)}
foreach($mode in @('normal','exit-on-request','expire-after-restore')){
    foreach($field in @('root','revision','imageId','probeSha256','configurationSha256','missing','actualImage','actualProbe')){
        $binding=@{root='generated-root';revision=$commit.revision;imageId=$commit.imageId;probeSha256=$commit.probeSha256;configurationSha256=$commit.configurationSha256}
        $image=@{ImageClaimed=$false;ImageId=$commit.imageId;ProbeHash=$commit.probeSha256}
        $category='original-host-binding-drift'
        if($field -ceq 'missing'){$binding.Remove('root');$category='original-host-binding-fields'}
        elseif($field -ceq 'actualImage'){$image.ImageId='foreign'}
        elseif($field -ceq 'actualProbe'){$image.ProbeHash='foreign'}
        else{$binding[$field]='foreign'}
        try{
            $null=Invoke-RetainedDataStageHost 'unused' 'unused' 'generated-root' @{} $commit @{} $null $image $null -Mode $mode -OriginalExpected $binding
            throw 'drift-accepted'
        }catch{if($_.Exception.Message -cne $category){throw}}
        $checks++
    }
}
if($checks -ne 24 -or $script:opens -ne 0 -or $script:native -ne 0){throw 'unexpected-work-or-missing-case'}
@{verified=$true;refusals=$checks;peerOpens=0;nativeCalls=0;originalInputsRead=$false}|ConvertTo-Json -Compress
