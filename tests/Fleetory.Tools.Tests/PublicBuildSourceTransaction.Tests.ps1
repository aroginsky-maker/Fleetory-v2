$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot '../../eng/pilot/PublicBuildSourceTransaction.ps1')
$expected=[Text.Encoding]::ASCII.GetBytes('generated-public-source-only')
$digest=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($expected)).ToLowerInvariant()
$cases=0
foreach($case in @('normal','controller-before-capture','controller-after-build','source-after-build','source-deadline','bad-source','source-during-use')){
    $clock=[Diagnostics.Stopwatch]::StartNew()
    $start=[Diagnostics.ProcessStartInfo]::new([Environment]::ProcessPath)
    $start.UseShellExecute=$false;$start.RedirectStandardInput=$true;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
    $mode=if($case -ceq 'bad-source'){'magic'}else{'normal'}
    foreach($word in @('-NoProfile','-File',(Join-Path $PSScriptRoot 'PublicBuildTransportFixture.ps1'),$mode)){$start.ArgumentList.Add($word)}
    $child=[Diagnostics.Process]::Start($start)
    $source=[Fleetory.Pilot.PublicBuildSourceTransport]::new($child,$clock,$(if($case -ceq 'source-deadline'){2000}else{10000}))
    $sourceFixture=@{builds=0;removes=0;inspects=0;uses=0;alive=($case -cne 'controller-before-capture');image=('sha256:'+('d'*64))}
    $native={param([string[]]$Arguments,[byte[]]$Bytes)
        if($Arguments[0] -ceq 'build'){
            $sourceFixture.builds++
            if($case -ceq 'controller-after-build'){$sourceFixture.alive=$false}
            if($case -ceq 'source-after-build'){$child.Kill();if(-not $child.WaitForExit(5000)){throw 'Source loss unconfirmed'}}
            if($case -ceq 'source-deadline'){Start-Sleep -Milliseconds 2100}
            return [Tuple[int,byte[],byte[]]]::new(0,[Text.Encoding]::ASCII.GetBytes($sourceFixture.image+"`n"),[byte[]]@())
        }
        if($Arguments[1] -ceq 'rm'){
            $sourceFixture.removes++
            return [Tuple[int,byte[],byte[]]]::new(0,[Text.Encoding]::ASCII.GetBytes('Deleted: '+$sourceFixture.image+"`n"),[byte[]]@())
        }
        $sourceFixture.inspects++
        return [Tuple[int,byte[],byte[]]]::new(1,[byte[]]@(),[Text.Encoding]::ASCII.GetBytes('Error: no such image: '+$sourceFixture.image+"`n"))
    }
    $alive={return $sourceFixture.alive}
    $use={param($Context,$Client,$SourceAlive)
        $null=[Fleetory.Pilot.PublicBuildImageCustody]::Id($Context,$Client)
        if(-not (& $SourceAlive)){throw 'Composed source/controller callback unavailable before use'}
        $sourceFixture.uses++
        $replay=$false;try{$source.RequestBeforeSdk()}catch{$replay=$true}
        if(-not $replay){throw 'Pre-SDK permit replay accepted'}
        if($case -ceq 'source-during-use'){
            $child.Kill();if(-not $child.WaitForExit(5000)){throw 'Source loss during use unconfirmed'}
            if(& $SourceAlive){throw 'Composed callback accepted dead source during use'}
        }
        return 'generated source consumed'
    }
    $failed=$false
    try{$result=Invoke-PublicBuildSourceTransaction $source $digest $native $alive $use}
    catch{if($case -ceq 'normal'){throw};$failed=$true}
    if($failed -ne ($case -cne 'normal')){throw 'Unexpected source transaction result'}
    $expectedBuild=if($case -cin @('bad-source','controller-before-capture')){0}else{1}
    if($sourceFixture.builds -ne $expectedBuild -or $sourceFixture.removes -ne $expectedBuild -or $sourceFixture.inspects -ne $expectedBuild -or $sourceFixture.uses -ne $(if($case -cin @('normal','source-during-use')){1}else{0})){throw 'Original source/image cleanup counts differ'}
    if($source.IsAlive()){throw 'Source still alive after transaction'}
    $replay=$false;try{$null=Invoke-PublicBuildSourceTransaction $source $digest $native $alive $use}catch{$replay=$true}
    if(-not $replay -or $sourceFixture.builds -ne $expectedBuild){throw 'Source transaction replay reached native backend'}
    $cases++
}
Write-Output "PASS $cases live source/image transaction cases; synthetic backend; no native resources"
