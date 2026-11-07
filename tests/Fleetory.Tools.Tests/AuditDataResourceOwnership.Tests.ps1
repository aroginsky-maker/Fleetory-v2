#requires -Version 7.3
param([ValidateSet('test','claim','reader')][string]$Mode='test',[string]$Directory='',[string]$Fixture='')
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
foreach($helper in @('../../eng/pilot/ImmuDataRoundtripPolicy.ps1','../../eng/pilot/ProviderRecoveryPolicy.ps1',
    'NativeSignerFixture.ps1','NativeWorkerRuntime.ps1','../../eng/pilot/AuditDataResourceOwnership.ps1')){. (Join-Path $PSScriptRoot $helper)}
function Context([string]$Repository,[string]$Nonce=([Guid]::NewGuid().ToString('D'))){
    return @{Fixture=$Nonce;Root=(Join-Path $Repository ('artifacts/native-audit-controller-'+$Nonce));
        PayloadClaimed=$false;PayloadRemoved=$false;ImageName=(Get-ImmuDataImageName $Nonce);ImageId=$null;
        Stores=[Collections.Generic.List[object]]::new()}
}
if($Mode -ceq 'claim'){
    $candidate=Context $Directory $Fixture;$claimed=$false
    try{New-AuditDataPublicPayload $Directory $candidate;$claimed=$true}catch{}
    @{claimed=$claimed;recorded=$candidate.PayloadClaimed}|ConvertTo-Json -Compress
    exit 0
}
if($Mode -ceq 'reader'){
    $path=Join-Path $Directory 'owned-stores.json';$reads=0;$clock=[Diagnostics.Stopwatch]::StartNew()
    while(-not (Test-Path -LiteralPath (Join-Path $Directory 'stop'))){
        if($clock.Elapsed.TotalSeconds -gt 20){throw 'Concurrent ledger reader deadline.'}
        # Windows can refuse an open during replacement. Only a complete read is evidence;
        # a missing name is not interpreted as resource absence or an empty ledger.
        try{$stream=[IO.FileStream]::new($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))}
        catch [IO.FileNotFoundException]{continue}
        catch [IO.IOException]{if($IsWindows -and ($_.Exception.HResult -band 65535) -in @(32,33)){continue};throw}
        try{
            $reader=[IO.StreamReader]::new($stream,[Text.UTF8Encoding]::new($false,$true))
            try{$text=$reader.ReadToEnd()}finally{$reader.Dispose()}
        }finally{$stream.Dispose()}
        $value=$text|ConvertFrom-Json -AsHashtable -Depth 7
        if($text.Length -gt 16384 -or $value.fixture -cne $Fixture -or @($value.stores).Count -ne 1 -or
            $value.stores[0].Id -cnotmatch '^([a-f0-9])\1{63}\z'){throw 'Concurrent reader saw a torn resource record.'}
        $reads++
        if($reads -eq 1){[IO.File]::WriteAllText((Join-Path $Directory 'ready'),'ready')}
    }
    Write-Output $reads
    exit 0
}
$count=0
function Check([bool]$Condition,[string]$Name){if(-not $Condition){throw ('Resource ownership regression: '+$Name)};$script:count++}
function Refused([scriptblock]$Action,[string]$Name){$seen=$false;try{& $Action}catch{$seen=$true};Check $seen $Name}
function Start-Child([string[]]$Arguments){
    $start=[Diagnostics.ProcessStartInfo]::new([Environment]::ProcessPath)
    $start.UseShellExecute=$false;$start.CreateNoWindow=$true;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
    foreach($arg in @('-NoLogo','-NoProfile','-NonInteractive','-File',$PSCommandPath)+$Arguments){$null=$start.ArgumentList.Add($arg)}
    $process=[Diagnostics.Process]::new();$process.StartInfo=$start
    if(-not $process.Start()){throw 'Resource contract child did not start.'}
    return @{Process=$process;Output=$process.StandardOutput.ReadToEndAsync();Error=$process.StandardError.ReadToEndAsync()}
}
function Finish-Child($Child){
    if(-not $Child.Process.WaitForExit(25000)){throw 'Resource contract child deadline.'}
    $output=$Child.Output.GetAwaiter().GetResult();$errorText=$Child.Error.GetAwaiter().GetResult()
    if($Child.Process.ExitCode -ne 0){[Console]::Error.WriteLine($errorText)}
    Check ($Child.Process.ExitCode -eq 0 -and [string]::IsNullOrWhiteSpace($errorText)) 'child-exit'
    return $output
}
$temporaryBase=Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'artifacts'
$null=New-Item -ItemType Directory -Path $temporaryBase -Force
$directory=Join-Path $temporaryBase ('fleetory-resource-contract-'+[Guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path (Join-Path $directory 'artifacts')
$children=[Collections.Generic.List[object]]::new()
try{
    foreach($kind in @('directory','file')){
        $c=Context $directory
        if($kind -ceq 'directory'){$null=New-Item -ItemType Directory -Path $c.Root;[IO.File]::WriteAllText((Join-Path $c.Root 'foreign'),'foreign')}
        else{[IO.File]::WriteAllText($c.Root,'foreign')}
        Refused {New-AuditDataPublicPayload $directory $c} ('preexisting-'+$kind)
        Check (-not $c.PayloadClaimed) ('unclaimed-'+$kind)
        Remove-AuditDataPublicPayload $directory $c
        $sentinel=if($kind -ceq 'directory'){Join-Path $c.Root 'foreign'}else{$c.Root}
        Check ([IO.File]::ReadAllText($sentinel) -ceq 'foreign') ('foreign-survives-'+$kind)
    }
    $outside=Join-Path $directory 'outside';$null=New-Item -ItemType Directory -Path $outside
    [IO.File]::WriteAllText((Join-Path $outside 'foreign'),'foreign')
    $c=Context $directory
    $linkType=if($IsWindows){'Junction'}else{'SymbolicLink'}
    $null=New-Item -ItemType $linkType -Path $c.Root -Target $outside
    Refused {New-AuditDataPublicPayload $directory $c} 'preexisting-link'
    Remove-AuditDataPublicPayload $directory $c
    Check (-not $c.PayloadClaimed -and [IO.File]::ReadAllText((Join-Path $outside 'foreign')) -ceq 'foreign') 'linked-foreign-survives'
    Remove-Item -LiteralPath $c.Root -Force

    $c=Context $directory;New-AuditDataPublicPayload $directory $c
    Check ($c.PayloadClaimed -and -not $c.PayloadRemoved -and (Test-Path -LiteralPath $c.Root)) 'new-claim'
    [IO.File]::WriteAllText((Join-Path $c.Root 'public-code'),'generated')
    Remove-AuditDataPublicPayload $directory $c
    Check (-not $c.PayloadClaimed -and $c.PayloadRemoved -and -not (Test-Path -LiteralPath $c.Root)) 'consumed-cleanup'
    $null=New-Item -ItemType Directory -Path $c.Root;[IO.File]::WriteAllText((Join-Path $c.Root 'foreign'),'later')
    Remove-AuditDataPublicPayload $directory $c
    Refused {New-AuditDataPublicPayload $directory $c} 'consumed-claim-reuse'
    Check ([IO.File]::ReadAllText((Join-Path $c.Root 'foreign')) -ceq 'later') 'cleanup-replay-preserves-later-occupant'

    foreach($kind in @('root','fixture','zero','state')){
        $bad=Context $directory
        if($kind -ceq 'root'){$bad.Root=$outside}elseif($kind -ceq 'fixture'){$bad.Fixture='../escape'}
        elseif($kind -ceq 'zero'){$bad.Fixture=[Guid]::Empty.ToString('D')}else{$bad.PayloadClaimed='true'}
        Refused {New-AuditDataPublicPayload $directory $bad} ('bad-claim-'+$kind)
    }
    $linkedRepo=Join-Path $directory 'linked';$null=New-Item -ItemType Directory -Path $linkedRepo
    $null=New-Item -ItemType $linkType -Path (Join-Path $linkedRepo 'artifacts') -Target $outside
    $bad=Context $linkedRepo
    Refused {New-AuditDataPublicPayload $linkedRepo $bad} 'linked-parent'
    Check (-not $bad.PayloadClaimed -and -not (Test-Path -LiteralPath (Join-Path $outside ('native-audit-controller-'+$bad.Fixture)))) 'linked-parent-no-write'
    Remove-Item -LiteralPath (Join-Path $linkedRepo 'artifacts') -Force

    $race=Context $directory
    foreach($n in 1..2){$children.Add((Start-Child @('-Mode','claim','-Directory',$directory,'-Fixture',$race.Fixture)))}
    $claims=@($children|ForEach-Object {(Finish-Child $_)|ConvertFrom-Json -AsHashtable})
    Check (@($claims|Where-Object {$_.claimed -eq $true -and $_.recorded -eq $true}).Count -eq 1) 'one-exclusive-winner'
    Check (@($claims|Where-Object {$_.claimed -eq $false -and $_.recorded -eq $false}).Count -eq 1) 'loser-remains-unclaimed'

    $ledger=Context $directory;New-AuditDataPublicPayload $directory $ledger
    $session=[Guid]::NewGuid().ToString('D')
    $store=@{Id=$null;Session=$session;Name=('fleetory-immu-store-'+$session.Replace('-',''));Started=[DateTimeOffset]::UtcNow;Role='target'}
    $ledger.Stores.Add($store);Write-AuditDataLedger $ledger
    $path=Join-Path $ledger.Root 'owned-stores.json';$old=[IO.File]::ReadAllText($path)
    Check (($old|ConvertFrom-Json -AsHashtable).stores[0].Id -eq $null) 'intent-before-container-id'
    $store.Id='a'*64;$ledger.ImageId='sha256:'+('b'*64);Write-AuditDataLedger $ledger
    $old=[IO.File]::ReadAllText($path)
    Check (($old|ConvertFrom-Json -AsHashtable).stores[0].Id -ceq $store.Id) 'published-container-id'
    $store.Role='foreign'
    Refused {Write-AuditDataLedger $ledger} 'invalid-store'
    Check ([IO.File]::ReadAllText($path) -ceq $old) 'invalid-preserves-previous'
    $store.Role='target'
    $publication=${function:Publish-AuditDataLedger}
    try{
        function Publish-AuditDataLedger([string]$Temporary,[string]$Destination){
            $pending=[IO.File]::ReadAllText($Temporary)|ConvertFrom-Json -AsHashtable
            Check ($pending.stores[0].Id -ceq ('c'*64) -and [IO.File]::ReadAllText($Destination) -ceq $old) 'flushed-before-publication'
            throw [IO.IOException]::new('Injected publication failure.')
        }
        $store.Id='c'*64
        Refused {Write-AuditDataLedger $ledger} 'publication-failure'
    }finally{Set-Item -Path Function:Publish-AuditDataLedger -Value $publication}
    Check ([IO.File]::ReadAllText($path) -ceq $old) 'failed-publication-preserves-previous'
    Check (@(Get-ChildItem -LiteralPath $ledger.Root -Filter '*.tmp' -Force).Count -eq 0) 'owned-temporary-removed'
    $foreignTemp=Join-Path $ledger.Root 'owned-stores.foreign.tmp';[IO.File]::WriteAllText($foreignTemp,'foreign')
    Write-AuditDataLedger $ledger
    Check ([IO.File]::ReadAllText($foreignTemp) -ceq 'foreign') 'foreign-temporary-preserved'

    $reader=Start-Child @('-Mode','reader','-Directory',$ledger.Root,'-Fixture',$ledger.Fixture);$children.Add($reader)
    $ready=Join-Path $ledger.Root 'ready';$wait=[Diagnostics.Stopwatch]::StartNew()
    while(-not (Test-Path -LiteralPath $ready)){
        if($wait.Elapsed.TotalSeconds -gt 15 -or $reader.Process.HasExited){throw 'Ledger reader did not become ready.'}
        Start-Sleep -Milliseconds 10
    }
    foreach($n in 0..99){$store.Id=([string]'0123456789abcdef'[$n % 16])*64;Write-AuditDataLedger $ledger}
    [IO.File]::WriteAllText((Join-Path $ledger.Root 'stop'),'stop')
    $reads=[int](Finish-Child $reader)
    Check ($reads -ge 2) 'concurrent-reader-complete-json'
    Check (@(Get-ChildItem -LiteralPath $ledger.Root -Filter '*.tmp' -Force).Count -eq 1) 'only-foreign-temporary-remains'

    $linkedLedger=Context $directory;New-AuditDataPublicPayload $directory $linkedLedger
    $destination=Join-Path $linkedLedger.Root 'owned-stores.json'
    $null=New-Item -ItemType Directory -Path $destination
    Refused {Write-AuditDataLedger $linkedLedger} 'directory-destination'
    Check ((Get-Item -LiteralPath $destination).PSIsContainer) 'foreign-destination-preserved'
    Remove-AuditDataPublicPayload $directory $ledger;Remove-AuditDataPublicPayload $directory $linkedLedger
}finally{
    foreach($child in $children){
        if(-not $child.Process.HasExited){$child.Process.Kill($true);$null=$child.Process.WaitForExit(3000)}
        $child.Process.Dispose()
    }
    if(Test-Path -LiteralPath $directory){
        $owned=Get-ProviderOrdinaryItem $directory
        if($owned.FullName -cne $directory -or $owned.Parent.FullName -cne $temporaryBase){throw 'Test cleanup target changed.'}
        Remove-Item -LiteralPath $owned.FullName -Recurse -Force
    }
}
Write-Output ('AUDIT RESOURCE OWNERSHIP PASS:'+ $count +' assertions;exclusive claim,foreign preservation,atomic publication,100 concurrent replacements.')
$global:LASTEXITCODE=0
