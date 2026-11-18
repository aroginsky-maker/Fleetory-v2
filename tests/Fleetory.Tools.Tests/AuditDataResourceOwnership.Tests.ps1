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
    Check ($null -eq ($old|ConvertFrom-Json -AsHashtable).stores[0].Id) 'intent-before-container-id'
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

    # Same-process raw reply custody. These generated CLI models do not prove Docker origin.
    . (Join-Path $PSScriptRoot 'NativeAuditDataFixture.ps1')
    $script:custodyModel=$null
    function Invoke-Docker([string[]]$Arguments,[byte[]]$InputBytes=$null,[int]$TimeoutSeconds=60,[switch]$AllowFailure){
        $m=$script:custodyModel;$m.Calls.Add(($Arguments -join '|'))
        if($m.Throw){throw 'Injected native transport loss.'}
        if($Arguments[0] -ceq 'inspect'){
            if($m.Absent -and $m.PostInspectThrow){throw 'Injected post-removal read loss.'}
            if($m.Absent){$exitCode=1;$out=$m.AbsentOutput;$err='No such object: '+$Arguments[1]+"`n";if($m.WrongAbsentId){$err='No such object: '+('f'*64)+"`n"}}
            else{
                $exitCode=0;$err='';$s=$m.Store;$c=$m.Context
                $out=@(@{Id=$s.Id;Name=('/'+$s.Name);Created=$s.Started.ToString('O');Image=$c.ImageId;
                    Config=@{Image=$c.ImageId;Labels=@{'fleetory.immu-data.session'=$s.Session}}})|ConvertTo-Json -Depth 5 -Compress -AsArray
                if($m.BadProfile){$out=$out.Replace('/'+$s.Name,'/foreign')}
            }
        }else{$exitCode=$m.Exit;$out=$m.Output;$err='';if($Arguments[0] -ceq 'rm' -and $exitCode -eq 0){$m.Absent=$true}}
        return @{ExitCode=$exitCode;Stdout=$out;Stderr=$err;StdoutBytes=[Text.Encoding]::UTF8.GetBytes($out);StderrBytes=[Text.Encoding]::UTF8.GetBytes($err)}
    }
    function New-CustodyModel{
        $c=Context $directory;$c.ImageId='sha256:'+('d'*64);$c.LifetimeSeconds=660
        $session=[Guid]::NewGuid().ToString('D')
        $s=@{Id=$null;Session=$session;Name=('fleetory-immu-store-'+$session.Replace('-',''));Started=[DateTimeOffset]::UtcNow;Role='target'}
        $c.Stores.Add($s)
        $script:custodyModel=@{Context=$c;Store=$s;Calls=[Collections.Generic.List[string]]::new();Output=(('a'*64)+"`n");Exit=0;Throw=$false;Absent=$false;AbsentOutput="[]`n";WrongAbsentId=$false;PostInspectThrow=$false;BadProfile=$false}
        return $script:custodyModel
    }
    function Claim-CustodyModel($Model){$null=Invoke-AuditDataContainerOperation $Model.Context $Model.Store 'Create' @('run','fixed-model')}
    foreach($bad in @('',('a'*12),('a'*64),(' '+('a'*64)+"`n"),(('a'*64)+"`n"+('b'*64)+"`n"),(('A'*64)+"`n"))){
        $m=New-CustodyModel;$m.Output=$bad
        Refused {Claim-CustodyModel $m} 'create-raw-boundary'
        $calls=$m.Calls.Count;$m.Store.Id='a'*64
        Refused {Remove-AuditDataStore $m.Context $m.Store} 'unknown-create-no-name-adoption'
        Refused {Claim-CustodyModel $m} 'unknown-create-consumed'
        Check ($m.Calls.Count -eq $calls) 'unknown-create-no-docker'
    }
    foreach($kind in @('exit','throw')){
        $m=New-CustodyModel
        if($kind -ceq 'exit'){$m.Exit=1}else{$m.Throw=$true}
        Refused {Claim-CustodyModel $m} 'create-failed-unknown'
        $calls=$m.Calls.Count;$m.Exit=0;$m.Throw=$false
        Check (-not (Test-AuditDataStoreClosed $m.Context $m.Store)) 'failed-create-never-closed'
        Refused {Claim-CustodyModel $m} 'failed-create-never-retried'
        Refused {Remove-AuditDataStore $m.Context $m.Store} 'failed-create-never-adopted'
        Check ($m.Calls.Count -eq $calls) 'failed-create-no-docker'
    }
    foreach($newline in @("`n","`r`n")){
        $m=New-CustodyModel;$m.Output=('a'*64)+$newline;Claim-CustodyModel $m
        Check ($m.Store.Id -ceq ('a'*64)) 'full-id-not-trimmed-or-shortened'
        Check (-not (Test-AuditDataStoreClosed $m.Context $m.Store)) 'created-store-still-live'
        $c=$m.Context;$s=$m.Store;$client=${function:Invoke-Docker};$calls=$m.Calls.Count
        foreach($pair in @(@('Session',[Guid]::NewGuid().ToString('D')),@('Name','foreign'),@('Role','source'),@('Started',$s.Started.AddTicks(1)),@('Id',('b'*64)))){
            $old=$s[$pair[0]];$s[$pair[0]]=$pair[1]
            Refused {Remove-AuditDataStore $c $s} 'changed-store-refused-before-lookup';$s[$pair[0]]=$old
        }
        foreach($pair in @(@('Fixture',[Guid]::NewGuid().ToString('D')),@('ImageName','foreign:fixture'),@('ImageId',('sha256:'+('b'*64))),@('LifetimeSeconds',3300))){
            $old=$c[$pair[0]];$c[$pair[0]]=$pair[1]
            Refused {Remove-AuditDataStore $c $s} 'changed-context-refused-before-lookup';$c[$pair[0]]=$old
        }
        Refused {Remove-AuditDataStore $c ($s.Clone())} 'copied-store-has-no-claim'
        Refused {Remove-AuditDataStore ($c.Clone()) $s} 'copied-context-has-no-claim'
        $copy=($s|ConvertTo-Json -Compress)|ConvertFrom-Json -AsHashtable
        Refused {Remove-AuditDataStore $c $copy} 'serialized-ledger-has-no-claim'
        $list=$c.Stores;$c.Stores=[Collections.Generic.List[object]]::new();$c.Stores.Add($s)
        Refused {Remove-AuditDataStore $c $s} 'replaced-store-list';$c.Stores=$list
        $c.Stores.Clear();Refused {Remove-AuditDataStore $c $s} 'removed-store-refused';$c.Stores.Add($s)
        try{
            function Invoke-Docker{throw 'Changed live client must not run.'}
            Refused {Remove-AuditDataStore $c $s} 'changed-live-client'
        }finally{Set-Item -Path Function:Invoke-Docker -Value $client}
        Check ($m.Calls.Count -eq $calls) 'mutations-never-looked-up'
        $m.BadProfile=$true
        Refused {Remove-AuditDataStore $c $s} 'fresh-inspection-foreign-refused'
        Check (@($m.Calls|Where-Object {$_ -like 'rm|*'}).Count -eq 0) 'foreign-profile-never-removed'
        $m.BadProfile=$false;$m.Output=('a'*64)+$newline;$m.Absent=$false
        Remove-AuditDataStore $c $s
        Check (Test-AuditDataStoreClosed $c $s) 'complete-removal-known-closed'
        Refused {Test-AuditDataStoreClosed ($c.Clone()) $s} 'closed-state-not-importable'
        $calls=$m.Calls.Count;Refused {Remove-AuditDataStore $c $s} 'complete-removal-consumed'
        Check ($m.Calls.Count -eq $calls) 'complete-removal-no-replay'
    }
    foreach($kind in @('partial','wrong-id','exit','throw')){
        $m=New-CustodyModel;Claim-CustodyModel $m
        switch($kind){'partial'{$m.Output='a'*12};'wrong-id'{$m.Output=('b'*64)+"`n"};'exit'{$m.Exit=1};'throw'{$m.Throw=$true}}
        Refused {Invoke-AuditDataContainerOperation $m.Context $m.Store 'Remove' @('rm','-f','-v',$m.Store.Id)} 'removal-outcome-unknown'
        $calls=$m.Calls.Count;$m.Throw=$false;$m.Exit=0;$m.Output=('a'*64)+"`n"
        Check (-not (Test-AuditDataStoreClosed $m.Context $m.Store)) 'unknown-removal-not-closed'
        Refused {Remove-AuditDataStore $m.Context $m.Store} 'unknown-removal-consumed'
        Check ($m.Calls.Count -eq $calls) 'unknown-removal-no-retry'
    }
    $m=New-CustodyModel;Claim-CustodyModel $m;$m.Absent=$true
    Remove-AuditDataStore $m.Context $m.Store;$calls=$m.Calls.Count
    Check (Test-AuditDataStoreClosed $m.Context $m.Store) 'observed-absence-known-closed'
    Refused {Remove-AuditDataStore $m.Context $m.Store} 'observed-absence-consumed'
    Check ($m.Calls.Count -eq $calls -and @($m.Calls|Where-Object {$_ -like 'rm|*'}).Count -eq 0) 'already-absent-never-removed'
    foreach($raw in @('',"[]`n","[]`r`n")){
        $m=New-CustodyModel;Claim-CustodyModel $m;$m.Absent=$true;$m.AbsentOutput=$raw
        Remove-AuditDataStore $m.Context $m.Store
        Check (Test-AuditDataStoreClosed $m.Context $m.Store) 'exact-empty-inspect-array-absence'
        Check (@($m.Calls|Where-Object {$_ -like 'rm|*'}).Count -eq 0) 'no-removal-for-held-absent-reply'
    }
    foreach($kind in @('stdout','id')){
        $m=New-CustodyModel;Claim-CustodyModel $m;$m.Absent=$true
        if($kind -ceq 'stdout'){$m.AbsentOutput='[{}]'}else{$m.WrongAbsentId=$true}
        Refused {Remove-AuditDataStore $m.Context $m.Store} 'ambiguous-absence-never-closes'
        Check (-not (Test-AuditDataStoreClosed $m.Context $m.Store)) 'invalid-absence-stays-live'
        Check (@($m.Calls|Where-Object {$_ -like 'rm|*'}).Count -eq 0) 'invalid-absence-never-removes'
    }
    foreach($kind in @('transport','stdout','id')){
        $m=New-CustodyModel;Claim-CustodyModel $m
        if($kind -ceq 'transport'){$m.PostInspectThrow=$true}
        elseif($kind -ceq 'stdout'){$m.AbsentOutput='[{}]'}else{$m.WrongAbsentId=$true}
        Refused {Remove-AuditDataStore $m.Context $m.Store} 'post-removal-absence-unverified'
        Check (-not (Test-AuditDataStoreClosed $m.Context $m.Store)) 'rm-ack-not-closed-without-absence'
        $calls=$m.Calls.Count
        Refused {Remove-AuditDataStore $m.Context $m.Store} 'post-removal-loss-no-mutation-replay'
        Check ($m.Calls.Count -eq $calls -and @($m.Calls|Where-Object {$_ -like 'rm|*'}).Count -eq 1) 'post-removal-loss-only-one-rm'
    }
    # Untagged historical image lifecycle. Models exercise replies, not Docker origin.
    function Invoke-Docker([string[]]$Arguments,[byte[]]$InputBytes=$null,[int]$TimeoutSeconds=60,[switch]$AllowFailure){
        $m=$script:imageModel;$m.Calls.Add(($Arguments -join '|'))
        if($m.Throw){throw 'Injected image native loss.'}
        $out='';$err='';$exitCode=$m.Exit
        if($Arguments[0] -ceq 'build'){
            Check ($TimeoutSeconds -eq 120 -and ($Arguments -join '|') -ceq 'build|--quiet|--network|none|--pull=false|-' -and $InputBytes.Length -gt 0) 'fixed-untagged-build-argv'
            if($m.MutateArchive){$InputBytes[0]=$InputBytes[0] -bxor 1}
            $out=$m.Output
        }elseif($Arguments[1] -ceq 'inspect'){
            if($m.Gone){
                if($m.PostInspectThrow){throw 'Injected image post-removal read loss.'}
                $exitCode=1;$out=$m.AbsentOutput
                $missing=if($m.WrongAbsentId){'sha256:'+('f'*64)}else{$Arguments[2]}
                $err='Error response from daemon: No such image: '+$missing+"`n"
            }else{
                $c=$m.Context;$exitCode=0
                $out=@(@{Id=$c.ImageId;Created=([Fleetory.Pilot.AuditImageCustody]::Started($c,${function:Invoke-Docker})).ToString('O');
                    Config=@{User='3322:3322';Labels=@{'fleetory.immu-data.build'=$c.Fixture}};RepoTags=$m.Tags;RepoDigests=$m.Digests;
                    RootFS=@{Type='layers';Layers=@('sha256:'+('d'*64))}})|ConvertTo-Json -Depth 6 -Compress -AsArray
            }
        }else{
            Check (($Arguments -join '|') -ceq ('image|rm|--no-prune|'+$m.Context.ImageId)) 'fixed-image-no-prune-no-force'
            $out=$m.RemoveOutput
            if($exitCode -eq 0){$m.Gone=$true}
        }
        return @{ExitCode=$exitCode;Stdout=$out;Stderr=$err;StdoutBytes=[Text.Encoding]::UTF8.GetBytes($out);StderrBytes=[Text.Encoding]::UTF8.GetBytes($err)}
    }
    function New-ImageModel{
        $c=Context $directory;$c.ImageClaimed=$false;$c.ProbeHash='b'*64
        $id='sha256:'+('a'*64)
        $script:imageModel=@{Context=$c;Calls=[Collections.Generic.List[string]]::new();Exit=0;Throw=$false;MutateArchive=$false;
            Output=($id+"`n");RemoveOutput=('Deleted: '+$id+"`n");Gone=$false;Tags=@();Digests=@();
            AbsentOutput="[]`n";WrongAbsentId=$false;PostInspectThrow=$false}
        return $script:imageModel
    }
    function Claim-ImageModel($Model){
        $null=Invoke-AuditDataImageOperation $Model.Context 'Build' @('build','--quiet','--network','none','--pull=false','-') ([byte[]]@(1,2,3))
    }
    $m=New-ImageModel
    Refused {Build-AuditDataImage $m.Context 'untrusted:latest'} 'caller-selected-cli-image-refused'
    Check ($m.Calls.Count -eq 0 -and -not [Fleetory.Pilot.AuditImageCustody]::Attempted($m.Context)) 'untrusted-base-before-any-docker-or-claim'
    foreach($size in @(0,16777217)){
        $m=New-ImageModel;$bytes=[byte[]]::new($size)
        Refused {Invoke-AuditDataImageOperation $m.Context 'Build' @('build','--quiet','--network','none','--pull=false','-') $bytes} 'image-archive-bound-before-native'
        Check ($m.Calls.Count -eq 0 -and -not [Fleetory.Pilot.AuditImageCustody]::Attempted($m.Context)) 'image-invalid-archive-no-call-or-claim'
    }
    $m=New-ImageModel;Remove-AuditDataImage $m.Context;Check ($m.Calls.Count -eq 0) 'never-attempted-image-no-docker'
    $m.Context.ImageClaimed=$true;$m.Context.ImageId='sha256:'+('a'*64)
    Refused {Remove-AuditDataImage $m.Context} 'metadata-image-no-authority'
    Check ($m.Calls.Count -eq 0) 'metadata-image-no-inspect'
    foreach($kind in @('empty','short','no-newline','bare-id','extra-line','uppercase','exit','throw','mutated-archive')){
        $m=New-ImageModel
        switch($kind){
            'empty'{$m.Output=''};'short'{$m.Output='sha256:'+('a'*12)};'no-newline'{$m.Output='sha256:'+('a'*64)}
            'bare-id'{$m.Output=('a'*64)+"`n"};'extra-line'{$m.Output+="extra`n"};'uppercase'{$m.Output='sha256:'+('A'*64)+"`n"}
            'exit'{$m.Exit=1};'throw'{$m.Throw=$true};'mutated-archive'{$m.MutateArchive=$true}
        }
        Refused {Claim-ImageModel $m} 'unknown-image-build-reply'
        $calls=$m.Calls.Count;$m.Throw=$false;$m.Exit=0
        Check (-not (Test-AuditDataImageClosed $m.Context)) 'unknown-image-build-never-closed'
        $m.Context.ImageClaimed=$false
        Refused {Remove-AuditDataImage $m.Context} 'cleared-flag-cannot-hide-image-attempt'
        $m.Context.ImageClaimed=$true;$m.Context.ImageId='sha256:'+('a'*64)
        Refused {Remove-AuditDataImage $m.Context} 'saved-image-id-cannot-repair-build'
        Refused {Claim-ImageModel $m} 'unknown-image-build-no-replay'
        Check ($m.Calls.Count -eq $calls) 'unknown-image-no-docker-after-reply-loss'
    }
    foreach($newline in @("`n","`r`n")){
        $m=New-ImageModel;$m.Output='sha256:'+('a'*64)+$newline;$m.RemoveOutput='Deleted: sha256:'+('a'*64)+$newline
        Claim-ImageModel $m;$c=$m.Context;$calls=$m.Calls.Count
        Check ($c.ImageId -ceq ('sha256:'+('a'*64)) -and -not (Test-AuditDataImageClosed $c)) 'full-image-build-live'
        Refused {Remove-AuditDataImage ($c.Clone())} 'copied-image-context'
        foreach($pair in @(@('Fixture',[Guid]::NewGuid().ToString('D')),@('Root','foreign'),@('ImageName','foreign:tag'),@('ProbeHash',('c'*64)),@('ImageId',('sha256:'+('c'*64))),@('ImageClaimed',$false))){
            $old=$c[$pair[0]];$c[$pair[0]]=$pair[1]
            Refused {Remove-AuditDataImage $c} 'changed-image-metadata';$c[$pair[0]]=$old
        }
        $client=${function:Invoke-Docker}
        try{function Invoke-Docker{throw 'Changed image client must never execute.'};Refused {Remove-AuditDataImage $c} 'changed-image-client'}
        finally{Set-Item -Path Function:Invoke-Docker -Value $client}
        Check ($m.Calls.Count -eq $calls) 'changed-image-descriptors-no-lookup'
        $m.Tags=@('foreign:tag');Refused {Remove-AuditDataImage $c} 'image-foreign-tag-refused';$m.Tags=@()
        $m.Digests=@('foreign@sha256:'+('e'*64));Refused {Remove-AuditDataImage $c} 'image-foreign-digest-refused';$m.Digests=@()
        Check (@($m.Calls|Where-Object {$_ -like 'image|rm|*'}).Count -eq 0) 'foreign-image-reference-never-removed'
        Remove-AuditDataImage $c;Check (Test-AuditDataImageClosed $c) 'image-rm-and-held-absence-closed'
        $calls=$m.Calls.Count;Refused {Remove-AuditDataImage $c} 'image-removal-no-replay'
        Check ($m.Calls.Count -eq $calls -and @($m.Calls|Where-Object {$_ -like 'image|rm|*'}).Count -eq 1) 'one-own-image-removal-only'
    }
    foreach($kind in @('partial','wrong-id','extra-line','exit','throw')){
        $m=New-ImageModel;Claim-ImageModel $m
        switch($kind){'partial'{$m.RemoveOutput='Deleted: sha256:aa'};'wrong-id'{$m.RemoveOutput='Deleted: sha256:'+('f'*64)+"`n"};'extra-line'{$m.RemoveOutput+="Deleted: parent`n"};'exit'{$m.Exit=1};'throw'{$m.Throw=$true}}
        Refused {Invoke-AuditDataImageOperation $m.Context 'Remove' @('image','rm','--no-prune',$m.Context.ImageId)} 'unknown-image-remove-reply'
        Check (-not (Test-AuditDataImageClosed $m.Context)) 'unknown-image-remove-not-closed'
        $calls=$m.Calls.Count;Refused {Remove-AuditDataImage $m.Context} 'unknown-image-removal-no-retry'
        Check ($m.Calls.Count -eq $calls) 'unknown-image-removal-no-lookup'
    }
    foreach($kind in @('transport','stdout','id')){
        $m=New-ImageModel;Claim-ImageModel $m
        if($kind -ceq 'transport'){$m.PostInspectThrow=$true}elseif($kind -ceq 'stdout'){$m.AbsentOutput='[{}]'}else{$m.WrongAbsentId=$true}
        Refused {Remove-AuditDataImage $m.Context} 'image-post-rm-absence-failure'
        Check (-not (Test-AuditDataImageClosed $m.Context)) 'image-ack-alone-never-closes'
        $calls=$m.Calls.Count;Refused {Remove-AuditDataImage $m.Context} 'image-post-rm-no-second-mutation'
        Check ($m.Calls.Count -eq $calls -and @($m.Calls|Where-Object {$_ -like 'image|rm|*'}).Count -eq 1) 'image-post-rm-only-one-removal'
    }
    $m=New-ImageModel;Claim-ImageModel $m;$m.Gone=$true
    Remove-AuditDataImage $m.Context
    Check ((Test-AuditDataImageClosed $m.Context) -and @($m.Calls|Where-Object {$_ -like 'image|rm|*'}).Count -eq 0) 'known-image-already-absent-no-rm'
    # A closed native-call profile prepares OS lifetime integration; no OS claim is made here.
    function New-HistoricalProfileModel {
        $c=Context $directory;$c.LifetimeSeconds=660;$c.ProbeHash='e'*64;$c.ImageClaimed=$false
        $client=[object]::new()
        [Fleetory.Pilot.AuditHistoricalProbeProfile]::Begin($c,$client)
        $imageReply=[Tuple[int,byte[],byte[]]]::new(0,[Text.Encoding]::ASCII.GetBytes('sha256:'+('d'*64)+"`n"),[byte[]]::new(0))
        $image=[Func[Tuple[int,byte[],byte[]]]]{return $imageReply}.GetNewClosure()
        $null=[Fleetory.Pilot.AuditImageCustody]::Build($c,$client,[byte[]]@(1,2,3),$image)
        $nonce=[Guid]::NewGuid().ToString('D')
        $s=@{Id=$null;Session=$nonce;Name=('fleetory-immu-store-'+$nonce.Replace('-',''));Started=[DateTimeOffset]::UtcNow;Role='target'}
        $c.Stores.Add($s)
        $create=[Func[Tuple[int,byte[],byte[]]]]{return [Tuple[int,byte[],byte[]]]::new(0,[Text.Encoding]::ASCII.GetBytes(('a'*64)+"`n"),[byte[]]::new(0))}
        $null=[Fleetory.Pilot.AuditContainerCustody]::Create($c,$s,$client,$create)
        return @{Context=$c;Store=$s;Client=$client;Calls=0;Throw=$false;MutateInput=$false;MutateArgs=$false;MutateStore=$false;LargeOutput=$false;LargeError=$false;
            NullReply=$false;Reply=[Tuple[int,byte[],byte[]]]::new(0,[Text.Encoding]::UTF8.GetBytes('{"category":"model"}'),[byte[]]::new(0));Delivery=$null}
    }
    function Invoke-HistoricalProfileModel($Model,[string]$ProbeMode='audit-health',[byte[]]$Bytes=([Text.Encoding]::UTF8.GetBytes('{"generated":"private"}'))){
        $expectedId=$Model.Store.Id;$before=$Model.Calls
        $operation=[Func[string[],byte[],Tuple[int,byte[],byte[]]]]{param([string[]]$Arguments,[byte[]]$InputBytes)
            $Model.Calls++;$Model.Delivery=$InputBytes;$Model.Arguments=[string[]]$Arguments.Clone()
            if($Model.Throw){throw 'Generated native transport loss.'}
            if($Model.MutateInput){$InputBytes[0]=$InputBytes[0] -bxor 1}
            if($Model.MutateArgs){$Arguments[-1]='foreign-mode'}
            if($Model.MutateStore){$Model.Store.Id='b'*64}
            if($Model.LargeOutput){return [Tuple[int,byte[],byte[]]]::new(0,[byte[]]::new(262145),[byte[]]::new(0))}
            if($Model.LargeError){return [Tuple[int,byte[],byte[]]]::new(0,[byte[]]::new(0),[byte[]]::new(4097))}
            if($Model.NullReply){return $null}
            return $Model.Reply
        }.GetNewClosure()
        try{return [Fleetory.Pilot.AuditHistoricalProbeProfile]::Invoke($Model.Context,$Model.Store,$Model.Client,$ProbeMode,$Bytes,$operation)}
        finally{
            if($Model.Calls -gt $before){
                $Arguments=$Model.Arguments
                $managedPrefix=if($ProbeMode -ceq 'observation-history-read'){'--historical-supervise|'}else{''}
                Check (($Arguments -join '|') -ceq ('exec|-i|-e|SSL_CERT_FILE=/tmp/ca.pem|-e|SSL_CERT_DIR=/tmp/empty-ca-dir|'+$expectedId+'|dotnet|/tool/ServerBackendProbe.dll|'+$managedPrefix+$ProbeMode)) 'historical-fixed-argv'
            }
        }
    }
    $m=New-HistoricalProfileModel;$original=[Text.Encoding]::UTF8.GetBytes('{"generated":"private"}');$frozen=$original.Clone()
    foreach($ProbeMode in @('audit-health','history-users','observation-history-read','observation-reader-denial')){
        $reply=Invoke-HistoricalProfileModel $m $ProbeMode $original
        Check ($reply.Item1 -eq 0 -and [Text.Encoding]::UTF8.GetString($reply.Item2) -ceq '{"category":"model"}') 'historical-opaque-native-reply'
        Check ([Convert]::ToHexString($original) -ceq [Convert]::ToHexString($frozen)) 'historical-original-request-unchanged'
        Check (@($m.Delivery|Where-Object {$_ -ne 0}).Count -eq 0) 'historical-private-delivery-cleared'
    }
    $reply.Item2[0]=0;Check ($m.Reply.Item2[0] -eq 123) 'historical-returned-reply-is-copy'
    Check ([Fleetory.Pilot.AuditHistoricalProbeProfile]::Calls($m.Context,$m.Client) -eq 4) 'historical-count-retained'
    Refused {[Fleetory.Pilot.AuditHistoricalProbeProfile]::Begin($m.Context,$m.Client)} 'historical-begin-cannot-reset'
    foreach($ProbeMode in @('','AUDIT-HEALTH','history-seed','audit-publish','restore','/bin/sh','--help')){
        Refused {Invoke-HistoricalProfileModel $m $ProbeMode} 'historical-arbitrary-command-refused'
    }
    foreach($size in @(0,131073)){
        Refused {Invoke-HistoricalProfileModel $m 'audit-health' ([byte[]]::new($size))} 'historical-request-bound'
    }
    Check ($m.Calls -eq 4) 'historical-invalid-calls-never-enter-native'
    foreach($kind in @('context','store','client','root','image','role','lifetime')){
        $m=New-HistoricalProfileModel;$c=$m.Context;$s=$m.Store;$client=$m.Client
        switch($kind){'context'{$m.Context=$c.Clone()};'store'{$m.Store=$s.Clone()};'client'{$m.Client=[object]::new()};'root'{$c.Root='foreign'};
            'image'{$c.ImageId='sha256:'+('b'*64)};'role'{$s.Role='source'};'lifetime'{$c.LifetimeSeconds=3300}}
        Refused {Invoke-HistoricalProfileModel $m} 'historical-original-live-objects-required'
        Check ($m.Calls -eq 0) 'historical-foreign-context-no-native-operation'
    }
    foreach($kind in @('Throw','MutateInput','MutateArgs','MutateStore','LargeOutput','LargeError','NullReply')){
        $m=New-HistoricalProfileModel;$m[$kind]=$true;$originalId=$m.Store.Id
        Refused {Invoke-HistoricalProfileModel $m} 'historical-unknown-native-outcome'
        Check ($m.Calls -eq 1) 'historical-unknown-attempt-consumed-before-native'
        $m[$kind]=$false;$m.Store.Id=$originalId
        Refused {Invoke-HistoricalProfileModel $m} 'historical-no-next-call-after-unknown'
        Refused {[Fleetory.Pilot.AuditHistoricalProbeProfile]::Begin($m.Context,$m.Client)} 'historical-unknown-profile-not-renewed'
        Check ($m.Calls -eq 1 -and [Fleetory.Pilot.AuditContainerCustody]::Id($m.Context,$m.Store,$m.Client) -ceq $originalId) 'historical-failure-preserves-cleanup-authority'
        Check (@($m.Delivery|Where-Object {$_ -ne 0}).Count -eq 0) 'historical-failed-delivery-cleared'
    }
    $m=New-HistoricalProfileModel
    for($n=0;$n -lt 64;$n++){$null=Invoke-HistoricalProfileModel $m}
    Refused {Invoke-HistoricalProfileModel $m} 'historical-native-call-count-bound'
    Check ($m.Calls -eq 64) 'historical-count-bound-before-native'
    $script:imageModel=$null
    $script:custodyModel=$null
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
Write-Output ('AUDIT RESOURCE OWNERSHIP PASS:'+ $count +' assertions;exclusive claim,foreign preservation,atomic publication,100 concurrent replacements,live raw container/image replies,untagged build,no-prune,closed historical probe profile and consumed attempts.')
$global:LASTEXITCODE=0
