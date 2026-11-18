# Generated-only fault witness. The complete Docker reply and live claim stay here until removal.
function Write-HistoricalWitnessFrame($Output,$Token,$Value){
    $bytes=[Text.Encoding]::UTF8.GetBytes(($Value|ConvertTo-Json -Compress -Depth 4))
    Send-IndependentFrame $Output $bytes $Token
}

function Invoke-HistoricalCreateWitness([string]$RequestSha256){
    $deadline=[Threading.CancellationTokenSource]::new([TimeSpan]::FromSeconds(42))
    $inputStream=[Console]::OpenStandardInput();$outputStream=[Console]::OpenStandardOutput()
    $stack=$null;$owned=$null;$native=@{Reply=$null}
    try{
        $token=$deadline.Token
        $raw=Read-IndependentFrame $inputStream $token 512
        Assert-ImmuData ((Get-ImmuDataHash ([Text.Encoding]::UTF8.GetBytes($raw))) -ceq $RequestSha256) 'create-witness-pin'
        $request=$raw|ConvertFrom-Json -AsHashtable -Depth 3
        Assert-ImmuData ($request.Count -eq 5 -and $request.fault -cin @('lost','truncated') -and
            $request.imageId -cmatch '^sha256:[a-f0-9]{64}\z') 'create-witness-request'
        foreach($value in @($request.nonce,$request.fixture,$request.session)){
            $parsed=[Guid]::Empty
            Assert-ImmuData ($value -is [string] -and [Guid]::TryParseExact($value,'D',[ref]$parsed) -and
                $parsed -ne [Guid]::Empty -and $parsed.ToString('D') -ceq $value) 'create-witness-nonce'
        }
        $image=Invoke-Docker @('image','inspect','--format','{{.Id}}|{{.Config.User}}|{{index .Config.Labels "fleetory.immu-data.build"}}',$request.imageId)
        Assert-ImmuData ($image.Stdout.Trim() -ceq ($request.imageId+'|3322:3322|'+$request.fixture)) 'create-witness-image'
        $stack=@{Fixture=$request.fixture;ImageId=$request.imageId;ImageName=(Get-ImmuDataImageName $request.fixture);
            LifetimeSeconds=660;Stores=[Collections.Generic.List[object]]::new()}
        $owned=@{Id=$null;Session=$request.session;Name=('fleetory-immu-store-'+$request.session.Replace('-',''));Started=[DateTimeOffset]::UtcNow;Role='target'}
        $null=Assert-FreshAuditDataStoreName $owned.Name
        $stack.Stores.Add($owned)
        $client=${function:Invoke-Docker}
        $arguments=Get-AuditDataStoreArguments $stack $owned $request.imageId
        $create=[Func[Tuple[int,byte[],byte[]]]]{
            $native.Reply=& $client $arguments $null 20 -AllowFailure
            return [Tuple[int,byte[],byte[]]]::new($native.Reply.ExitCode,$native.Reply.StdoutBytes,$native.Reply.StderrBytes)
        }.GetNewClosure()
        $id=[Fleetory.Pilot.AuditContainerCustody]::Create($stack,$owned,$client,$create)
        Read-AuditDataStore $stack $owned
        $replyPin=Get-ImmuDataHash $native.Reply.StdoutBytes
        $prefix=if($request.fault -ceq 'truncated'){[Convert]::ToBase64String([byte[]]$native.Reply.StdoutBytes[0..11])}
        Write-HistoricalWitnessFrame $outputStream $token @{stage='created';nonce=$request.nonce;pid=$PID;replySha256=$replyPin;prefix=$prefix}
        $dispose=Read-IndependentFrame $inputStream $token 96
        Assert-ImmuData ($dispose -ceq ('dispose:'+$request.nonce)) 'create-witness-dispose'
        $last=[byte[]]::new(1)
        $count=$inputStream.ReadAsync($last,0,1,$token).WaitAsync($token).GetAwaiter().GetResult()
        Assert-ImmuData ($count -eq 0) 'create-witness-trailing'
    }finally{
        try{
            if($null -ne $owned -and $null -ne $owned.Id){
                Remove-AuditDataStore $stack $owned
                Assert-ImmuData (Test-AuditDataStoreClosed $stack $owned) 'create-witness-owned-absence'
            }
        }finally{$deadline.Dispose()}
    }
    $terminal=[Threading.CancellationTokenSource]::new([TimeSpan]::FromSeconds(3))
    try{
        Write-HistoricalWitnessFrame $outputStream $terminal.Token @{stage='closed';nonce=$request.nonce;pid=$PID;id=$id;
            nativeReply=[Convert]::ToBase64String($native.Reply.StdoutBytes)}
    }finally{$terminal.Dispose()}
}

function Open-HistoricalCreateWitness($Request){
    $bytes=[Text.Encoding]::UTF8.GetBytes(($Request|ConvertTo-Json -Compress))
    $start=[Diagnostics.ProcessStartInfo]::new([Environment]::ProcessPath)
    $start.UseShellExecute=$false;$start.CreateNoWindow=$true
    $start.RedirectStandardInput=$true;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
    $start.Environment.Clear()
    foreach($name in @('PATH','SystemRoot','WINDIR','HOME','USERPROFILE','APPDATA','LOCALAPPDATA','ProgramData','TEMP','TMP','TMPDIR')){
        $value=[Environment]::GetEnvironmentVariable($name)
        if($null -ne $value){$start.Environment[$name]=$value}
    }
    foreach($part in @('-NoLogo','-NoProfile','-NonInteractive','-File',(Join-Path $PSScriptRoot 'Invoke-HistoricalAuditObservation.ps1'),
        '-ExpectedPlanSha256',(Get-ImmuDataHash $bytes),'-GeneratedCreateWitness')){
        $start.ArgumentList.Add($part)
    }
    $deadline=[Threading.CancellationTokenSource]::new([TimeSpan]::FromSeconds(39))
    $peer=@{process=$null;input=$null;output=$null;cancel=$deadline;ack=$null;closed=$false}
    try{
        $peer.process=[Diagnostics.Process]::Start($start)
        Assert-ImmuData ($null -ne $peer.process -and $peer.process.Id -ne $PID) 'create-witness-process'
        $peer.input=$peer.process.StandardInput.BaseStream;$peer.output=$peer.process.StandardOutput.BaseStream
        Send-IndependentFrame $peer.input $bytes $deadline.Token
        $ack=(Read-IndependentFrame $peer.output $deadline.Token 512)|ConvertFrom-Json -AsHashtable -Depth 3
        Assert-ImmuData ($ack.Count -eq 5 -and $ack.stage -ceq 'created' -and $ack.nonce -ceq $Request.nonce -and
            $ack.pid -eq $peer.process.Id -and $ack.replySha256 -cmatch '^[a-f0-9]{64}\z') 'create-witness-ack'
        if($Request.fault -ceq 'truncated'){
            $prefix=[Convert]::FromBase64String($ack.prefix)
            Assert-ImmuData ($prefix.Length -eq 12 -and [Text.Encoding]::ASCII.GetString($prefix) -cmatch '^[a-f0-9]{12}\z') 'create-witness-prefix'
        }else{
            Assert-ImmuData ($null -eq $ack.prefix) 'create-witness-withheld'
        }
        $peer.ack=$ack
        return $peer
    }catch{
        Close-HistoricalCreateWitness $peer
        throw
    }
}

function Close-HistoricalCreateWitness($Peer){
    if($null -eq $Peer){return}
    try{
        if($null -ne $Peer.process){
            try{$Peer.process.StandardInput.Close()}catch{}
            if(-not $Peer.process.HasExited){$null=$Peer.process.WaitForExit(4500)}
            $Peer.process.Dispose()
        }
    }finally{$Peer.cancel.Dispose()}
}

function Complete-HistoricalCreateWitness($Peer,$Request){
    $token=$Peer.cancel.Token
    Send-IndependentFrame $Peer.input ([Text.Encoding]::ASCII.GetBytes(('dispose:'+$Request.nonce))) $token
    $Peer.input.Dispose()
    $closed=(Read-IndependentFrame $Peer.output $token 512)|ConvertFrom-Json -AsHashtable -Depth 3
    $null=$Peer.process.WaitForExitAsync($token).GetAwaiter().GetResult()
    Assert-ImmuData ($Peer.process.ExitCode -eq 0 -and $Peer.output.ReadByte() -eq -1 -and
        $Peer.process.StandardError.BaseStream.ReadByte() -eq -1 -and $closed.Count -eq 5 -and
        $closed.stage -ceq 'closed' -and $closed.nonce -ceq $Request.nonce -and $closed.pid -eq $Peer.process.Id -and
        $closed.id -cmatch '^[a-f0-9]{64}\z') 'create-witness-close'
    $native=[Convert]::FromBase64String($closed.nativeReply)
    $decoded=[Text.Encoding]::ASCII.GetString($native)
    Assert-ImmuData ((Get-ImmuDataHash $native) -ceq $Peer.ack.replySha256 -and
        ($decoded -ceq ($closed.id+[char]10) -or $decoded -ceq ($closed.id+[char]13+[char]10))) 'create-witness-complete-reply'
    if($Request.fault -ceq 'truncated'){
        Assert-ImmuData ($Peer.ack.prefix -ceq [Convert]::ToBase64String([byte[]]$native[0..11])) 'create-witness-truncated-reply'
    }
    $Peer.closed=$true
    return @{id=$closed.id;native=$native}
}

function Assert-HistoricalUnknownCreate($Context,$Store){
    $before=$script:nativeDockerCalls
    $refused=$false
    try{Remove-AuditDataStore $Context $Store}catch{
        if($_.Exception.GetBaseException().Message -cne 'Audit container live custody refused: outcome.'){throw}
        $refused=$true
    }
    Assert-ImmuData ($refused -and $script:nativeDockerCalls -eq $before -and $null -eq $Store.Id) 'create-unknown-removal'
}

function Assert-HistoricalLateCreate($Context,$Store,[byte[]]$NativeReply){
    $before=$script:nativeDockerCalls
    $late=@{calls=0}
    $operation=[Func[Tuple[int,byte[],byte[]]]]{
        $late.calls++
        return [Tuple[int,byte[],byte[]]]::new(0,$NativeReply,[byte[]]@())
    }.GetNewClosure()
    $refused=$false
    try{$null=[Fleetory.Pilot.AuditContainerCustody]::Create($Context,$Store,${function:Invoke-Docker},$operation)}
    catch{
        if($_.Exception.GetBaseException() -isnot [ArgumentException]){throw}
        $refused=$true
    }
    Assert-ImmuData ($refused -and $late.calls -eq 0 -and $script:nativeDockerCalls -eq $before -and $null -eq $Store.Id) 'create-late-reply'
}

function Invoke-HistoricalRoutedCreateFault($Peer,[ValidateSet('lost','truncated')][string]$Fault){
    $attempt=New-AuditDataStoreIntent $context 'target' -WitnessChecksName
    $image=[Fleetory.Pilot.AuditImageCustody]::Id($context,${function:Invoke-Docker})
    $request=@{nonce=$plan.nonce;fixture=$context.Fixture;imageId=$image;session=$attempt.Session;fault=$Fault}
    $open=${function:Open-HistoricalCreateWitness}
    $call=@{witness=$null;count=0}
    $operation=[Func[Tuple[int,byte[],byte[]]]]{
        $call.count++
        $call.witness=& $open $request
        if($Fault -ceq 'lost'){return $null}
        return [Tuple[int,byte[],byte[]]]::new(0,[Convert]::FromBase64String($call.witness.ack.prefix),[byte[]]@())
    }.GetNewClosure()
    try{
        $refused=$false
        try{$null=[Fleetory.Pilot.AuditContainerCustody]::Create($context,$attempt,${function:Invoke-Docker},$operation)}
        catch{
            $expected=if($Fault -ceq 'lost'){'Audit native reply refused.'}else{'Audit native ID reply refused.'}
            if($_.Exception.GetBaseException().Message -cne $expected){throw}
            $refused=$true
        }
        Assert-ImmuData ($refused -and $call.count -eq 1 -and $null -ne $call.witness -and -not $call.witness.process.HasExited) 'create-routed-fault'
        Assert-HistoricalUnknownCreate $context $attempt
        $proof=Complete-HistoricalCoordinatorCreateRefusal $Peer
        $closed=Complete-HistoricalCreateWitness $call.witness $request
        Assert-HistoricalLateCreate $context $attempt $closed.native
        $attempt.Id=$closed.id
        try{
            $before=$script:nativeDockerCalls
            $rejected=$false
            try{Remove-AuditDataStore $context $attempt}catch{
                if($_.Exception.GetBaseException().Message -cne 'Audit container live custody refused: store-id.'){throw}
                $rejected=$true
            }
            Assert-ImmuData ($rejected -and $script:nativeDockerCalls -eq $before) 'create-late-adoption'
        }finally{$attempt.Id=$null}
        return @{coordinator=$proof;fault=$Fault;witnessPid=$call.witness.process.Id;containerId=$closed.id;
            createDispatches=$call.count;replySeenOnlyAfterCleanup=$true;unknownCleanupRefused=$true;lateReplyRefused=$true;
            idAdoptionRefused=$true;witnessOwnedAbsenceVerified=$true}
    }finally{
        try{
            if($null -ne $call.witness -and $call.witness.closed){
                # Drop only the failed descriptor. Its consumed claim never becomes cleanup authority.
                Assert-ImmuData ($null -eq $attempt.Id -and $context.Stores.Remove($attempt)) 'create-unknown-descriptor'
            }
        }finally{Close-HistoricalCreateWitness $call.witness}
    }
}
