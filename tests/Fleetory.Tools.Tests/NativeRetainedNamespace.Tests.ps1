#requires -Version 7.3
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$repo=Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
foreach($helper in @('PilotNativeProcess.ps1','../../eng/pilot/ProviderRecoveryPolicy.ps1','../../eng/pilot/ProviderRecoveryTransport.ps1',
    '../../eng/pilot/ImmuDataRoundtripPolicy.ps1','NativeSignerFixture.ps1','NativeJournalFixture.ps1',
    'NativeAuditFixture.ps1','NativeAuditDataFixture.ps1','../../eng/pilot/historical/RetainedAuditNamespace.ps1')){
    . (Join-Path $PSScriptRoot $helper)
}
$clock=[Diagnostics.Stopwatch]::StartNew();$cleaning=$false;$nativeMeter=@{calls=0}
function Invoke-Docker([string[]]$Arguments,[byte[]]$InputBytes=$null,[int]$TimeoutSeconds=60,[switch]$AllowFailure){
    Assert-ImmuData ($cleaning -or $clock.Elapsed.TotalSeconds -lt 240) 'namespace-fixture-deadline'
    $nativeMeter.calls++
    $reply=if($IsLinux){Invoke-NativeBytes '/bin/sh' @('-c',(Get-ProviderDockerShellCommand $Arguments -ClassicBuilder:($Arguments[0] -ceq 'build'))) $InputBytes $TimeoutSeconds}
        else{Invoke-NativeBytes 'docker' (@('--context','desktop-linux')+$Arguments) $InputBytes $TimeoutSeconds}
    if(-not $AllowFailure){Assert-ImmuData ($reply.ExitCode -eq 0) 'namespace-docker-operation'}
    return $reply
}
function Remove-NamespaceStore($Context,$Store){
    if($null -eq $Store.Id -or [Fleetory.Pilot.AuditContainerCustody]::Closed($Context,$Store,${function:Invoke-Docker})){return}
    $id=[Fleetory.Pilot.AuditContainerCustody]::Id($Context,$Store,${function:Invoke-Docker})
    $null=Invoke-AuditDataContainerOperation $Context $Store 'Remove' @('rm','--force',$id)
    $null=Invoke-AuditDataContainerOperation $Context $Store 'ConfirmRemoval' @('inspect',$id)
}
$session=[Guid]::NewGuid().ToString('D');$root=Join-Path $repo ('artifacts/retained-namespace-'+$session)
$imageContext=@{Fixture=$session;Root=$root;ImageName='retained-namespace';ProbeHash=('0'*64);ImageId=$null;ImageClaimed=$false}
$parents=[Collections.Generic.List[object]]::new();$children=[Collections.Generic.List[object]]::new();$results=@()
$oldBuildKit=$env:DOCKER_BUILDKIT;$env:DOCKER_BUILDKIT='0'
try{
    $null=New-Item -ItemType Directory -Path $root
    $dockerfile="FROM $script:nativeAuditSourceImage AS upstream`nFROM $script:nativeSignerImage`nCOPY --from=upstream /usr/sbin/immudb /usr/sbin/immudb`nLABEL fleetory.retained-namespace.build=$session`nUSER 3322:3322`n"
    [IO.File]::WriteAllText((Join-Path $root 'Dockerfile'),$dockerfile,[Text.UTF8Encoding]::new($false))
    $tar=Invoke-NativeBytes 'tar' @('-cf','-','-C',$root,'Dockerfile') -TimeoutSeconds 10
    Assert-ImmuData ($tar.ExitCode -eq 0 -and $tar.StdoutBytes.Length -le 65536) 'namespace-public-build-context'
    $native=New-AuditDataNativeCall @('build','--quiet','--network','none','--pull=false','-') $tar.StdoutBytes
    $null=[Fleetory.Pilot.AuditImageCustody]::Build($imageContext,$native.Client,$tar.StdoutBytes,$native.Invoke)
    $pgImage=@((Invoke-Docker @('image','inspect',$script:nativeJournalImage)).Stdout|ConvertFrom-Json -AsHashtable)[0].Id
    foreach($flow in @('reverse-cleanup','parent-removed','parent-stopped')){
        $nonce=[Guid]::NewGuid().ToString('D')
        $parentContext=@{Fixture=$nonce;ImageName=$script:nativeJournalImage;ImageId=$pgImage;LifetimeSeconds=3300;Stores=[Collections.Generic.List[object]]::new()}
        $parent=@{Session=$nonce;Name=('fleetory-native-journal-'+$nonce.Replace('-',''));Role='retained-postgres-target';Started=[DateTimeOffset]::UtcNow;Id=$null}
        $parentContext.Stores.Add($parent);$parents.Add(@{Context=$parentContext;Store=$parent})
        $parent.Id=Invoke-AuditDataContainerOperation $parentContext $parent 'Create' (Get-NativeJournalArguments $nonce)
        $context=New-RetainedAuditNamespace $parentContext $parent $imageContext
        $store=@{Session=$context.Fixture;Name=('fleetory-retained-audit-'+$context.Fixture.Replace('-',''));Role='retained-coupled-audit';Started=[DateTimeOffset]::UtcNow;Id=$null}
        $context.Stores.Add($store);$children.Add(@{Context=$context;Store=$store})
        $refused=0
        $beforeRefusals=$nativeMeter.calls
        foreach($bad in @($context.Clone(),@{Fixture=$context.Fixture;ImageName=$context.ImageName;ImageId=$context.ImageId;LifetimeSeconds=3300;Stores=$context.Stores})){
            try{$null=Get-RetainedAuditNamespace $bad}catch{if($_.Exception.GetBaseException() -isnot [InvalidOperationException]){throw};$refused++;continue}
            throw 'Copied namespace context accepted.'
        }
        foreach($claim in @(@{parent=$parentContext.Clone();image=$imageContext},@{parent=$parentContext;image=$imageContext.Clone()})){
            try{$null=New-RetainedAuditNamespace $claim.parent $parent $claim.image}catch{if($_.Exception.GetBaseException() -isnot [InvalidOperationException]){throw};$refused++;continue}
            throw 'Copied upstream custody accepted.'
        }
        Assert-ImmuData ($refused -eq 4 -and $nativeMeter.calls -eq $beforeRefusals) 'namespace-copy-refused-before-native'
        $store.Id=Invoke-AuditDataContainerOperation $context $store 'Create' (Get-RetainedAuditArguments $context $store)
        $null=Read-RetainedAuditNamespace $context $store
        # Each process sees the same isolated network namespace, without opening service ports.
        $parentNet=(Invoke-Docker @('exec',$parent.Id,'readlink','/proc/self/ns/net')).Stdout.Trim()
        $childNet=(Invoke-Docker @('exec',$store.Id,'readlink','/proc/self/ns/net')).Stdout.Trim()
        Assert-ImmuData ($parentNet -ceq $childNet -and $parentNet -cmatch '^net:\[[0-9]+\]$') 'namespace-kernel-identity'
        $parentLossRefused=$false
        if($flow -ceq 'parent-removed'){
            Remove-NamespaceStore $parentContext $parent
            try{$null=Read-RetainedAuditNamespace $context $store}catch{if($_.Exception.GetBaseException() -isnot [InvalidOperationException]){throw};$parentLossRefused=$true}
            Assert-ImmuData $parentLossRefused 'namespace-dead-parent-work-refusal'
        }elseif($flow -ceq 'parent-stopped'){
            # Stop removes this --rm parent without closing its in-process claim: native liveness must also be checked.
            $null=Invoke-Docker @('stop','--time','0',$parent.Id)
            try{$null=Read-RetainedAuditNamespace $context $store}catch{$parentLossRefused=$true}
            Assert-ImmuData $parentLossRefused 'namespace-absent-parent-work-refusal'
            $null=Invoke-AuditDataContainerOperation $parentContext $parent 'Inspect' @('inspect',$parent.Id)
            [Fleetory.Pilot.AuditContainerCustody]::Absent($parentContext,$parent,${function:Invoke-Docker})
        }
        $null=Read-RetainedAuditNamespace $context $store -CleanupOnly
        Remove-NamespaceStore $context $store
        Remove-NamespaceStore $parentContext $parent
        $results+=@{flow=$flow;copiedContextsRefused=$refused;kernelNamespaceEqual=$true;parentLossWorkRefused=$parentLossRefused;
            childId=$store.Id;parentId=$parent.Id;childCleanupVerified=$true;parentCleanupVerified=$true}
    }
}finally{
    $cleaning=$true
    try{
        foreach($child in $children){Remove-NamespaceStore $child.Context $child.Store}
    }finally{
        try{foreach($parent in $parents){Remove-NamespaceStore $parent.Context $parent.Store}}
        finally{
            try{
                if($null -ne $imageContext.ImageId){
                    $native=New-AuditDataNativeCall @('image','rm','--no-prune',$imageContext.ImageId)
                    [Fleetory.Pilot.AuditImageCustody]::Remove($imageContext,$native.Client,$native.Invoke)
                    $native=New-AuditDataNativeCall @('image','inspect',$imageContext.ImageId)
                    [Fleetory.Pilot.AuditImageCustody]::ConfirmRemoval($imageContext,$native.Client,$native.Invoke)
                }
            }finally{$env:DOCKER_BUILDKIT=$oldBuildKit}
        }
    }
}
@{schema='fleetory.native-retained-audit-namespace.v1';verified=$true;cases=$results;ownImageId=$imageContext.ImageId;ownImageRemoved=$true;
    nativeDataRestored=$false;serverStarted=$false;originalInputsRead=$false;originalPkiUsed=$false;
    controllerDeathCleanupVerified=$false;unknownCreateOutcomeRecoveryVerified=$false;fullSystemRecoveryVerified=$false;phase7Complete=$false}|ConvertTo-Json -Depth 8 -Compress
