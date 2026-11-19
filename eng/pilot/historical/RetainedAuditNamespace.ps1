#requires -Version 7.3
# Distinct coupled profile. IDs come from live native custody, never manifest fields.
if(-not ('Fleetory.Pilot.RetainedAuditNamespace' -as [type])){
    Add-Type -TypeDefinition @'
namespace Fleetory.Pilot {
    public static class RetainedAuditNamespace {
        private sealed class Link {
            internal readonly object Context, Client, ParentContext, ParentStore, ImageContext;
            internal readonly int Process=System.Environment.ProcessId;
            internal Link(object context,object client,object parentContext,object parentStore,object imageContext) {
                Context=context;Client=client;ParentContext=parentContext;ParentStore=parentStore;ImageContext=imageContext;
            }
        }
        private static readonly System.Runtime.CompilerServices.ConditionalWeakTable<object,Link> Links=new();
        public static void Bind(object context,object client,object parentContext,object parentStore,object imageContext) {
            if(context==null || client==null || parentContext==null || parentStore==null || imageContext==null)
                throw new System.InvalidOperationException("Retained namespace link refused.");
            Links.Add(context,new Link(context,client,parentContext,parentStore,imageContext));
        }
        public static object[] Read(object context,object client) {
            if(!Links.TryGetValue(context,out var link) || !object.ReferenceEquals(link.Context,context) ||
                !object.ReferenceEquals(link.Client,client) || link.Process!=System.Environment.ProcessId)
                throw new System.InvalidOperationException("Retained namespace live link refused.");
            return new object[]{link.ParentContext,link.ParentStore,link.ImageContext};
        }
    }
}
'@
}
function New-RetainedAuditNamespace($ParentContext,$ParentStore,$ImageContext){
    $client=${function:Invoke-Docker}
    $parent=[Fleetory.Pilot.AuditContainerCustody]::Id($ParentContext,$ParentStore,$client)
    $image=[Fleetory.Pilot.AuditImageCustody]::Id($ImageContext,$client)
    Assert-ImmuData ($parent -cmatch '^[a-f0-9]{64}\z' -and $image -cmatch '^sha256:[a-f0-9]{64}\z') 'retained-namespace-native-ids'
    $context=@{Fixture=[Guid]::NewGuid().ToString('D');ImageName=$image;ImageId=$image;LifetimeSeconds=3300;
        Stores=[Collections.Generic.List[object]]::new()}
    [Fleetory.Pilot.RetainedAuditNamespace]::Bind($context,$client,$ParentContext,$ParentStore,$ImageContext)
    return $context
}
function Get-RetainedAuditNamespace($Context){
    $client=${function:Invoke-Docker}
    $link=[Fleetory.Pilot.RetainedAuditNamespace]::Read($Context,$client)
    $parent=[Fleetory.Pilot.AuditContainerCustody]::Id($link[0],$link[1],$client)
    $image=[Fleetory.Pilot.AuditImageCustody]::Id($link[2],$client)
    Assert-ImmuData ($Context.ImageId -ceq $image -and $Context.ImageName -ceq $image -and
        $Context.LifetimeSeconds -eq 3300) 'retained-namespace-image'
    $reply=Invoke-AuditDataContainerOperation $link[0] $link[1] 'Inspect' @('inspect',$parent)
    Assert-ImmuData ($reply.ExitCode -eq 0) 'retained-namespace-parent-inspect'
    $items=@($reply.Stdout|ConvertFrom-Json -AsHashtable -Depth 32)
    Assert-ImmuData ($items.Count -eq 1) 'retained-namespace-parent-single-object'
    Assert-NativeJournal $items[0] $parent $link[1].Session $link[0].ImageId $link[1].Started
    return @{ParentId=$parent;ImageId=$image;ParentContext=$link[0];ParentStore=$link[1]}
}
function Get-RetainedAuditArguments($Context,$Store){
    $link=Get-RetainedAuditNamespace $Context
    Assert-ImmuData ($Store.Session -ceq $Context.Fixture -and $Store.Role -ceq 'retained-coupled-audit' -and
        $Store.Name -ceq ('fleetory-retained-audit-'+$Context.Fixture.Replace('-',''))) 'retained-namespace-store'
    return @('run','-d','--rm','--name',$Store.Name,'--label',('fleetory.retained-audit.session='+$Store.Session),
        '--network',('container:'+$link.ParentId),'--read-only','--user','3322:3322','--cap-drop','ALL','--security-opt','no-new-privileges',
        '--memory','384m','--cpus','1','--pids-limit','128','--ulimit','core=0',
        '--tmpfs',('/data:'+$script:nativeAuditTmpfs['/data']),'--tmpfs',('/tmp:'+$script:nativeAuditTmpfs['/tmp']),
        '--tmpfs',('/run/fleetory-native:'+$script:nativeAuditPairSecretsTmpfs),
        '--entrypoint','/bin/sh',$link.ImageId,'-c','exec /bin/sleep 3300')
}
function Read-RetainedAuditNamespace($Context,$Store,[switch]$CleanupOnly){
    # Cleanup deliberately does not require a live parent; the child creator still owns its own ID.
    $id=[Fleetory.Pilot.AuditContainerCustody]::Id($Context,$Store,${function:Invoke-Docker})
    $link=if(-not $CleanupOnly){Get-RetainedAuditNamespace $Context}else{$null}
    $reply=Invoke-AuditDataContainerOperation $Context $Store 'Inspect' @('inspect',$id)
    Assert-ImmuData ($reply.ExitCode -eq 0) 'retained-namespace-inspect'
    $items=@($reply.Stdout|ConvertFrom-Json -AsHashtable -Depth 32)
    Assert-ImmuData ($items.Count -eq 1) 'retained-namespace-single-object'
    $info=$items[0];$created=ConvertTo-ProviderTimestamp $info.Created
    Assert-ImmuData ($info.Id -ceq $id -and $info.Name -ceq ('/'+$Store.Name) -and
        $info.Config.Image -ceq $Context.ImageId -and $info.Image -ceq $Context.ImageId -and
        $info.Config.Labels['fleetory.retained-audit.session'] -ceq $Store.Session -and
        $created -ge $Store.Started -and $created -le [DateTimeOffset]::UtcNow.AddSeconds(5)) 'retained-namespace-ownership'
    if($CleanupOnly){return $id}
    Assert-NativeStoreRuntime $info '3322:3322' 'audit'
    Assert-ImmuData ($info.HostConfig.NetworkMode -ceq ('container:'+$link.ParentId) -and
        @($info.NetworkSettings.Networks.Keys).Count -eq 0) 'retained-namespace-network'
    $tmpfs=$script:nativeAuditTmpfs.Clone();$tmpfs['/run/fleetory-native']=$script:nativeAuditPairSecretsTmpfs
    Assert-ImmuData ((@($info.HostConfig.Tmpfs.Keys|Sort-Object)-join '|') -ceq (@($tmpfs.Keys|Sort-Object)-join '|')) 'retained-namespace-tmpfs'
    foreach($path in $tmpfs.Keys){Assert-ImmuData ($info.HostConfig.Tmpfs[$path] -ceq $tmpfs[$path]) 'retained-namespace-tmpfs'}
    return $id
}
