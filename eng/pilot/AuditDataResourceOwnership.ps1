#requires -Version 7.3
# In-process claims and atomic resource metadata; neither authenticates a dead owner.
if(-not ('Fleetory.Pilot.ExclusiveAuditDirectory' -as [type])){
    Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Runtime.InteropServices;
namespace Fleetory.Pilot {
    // Live trusted caller only. No import, serialization or cross-process recovery API.
    public static class AuditContainerCustody {
        private sealed class Claim {
            internal readonly System.Collections.IDictionary Context, Store;
            internal readonly object Client, Stores;
            internal readonly object[] ContextValues, StoreValues;
            internal readonly int Process = Environment.ProcessId;
            internal Tuple<int, byte[], byte[]> Creation, Inspection, Removal;
            internal string Id;
            internal int State; // Unknown create, live, removal attempted, closed.
            internal Claim(System.Collections.IDictionary context, System.Collections.IDictionary store, object client) {
                Context=context; Store=store; Client=client; Stores=context["Stores"];
                ContextValues=Values(context, ContextKeys); StoreValues=Values(store, StoreKeys);
            }
        }
        private static readonly string[] ContextKeys = {"Fixture", "ImageName", "ImageId", "LifetimeSeconds"};
        private static readonly string[] StoreKeys = {"Session", "Name", "Role", "Started"};
        private static readonly System.Runtime.CompilerServices.ConditionalWeakTable<object, Claim> Claims = new();
        private static object[] Values(System.Collections.IDictionary source, string[] keys) {
            var values=new object[keys.Length];
            for(int n=0;n<keys.Length;n++) values[n]=source[keys[n]];
            return values;
        }
        private static bool Same(object[] left, object[] right) {
            for(int n=0;n<left.Length;n++) if(!Equals(left[n],right[n])) return false;
            return true;
        }
        private static InvalidOperationException Refused(string reason="reply") => new("Audit container live custody refused: "+reason+".");
        private static Claim Get(System.Collections.IDictionary context, System.Collections.IDictionary store, object client, bool live=true) {
            if(!Claims.TryGetValue(store,out var claim)) throw Refused("unclaimed-store");
            if(!ReferenceEquals(context,claim.Context) || !ReferenceEquals(store,claim.Store)) throw Refused("object-identity");
            if(!ReferenceEquals(client,claim.Client)) throw Refused("client-identity");
            if(!ReferenceEquals(context["Stores"],claim.Stores)) throw Refused("store-list");
            if(claim.Process!=Environment.ProcessId) throw Refused("process");
            if(!Same(Values(context,ContextKeys),claim.ContextValues) || !Same(Values(store,StoreKeys),claim.StoreValues)) throw Refused("metadata");
            if(!Equals(store["Id"],claim.Id)) throw Refused("store-id");
            if(live && System.Threading.Volatile.Read(ref claim.State)!=1) throw Refused("outcome");
            bool present=false;
            foreach(var item in (System.Collections.IEnumerable)claim.Stores) if(ReferenceEquals(item,store)) present=true;
            if(!present) throw Refused();
            return claim;
        }
        private static Tuple<int,byte[],byte[]> Hold(Tuple<int,byte[],byte[]> reply) {
            if(reply==null || reply.Item2==null || reply.Item3==null || reply.Item2.Length>67108864 || reply.Item3.Length>1048576) throw Refused();
            return Tuple.Create(reply.Item1,(byte[])reply.Item2.Clone(),(byte[])reply.Item3.Clone());
        }
        private static string CompleteId(Tuple<int,byte[],byte[]> reply) {
            byte[] raw=reply.Item2;
            if(reply.Item1!=0 || (raw.Length!=65 && raw.Length!=66) || raw[raw.Length-1]!=10 ||
                (raw.Length==66 && raw[64]!=13)) throw Refused();
            for(int n=0;n<64;n++) if(!((raw[n]>=48 && raw[n]<=57)||(raw[n]>=97 && raw[n]<=102))) throw Refused();
            return System.Text.Encoding.ASCII.GetString(raw,0,64);
        }
        public static string Create(System.Collections.IDictionary context, System.Collections.IDictionary store, object client,
            Func<Tuple<int,byte[],byte[]>> operation) {
            if(client==null || operation==null || store["Id"]!=null) throw Refused();
            var claim=new Claim(context,store,client);
            Claims.Add(store,claim); // Consumed before the native call, even on exception/unknown output.
            claim.Creation=Hold(operation());
            claim.Id=CompleteId(claim.Creation);
            store["Id"]=claim.Id;
            claim.State=1;
            return Get(context,store,client).Id;
        }
        public static string Id(System.Collections.IDictionary context, System.Collections.IDictionary store, object client) => Get(context,store,client).Id;
        public static bool Closed(System.Collections.IDictionary context, System.Collections.IDictionary store, object client) {
            var claim=Get(context,store,client,false);
            return System.Threading.Volatile.Read(ref claim.State)==3;
        }
        public static Tuple<int,byte[],byte[]> Inspect(System.Collections.IDictionary context, System.Collections.IDictionary store, object client,
            Func<Tuple<int,byte[],byte[]>> operation) {
            var claim=Get(context,store,client);
            claim.Inspection=Hold(operation());
            return Hold(claim.Inspection);
        }
        public static void Remove(System.Collections.IDictionary context, System.Collections.IDictionary store, object client,
            Func<Tuple<int,byte[],byte[]>> operation) {
            var claim=Get(context,store,client);
            if(System.Threading.Interlocked.CompareExchange(ref claim.State,2,1)!=1) throw Refused("outcome"); // Consume before the call.
            claim.Removal=Hold(operation());
            if(CompleteId(claim.Removal)!=claim.Id) throw Refused();
            claim.State=3;
        }
        public static void Absent(System.Collections.IDictionary context, System.Collections.IDictionary store, object client) {
            var claim=Get(context,store,client);
            if(claim.Inspection==null || claim.Inspection.Item1!=1) throw Refused();
            string output=System.Text.Encoding.UTF8.GetString(claim.Inspection.Item2);
            if(output!="" && output!="[]\n" && output!="[]\r\n") throw Refused("absence-output");
            string text=System.Text.Encoding.UTF8.GetString(claim.Inspection.Item3);
            if(!System.Text.RegularExpressions.Regex.IsMatch(text,@"\A(?:Error: )?no such (object|container): "+claim.Id+@"\r?\n?\z",
                System.Text.RegularExpressions.RegexOptions.IgnoreCase)) throw Refused();
            if(System.Threading.Interlocked.CompareExchange(ref claim.State,3,1)!=1) throw Refused("outcome");
        }
    }
    public static class ExclusiveAuditDirectory {
        [DllImport("kernel32.dll", EntryPoint="CreateDirectoryW", CharSet=CharSet.Unicode, SetLastError=true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CreateWindows(string path, IntPtr attributes);
        [DllImport("libc", EntryPoint="mkdir", SetLastError=true)]
        private static extern int CreateUnix([MarshalAs(UnmanagedType.LPUTF8Str)] string path, uint mode);
        public static void Create(string path) {
            bool created;
            if (OperatingSystem.IsWindows()) created = CreateWindows(path, IntPtr.Zero);
            else if (OperatingSystem.IsLinux()) created = CreateUnix(path, 448) == 0;
            else throw new PlatformNotSupportedException("Exclusive audit directory platform.");
            if (!created) throw new IOException("Exclusive audit directory creation refused.");
        }
    }
}
'@
}
function Assert-AuditDataPayloadPath([string]$Repository,$Context){
    Assert-ImmuData ($Context.Fixture -cmatch '^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\z' -and
        $Context.Fixture -cne [Guid]::Empty.ToString('D')) 'payload-fixture'
    $parent=Join-Path $Repository 'artifacts'
    $expected=Join-Path $parent ('native-audit-controller-'+$Context.Fixture)
    Assert-ImmuData ([IO.Path]::IsPathFullyQualified($Repository) -and
        [IO.Path]::GetFullPath($Repository) -ceq $Repository -and $Context.Root -ceq $expected) 'payload-path'
    $ordinary=Get-ProviderOrdinaryItem $parent
    Assert-ImmuData ($ordinary.PSIsContainer -and $ordinary.FullName -ceq $parent) 'payload-parent'
}
function New-AuditDataPublicPayload([string]$Repository,$Context){
    Assert-AuditDataPayloadPath $Repository $Context
    Assert-ImmuData ($Context.PayloadClaimed -is [bool] -and -not $Context.PayloadClaimed -and
        $Context.PayloadRemoved -is [bool] -and -not $Context.PayloadRemoved) 'payload-claim-state'
    # Native exclusive mkdir also refuses a directory created between check and use.
    [Fleetory.Pilot.ExclusiveAuditDirectory]::Create($Context.Root)
    $Context.PayloadClaimed=$true
}
function Remove-AuditDataPublicPayload([string]$Repository,$Context){
    Assert-ImmuData ($Context.PayloadClaimed -is [bool] -and $Context.PayloadRemoved -is [bool]) 'payload-claim-state'
    if(-not $Context.PayloadClaimed){return}
    Assert-AuditDataPayloadPath $Repository $Context
    Remove-NativePublicPayload $Repository $Context.Root
    Assert-ImmuData (-not (Test-Path -LiteralPath $Context.Root)) 'payload-cleanup-absence'
    $Context.PayloadClaimed=$false
    $Context.PayloadRemoved=$true
}
function Publish-AuditDataLedger([string]$Temporary,[string]$Destination){
    if([IO.File]::Exists($Destination)){[IO.File]::Replace($Temporary,$Destination,[NullString]::Value)}
    else{[IO.File]::Move($Temporary,$Destination)}
}
function Write-AuditDataLedger($Context){
    $root=Get-ProviderOrdinaryItem $Context.Root
    Assert-ImmuData ($root.PSIsContainer -and $root.FullName -ceq $Context.Root -and
        $Context.ImageName -ceq (Get-ImmuDataImageName $Context.Fixture) -and
        ($null -eq $Context.ImageId -or $Context.ImageId -cmatch '^sha256:[a-f0-9]{64}\z') -and
        $Context.Stores.Count -le 16) 'ledger-context'
    $items=@($Context.Stores|ForEach-Object {
        Assert-ImmuData ($_.Session -cmatch '^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\z' -and
            $_.Name -ceq ('fleetory-immu-store-'+$_.Session.Replace('-','')) -and
            ($null -eq $_.Id -or $_.Id -cmatch '^[a-f0-9]{64}\z') -and $_.Started -is [DateTimeOffset] -and
            $_.Role -cin @('source','target','corrupt')) 'ledger-store'
        @{Id=$_.Id;Session=$_.Session;Name=$_.Name;Started=$_.Started;Role=$_.Role}
    })
    $bytes=[Text.Encoding]::UTF8.GetBytes((@{fixture=$Context.Fixture;image=$Context.ImageName;imageId=$Context.ImageId;stores=$items}|ConvertTo-Json -Depth 7 -Compress))
    Assert-ImmuData ($bytes.Length -gt 0 -and $bytes.Length -le 16384) 'ledger-size'
    $destination=Join-Path $Context.Root 'owned-stores.json'
    if(Test-Path -LiteralPath $destination){
        $existing=Get-ProviderOrdinaryItem $destination
        Assert-ImmuData (-not $existing.PSIsContainer -and $existing.Length -le 16384) 'ledger-destination'
    }
    $temporary=Join-Path $Context.Root ('owned-stores.'+[Guid]::NewGuid().ToString('N')+'.tmp')
    $stream=$null;$claimed=$false
    try{
        $stream=[IO.FileStream]::new($temporary,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None,
            4096,[IO.FileOptions]::WriteThrough)
        $claimed=$true
        $stream.Write($bytes,0,$bytes.Length)
        $stream.Flush($true)
        $stream.Dispose();$stream=$null
        # Same-directory rename publishes a complete flushed record, never truncated JSON.
        Publish-AuditDataLedger $temporary $destination
    }finally{
        if($null -ne $stream){$stream.Dispose()}
        if($claimed -and (Test-Path -LiteralPath $temporary)){
            $ordinary=Get-ProviderOrdinaryItem $temporary
            Assert-ImmuData (-not $ordinary.PSIsContainer -and $ordinary.FullName -ceq $temporary) 'ledger-temporary'
            [IO.File]::Delete($temporary)
        }
    }
}
