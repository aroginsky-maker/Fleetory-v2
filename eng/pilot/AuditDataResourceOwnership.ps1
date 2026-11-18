#requires -Version 7.3
# In-process claims and atomic resource metadata; neither authenticates a dead owner.
if(-not ('Fleetory.Pilot.ExclusiveAuditDirectory' -as [type])){
    Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Runtime.InteropServices;
namespace Fleetory.Pilot {
    internal static class AuditNativeReply {
        internal static object[] Values(System.Collections.IDictionary source, string[] keys) {
            var values=new object[keys.Length];
            for(int n=0;n<keys.Length;n++) values[n]=source[keys[n]];
            return values;
        }
        internal static bool Same(object[] left, object[] right) {
            for(int n=0;n<left.Length;n++) if(!Equals(left[n],right[n])) return false;
            return true;
        }
        internal static Tuple<int,byte[],byte[]> Hold(Tuple<int,byte[],byte[]> reply) {
            if(reply==null || reply.Item2==null || reply.Item3==null || reply.Item2.Length>67108864 || reply.Item3.Length>1048576) throw new InvalidOperationException("Audit native reply refused.");
            return Tuple.Create(reply.Item1,(byte[])reply.Item2.Clone(),(byte[])reply.Item3.Clone());
        }
        internal static string Id(Tuple<int,byte[],byte[]> reply, string prefix) {
            byte[] raw=reply.Item2;
            int length=prefix.Length+64;
            if(reply.Item1!=0 || (raw.Length!=length+1 && raw.Length!=length+2) || raw[raw.Length-1]!=10 ||
                (raw.Length==length+2 && raw[length]!=13)) throw new InvalidOperationException("Audit native ID reply refused.");
            for(int n=0;n<prefix.Length;n++) if(raw[n]!=prefix[n]) throw new InvalidOperationException("Audit native ID prefix refused.");
            for(int n=prefix.Length;n<length;n++) if(!((raw[n]>=48 && raw[n]<=57)||(raw[n]>=97 && raw[n]<=102))) throw new InvalidOperationException("Audit native ID digits refused.");
            return System.Text.Encoding.ASCII.GetString(raw,0,length);
        }
        internal static bool EmptyInspection(byte[] raw) {
            string output=System.Text.Encoding.UTF8.GetString(raw);
            return output=="" || output=="[]\n" || output=="[]\r\n";
        }
    }
    // Fixed historical image creator only; no import or dead-owner recovery API.
    public static class AuditImageCustody {
        private sealed class Claim {
            internal readonly System.Collections.IDictionary Context;
            internal readonly object Client;
            internal readonly object[] Values;
            internal readonly byte[] Archive;
            internal readonly int Process=Environment.ProcessId;
            internal readonly DateTimeOffset Started=DateTimeOffset.UtcNow;
            internal Tuple<int,byte[],byte[]> Creation, Inspection, Removal;
            internal string Id;
            internal int State;
            internal Claim(System.Collections.IDictionary context, object client, byte[] archive) {
                Context=context; Client=client; Values=AuditNativeReply.Values(context,Keys); Archive=(byte[])archive.Clone();
            }
        }
        private static readonly string[] Keys={"Fixture","Root","ImageName","ProbeHash"};
        private static readonly System.Runtime.CompilerServices.ConditionalWeakTable<object,Claim> Claims=new();
        private static InvalidOperationException Refused() => new("Audit image live custody refused.");
        private static Claim Get(System.Collections.IDictionary context, object client, bool live=true) {
            if(!Claims.TryGetValue(context,out var claim) || !ReferenceEquals(context,claim.Context) || !ReferenceEquals(client,claim.Client) ||
                claim.Process!=Environment.ProcessId || !AuditNativeReply.Same(AuditNativeReply.Values(context,Keys),claim.Values) ||
                !Equals(context["ImageId"],claim.Id) || !Equals(context["ImageClaimed"],true) ||
                (live && System.Threading.Volatile.Read(ref claim.State)!=1)) throw Refused();
            return claim;
        }
        public static bool Attempted(System.Collections.IDictionary context) => Claims.TryGetValue(context,out _);
        public static string Build(System.Collections.IDictionary context, object client, byte[] archive, Func<Tuple<int,byte[],byte[]>> operation) {
            if(client==null || operation==null || archive==null || archive.Length==0 || archive.Length>16777216 ||
                context["ImageId"]!=null || !Equals(context["ImageClaimed"],false)) throw Refused();
            var claim=new Claim(context,client,archive);
            Claims.Add(context,claim);
            context["ImageClaimed"]=true; // Consumed before invoking the actual fixed native build.
            claim.Creation=AuditNativeReply.Hold(operation());
            if(!archive.AsSpan().SequenceEqual(claim.Archive)) throw Refused();
            claim.Id=AuditNativeReply.Id(claim.Creation,"sha256:");
            context["ImageId"]=claim.Id;claim.State=1;
            return Get(context,client).Id;
        }
        public static string Id(System.Collections.IDictionary context, object client) => Get(context,client).Id;
        public static DateTimeOffset Started(System.Collections.IDictionary context, object client) => Get(context,client).Started;
        public static bool Closed(System.Collections.IDictionary context, object client) {
            var claim=Get(context,client,false);return System.Threading.Volatile.Read(ref claim.State)==3;
        }
        public static Tuple<int,byte[],byte[]> Inspect(System.Collections.IDictionary context, object client, Func<Tuple<int,byte[],byte[]>> operation) {
            var claim=Get(context,client);claim.Inspection=AuditNativeReply.Hold(operation());return AuditNativeReply.Hold(claim.Inspection);
        }
        private static void FullRemoval(Claim claim) {
            string text=System.Text.Encoding.UTF8.GetString(claim.Removal.Item2);
            if(claim.Removal.Item1!=0 || (text!="Deleted: "+claim.Id+"\n" && text!="Deleted: "+claim.Id+"\r\n")) throw Refused();
        }
        public static void Remove(System.Collections.IDictionary context, object client, Func<Tuple<int,byte[],byte[]>> operation) {
            var claim=Get(context,client);
            if(System.Threading.Interlocked.CompareExchange(ref claim.State,2,1)!=1) throw Refused();
            claim.Removal=AuditNativeReply.Hold(operation());FullRemoval(claim);
        }
        private static void Absence(Claim claim,int expected) {
            if(claim.Inspection==null || claim.Inspection.Item1!=1 || !AuditNativeReply.EmptyInspection(claim.Inspection.Item2)) throw Refused();
            string text=System.Text.Encoding.UTF8.GetString(claim.Inspection.Item3);
            if(!System.Text.RegularExpressions.Regex.IsMatch(text,@"\A(?:Error response from daemon: |Error: )?no such (object|image): "+claim.Id+@"\r?\n?\z",
                System.Text.RegularExpressions.RegexOptions.IgnoreCase)) throw Refused();
            if(System.Threading.Interlocked.CompareExchange(ref claim.State,3,expected)!=expected) throw Refused();
        }
        public static void Absent(System.Collections.IDictionary context, object client) => Absence(Get(context,client),1);
        public static void ConfirmRemoval(System.Collections.IDictionary context, object client, Func<Tuple<int,byte[],byte[]>> operation) {
            var claim=Get(context,client,false);
            if(System.Threading.Volatile.Read(ref claim.State)!=2 || claim.Removal==null) throw Refused();
            FullRemoval(claim);claim.Inspection=AuditNativeReply.Hold(operation());Absence(claim,2);
        }
    }
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
                ContextValues=AuditNativeReply.Values(context, ContextKeys); StoreValues=AuditNativeReply.Values(store, StoreKeys);
            }
        }
        private static readonly string[] ContextKeys = {"Fixture", "ImageName", "ImageId", "LifetimeSeconds"};
        private static readonly string[] StoreKeys = {"Session", "Name", "Role", "Started"};
        private static readonly System.Runtime.CompilerServices.ConditionalWeakTable<object, Claim> Claims = new();
        private static InvalidOperationException Refused(string reason="reply") => new("Audit container live custody refused: "+reason+".");
        private static Claim Get(System.Collections.IDictionary context, System.Collections.IDictionary store, object client, bool live=true) {
            if(!Claims.TryGetValue(store,out var claim)) throw Refused("unclaimed-store");
            if(!ReferenceEquals(context,claim.Context) || !ReferenceEquals(store,claim.Store)) throw Refused("object-identity");
            if(!ReferenceEquals(client,claim.Client)) throw Refused("client-identity");
            if(!ReferenceEquals(context["Stores"],claim.Stores)) throw Refused("store-list");
            if(claim.Process!=Environment.ProcessId) throw Refused("process");
            if(!AuditNativeReply.Same(AuditNativeReply.Values(context,ContextKeys),claim.ContextValues) || !AuditNativeReply.Same(AuditNativeReply.Values(store,StoreKeys),claim.StoreValues)) throw Refused("metadata");
            if(!Equals(store["Id"],claim.Id)) throw Refused("store-id");
            if(live && System.Threading.Volatile.Read(ref claim.State)!=1) throw Refused("outcome");
            bool present=false;
            foreach(var item in (System.Collections.IEnumerable)claim.Stores) if(ReferenceEquals(item,store)) present=true;
            if(!present) throw Refused();
            return claim;
        }
        private static string CompleteId(Tuple<int,byte[],byte[]> reply) => AuditNativeReply.Id(reply,"");
        public static string Create(System.Collections.IDictionary context, System.Collections.IDictionary store, object client,
            Func<Tuple<int,byte[],byte[]>> operation) {
            if(client==null || operation==null || store["Id"]!=null) throw Refused();
            var claim=new Claim(context,store,client);
            Claims.Add(store,claim); // Consumed before the native call, even on exception/unknown output.
            claim.Creation=AuditNativeReply.Hold(operation());
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
            claim.Inspection=AuditNativeReply.Hold(operation());
            return AuditNativeReply.Hold(claim.Inspection);
        }
        public static void Remove(System.Collections.IDictionary context, System.Collections.IDictionary store, object client,
            Func<Tuple<int,byte[],byte[]>> operation) {
            var claim=Get(context,store,client);
            if(System.Threading.Interlocked.CompareExchange(ref claim.State,2,1)!=1) throw Refused("outcome"); // Consume before the call.
            claim.Removal=AuditNativeReply.Hold(operation());
            if(CompleteId(claim.Removal)!=claim.Id) throw Refused();
            // Stay consumed and unclosed until the subsequent native absence reply.
        }
        public static void ConfirmRemoval(System.Collections.IDictionary context, System.Collections.IDictionary store, object client,
            Func<Tuple<int,byte[],byte[]>> operation) {
            var claim=Get(context,store,client,false);
            if(System.Threading.Volatile.Read(ref claim.State)!=2 || claim.Removal==null || CompleteId(claim.Removal)!=claim.Id) throw Refused("outcome");
            claim.Inspection=AuditNativeReply.Hold(operation());
            ConfirmAbsence(claim,2);
        }
        public static void Absent(System.Collections.IDictionary context, System.Collections.IDictionary store, object client) {
            ConfirmAbsence(Get(context,store,client),1);
        }
        private static void ConfirmAbsence(Claim claim, int expectedState) {
            if(claim.Inspection==null || claim.Inspection.Item1!=1) throw Refused();
            if(!AuditNativeReply.EmptyInspection(claim.Inspection.Item2)) throw Refused("absence-output");
            string text=System.Text.Encoding.UTF8.GetString(claim.Inspection.Item3);
            if(!System.Text.RegularExpressions.Regex.IsMatch(text,@"\A(?:Error: )?no such (object|container): "+claim.Id+@"\r?\n?\z",
                System.Text.RegularExpressions.RegexOptions.IgnoreCase)) throw Refused();
            if(System.Threading.Interlocked.CompareExchange(ref claim.State,3,expectedState)!=expectedState) throw Refused("outcome");
        }
    }
    // Closed historical native-probe profile; the creator keeps all Docker authority.
    public static class AuditHistoricalProbeProfile {
        private sealed class Profile {
            internal readonly System.Collections.IDictionary Context;
            internal readonly object Client;
            internal readonly object[] Values;
            internal readonly int Process=Environment.ProcessId;
            internal readonly long Started=System.Diagnostics.Stopwatch.GetTimestamp();
            internal readonly System.Collections.Generic.List<Tuple<string,byte[],Tuple<int,byte[],byte[]>>> Replies=new();
            internal int Busy, Calls;
            internal bool Unknown;
            internal Profile(System.Collections.IDictionary context,object client) {
                Context=context;Client=client;Values=AuditNativeReply.Values(context,Keys);
            }
        }
        private static readonly string[] Keys={"Fixture","Root","ImageName"};
        private static readonly System.Runtime.CompilerServices.ConditionalWeakTable<object,Profile> Profiles=new();
        private static InvalidOperationException Refused() => new("Historical probe profile refused.");
        private static Profile Get(System.Collections.IDictionary context,object client) {
            if(!Profiles.TryGetValue(context,out var p) || !ReferenceEquals(p.Context,context) || !ReferenceEquals(p.Client,client) ||
                p.Process!=Environment.ProcessId || p.Unknown || !AuditNativeReply.Same(p.Values,AuditNativeReply.Values(context,Keys)) ||
                System.Diagnostics.Stopwatch.GetElapsedTime(p.Started).TotalSeconds>=600) throw Refused();
            return p;
        }
        public static void Begin(System.Collections.IDictionary context,object client) {
            if(context==null || client==null || context["ImageId"]!=null || AuditImageCustody.Attempted(context) ||
                context["Stores"] is not System.Collections.ICollection stores || stores.Count!=0) throw Refused();
            Profiles.Add(context,new Profile(context,client)); // No reset, import or second begin.
        }
        private static string OwnedId(Profile p,System.Collections.IDictionary store) {
            if(!Equals(p.Context["LifetimeSeconds"],660) || !Equals(store["Role"],"target")) throw Refused();
            string image=AuditImageCustody.Id(p.Context,p.Client);
            string id=AuditContainerCustody.Id(p.Context,store,p.Client);
            if(!Equals(p.Context["ImageId"],image)) throw Refused();
            return id;
        }
        public static int Calls(System.Collections.IDictionary context,object client) => Get(context,client).Calls;
        public static Tuple<int,byte[],byte[]> Invoke(System.Collections.IDictionary context,System.Collections.IDictionary store,object client,
            string mode,byte[] input,Func<string[],byte[],Tuple<int,byte[],byte[]>> operation) {
            if(mode!="audit-health" && mode!="history-users" && mode!="observation-history-read" && mode!="observation-reader-denial") throw Refused();
            if(input==null || input.Length==0 || input.Length>131072 || operation==null) throw Refused();
            var p=Get(context,client);
            if(System.Threading.Interlocked.CompareExchange(ref p.Busy,1,0)!=0) throw Refused();
            byte[] frozen=(byte[])input.Clone(),delivery=null;
            try {
                string id=OwnedId(p,store);
                if(p.Calls>=64) throw Refused();
                var args=new[]{"exec","-i","-e","SSL_CERT_FILE=/tmp/ca.pem","-e","SSL_CERT_DIR=/tmp/empty-ca-dir",id,"dotnet","/tool/ServerBackendProbe.dll",mode};
                if(mode=="observation-history-read")
                    args=new[]{args[0],args[1],args[2],args[3],args[4],args[5],args[6],args[7],args[8],"--historical-supervise",mode};
                var sent=(string[])args.Clone();delivery=(byte[])frozen.Clone();
                p.Calls++;p.Unknown=true; // Consume before the actual fixed native operation.
                var reply=AuditNativeReply.Hold(operation(sent,delivery));
                p.Replies.Add(Tuple.Create(mode,System.Security.Cryptography.SHA256.HashData(frozen),reply));
                if(reply.Item2.Length>262144 || reply.Item3.Length>4096 || !input.AsSpan().SequenceEqual(frozen) ||
                    !delivery.AsSpan().SequenceEqual(frozen) || !sent.AsSpan().SequenceEqual(args) || OwnedId(p,store)!=id) throw Refused();
                p.Unknown=false;
                Get(context,client); // Deadline and original identity must still hold after the reply.
                return AuditNativeReply.Hold(reply); // Opaque bytes, not application acceptance or OS fencing.
            } catch {p.Unknown=true;throw;}
            finally {
                Array.Clear(frozen,0,frozen.Length);
                if(delivery!=null) Array.Clear(delivery,0,delivery.Length);
                System.Threading.Volatile.Write(ref p.Busy,0);
            }
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
