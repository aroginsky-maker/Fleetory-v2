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
    // Separate facade instances retain independent live claims; no import API.
    internal sealed class AuditImageCustodyCore {
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
            internal Claim(System.Collections.IDictionary context, object client, byte[] archive, string[] keys) {
                Context=context; Client=client; Values=AuditNativeReply.Values(context,keys); Archive=(byte[])archive.Clone();
            }
        }
        private readonly string[] Keys;
        private readonly int MaximumArchiveBytes;
        internal AuditImageCustodyCore(int maximumArchiveBytes, string[] keys) { MaximumArchiveBytes=maximumArchiveBytes; Keys=(string[])keys.Clone(); }
        private readonly System.Runtime.CompilerServices.ConditionalWeakTable<object,Claim> Claims=new();
        private static InvalidOperationException Refused() => new("Audit image live custody refused.");
        private Claim Get(System.Collections.IDictionary context, object client, bool live=true) {
            if(!Claims.TryGetValue(context,out var claim) || !ReferenceEquals(context,claim.Context) || !ReferenceEquals(client,claim.Client) ||
                claim.Process!=Environment.ProcessId || !AuditNativeReply.Same(AuditNativeReply.Values(context,Keys),claim.Values) ||
                !Equals(context["ImageId"],claim.Id) || !Equals(context["ImageClaimed"],true) ||
                (live && System.Threading.Volatile.Read(ref claim.State)!=1)) throw Refused();
            return claim;
        }
        internal bool Attempted(System.Collections.IDictionary context) => Claims.TryGetValue(context,out _);
        internal string Build(System.Collections.IDictionary context, object client, byte[] archive, Func<Tuple<int,byte[],byte[]>> operation) {
            if(client==null || operation==null || archive==null || archive.Length==0 || archive.Length>MaximumArchiveBytes ||
                context["ImageId"]!=null || !Equals(context["ImageClaimed"],false)) throw Refused();
            var claim=new Claim(context,client,archive,Keys);
            Claims.Add(context,claim);
            context["ImageClaimed"]=true; // Consumed before invoking the actual fixed native build.
            claim.Creation=AuditNativeReply.Hold(operation());
            if(!archive.AsSpan().SequenceEqual(claim.Archive)) throw Refused();
            claim.Id=AuditNativeReply.Id(claim.Creation,"sha256:");
            context["ImageId"]=claim.Id;claim.State=1;
            return Get(context,client).Id;
        }
        internal string Id(System.Collections.IDictionary context, object client) => Get(context,client).Id;
        internal DateTimeOffset Started(System.Collections.IDictionary context, object client) => Get(context,client).Started;
        internal bool Closed(System.Collections.IDictionary context, object client) {
            var claim=Get(context,client,false);return System.Threading.Volatile.Read(ref claim.State)==3;
        }
        internal Tuple<int,byte[],byte[]> Inspect(System.Collections.IDictionary context, object client, Func<Tuple<int,byte[],byte[]>> operation) {
            var claim=Get(context,client);claim.Inspection=AuditNativeReply.Hold(operation());return AuditNativeReply.Hold(claim.Inspection);
        }
        private static void FullRemoval(Claim claim) {
            string text=System.Text.Encoding.UTF8.GetString(claim.Removal.Item2);
            if(claim.Removal.Item1!=0 || (text!="Deleted: "+claim.Id+"\n" && text!="Deleted: "+claim.Id+"\r\n")) throw Refused();
        }
        internal void Remove(System.Collections.IDictionary context, object client, Func<Tuple<int,byte[],byte[]>> operation) {
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
        internal void Absent(System.Collections.IDictionary context, object client) => Absence(Get(context,client),1);
        internal void ConfirmRemoval(System.Collections.IDictionary context, object client, Func<Tuple<int,byte[],byte[]>> operation) {
            var claim=Get(context,client,false);
            if(System.Threading.Volatile.Read(ref claim.State)!=2 || claim.Removal==null) throw Refused();
            FullRemoval(claim);claim.Inspection=AuditNativeReply.Hold(operation());Absence(claim,2);
        }
    }
    public static class AuditImageCustody {
        private static readonly AuditImageCustodyCore Core=new(16777216,new string[] {"Fixture","Root","ImageName","ProbeHash"});
        public static bool Attempted(System.Collections.IDictionary context) => Core.Attempted(context);
        public static string Build(System.Collections.IDictionary context, object client, byte[] archive, Func<Tuple<int,byte[],byte[]>> operation) => Core.Build(context,client,archive,operation);
        public static string Id(System.Collections.IDictionary context, object client) => Core.Id(context,client);
        public static DateTimeOffset Started(System.Collections.IDictionary context, object client) => Core.Started(context,client);
        public static bool Closed(System.Collections.IDictionary context, object client) => Core.Closed(context,client);
        public static Tuple<int,byte[],byte[]> Inspect(System.Collections.IDictionary context, object client, Func<Tuple<int,byte[],byte[]>> operation) => Core.Inspect(context,client,operation);
        public static void Remove(System.Collections.IDictionary context, object client, Func<Tuple<int,byte[],byte[]>> operation) => Core.Remove(context,client,operation);
        public static void Absent(System.Collections.IDictionary context, object client) => Core.Absent(context,client);
        public static void ConfirmRemoval(System.Collections.IDictionary context, object client, Func<Tuple<int,byte[],byte[]>> operation) => Core.ConfirmRemoval(context,client,operation);
    }
    // Trusted native worker only. A serialized result is never an import grant.
    public sealed class PublicSdkOutputLease : IDisposable {
        private static readonly System.Runtime.CompilerServices.ConditionalWeakTable<object,object> Attempts=new();
        private readonly System.Collections.IDictionary imageContext, stack, store;
        private readonly object imageClient, sdkClient;
        private readonly Func<bool> alive;
        private readonly int process=Environment.ProcessId, thread=Environment.CurrentManagedThreadId;
        private readonly long capturedAt=System.Diagnostics.Stopwatch.GetTimestamp();
        private readonly double priorSeconds;
        private readonly string image, container;
        private byte[] bytes;
        private bool complete, consumed, disposed;
        private static void Require(bool value) {
            if(!value) throw new InvalidOperationException("Public SDK output handoff refused.");
        }
        private PublicSdkOutputLease(System.Collections.IDictionary sourceImage,object sourceClient,
            System.Collections.IDictionary sdkStack,System.Collections.IDictionary sdkStore,object nativeClient,
            Func<bool> controller,System.Diagnostics.Stopwatch originalAge) {
            Require(sourceImage!=null && sourceClient!=null && sdkStack!=null && sdkStore!=null && nativeClient!=null &&
                controller!=null && originalAge!=null && originalAge.IsRunning);
            imageContext=sourceImage;imageClient=sourceClient;stack=sdkStack;store=sdkStore;sdkClient=nativeClient;alive=controller;
            priorSeconds=originalAge.Elapsed.TotalSeconds;
            image=PublicBuildImageCustody.Id(imageContext,imageClient);
            Require(Equals(stack["ImageId"],image) && Equals(stack["LifetimeSeconds"],300) && Equals(store["Role"],"public-sdk"));
            container=AuditContainerCustody.Id(stack,store,sdkClient);
            Check();
        }
        private void Check() {
            Require(!disposed && process==Environment.ProcessId && thread==Environment.CurrentManagedThreadId &&
                alive!=null && priorSeconds>=0 &&
                priorSeconds+System.Diagnostics.Stopwatch.GetElapsedTime(capturedAt).TotalSeconds<310);
            Require(alive() && PublicBuildImageCustody.Id(imageContext,imageClient)==image);
        }
        public static PublicSdkOutputLease Capture(System.Collections.IDictionary image,object imageClient,
            System.Collections.IDictionary stack,System.Collections.IDictionary store,object sdkClient,
            Func<bool> controller,System.Diagnostics.Stopwatch originalAge,Func<Tuple<int,byte[],byte[]>> operation) {
            Require(operation!=null);
            var value=new PublicSdkOutputLease(image,imageClient,stack,store,sdkClient,controller,originalAge);
            // Consume before the operation, including truncated/error replies. Never retry by ID.
            Require(!Attempts.TryGetValue(store,out _));Attempts.Add(store,new object());
            var reply=AuditNativeReply.Hold(operation());
            value.Check();
            Require(AuditContainerCustody.Id(stack,store,sdkClient)==value.container &&
                reply.Item1==0 && reply.Item2.Length>0 && reply.Item2.Length<=67108864 && reply.Item3.Length==0);
            value.bytes=reply.Item2; // Already a private complete-reply snapshot.
            return value;
        }
        public void Complete() {
            Check();
            Require(!complete && !consumed && bytes!=null && AuditContainerCustody.Closed(stack,store,sdkClient));
            complete=true;
        }
        public int GetByteCount() {Check();Require(complete && !consumed && bytes!=null);return bytes.Length;}
        public bool IsClosed() {Check();Require(complete && !consumed);return AuditContainerCustody.Closed(stack,store,sdkClient);}
        internal Tuple<System.Collections.IDictionary,object,string> PublicationSource() {
            Check();Require(complete && !consumed && bytes!=null && AuditContainerCustody.Closed(stack,store,sdkClient));
            return Tuple.Create(imageContext,imageClient,image);
        }
        public byte[] Take() {
            Require(!consumed);consumed=true; // Failed or premature acceptance also consumes this result.
            byte[] result=null;
            try {
                Check();
                Require(complete && bytes!=null && AuditContainerCustody.Closed(stack,store,sdkClient));
                result=(byte[])bytes.Clone();Check();return result;
            }
            catch {if(result!=null)Array.Clear(result,0,result.Length);throw;}
            finally {Dispose();}
        }
        public void Dispose() {
            if(disposed)return;disposed=true;
            if(bytes!=null){Array.Clear(bytes,0,bytes.Length);bytes=null;}
        }
    }

    // Trusted surviving worker API. No receipt/path/JSON import and no native-resource cleanup rights.
    public sealed class PublicSdkPublicationPipe : IDisposable {
        private static readonly System.Runtime.CompilerServices.ConditionalWeakTable<object,object> Attempts=new();
        private readonly System.Diagnostics.Process child;
        private readonly System.Diagnostics.Stopwatch scopeAge, childAge;
        private readonly Func<bool> controller;
        private readonly Action<System.Diagnostics.Process> validateChild;
        private readonly int owner=Environment.ProcessId, thread=Environment.CurrentManagedThreadId;
        private readonly byte[] nonce;
        private byte[] sourcePin, manifest;
        private System.Collections.IDictionary sourceContext;
        private object sourceClient;
        private string sourceImage;
        private bool admitted, used, contextReady, readbackAttempted, disposed;
        private static void Require(bool value) {
            if(!value) throw new InvalidOperationException("SDK publication private pipe refused.");
        }
        private PublicSdkPublicationPipe(System.Diagnostics.Process process,System.Diagnostics.Stopwatch originalScope,
            System.Diagnostics.Stopwatch originalChildAge,Func<bool> alive,Action<System.Diagnostics.Process> originalChild,string token) {
            Require(process!=null && originalScope!=null && originalChildAge!=null && alive!=null && originalChild!=null &&
                token!=null && System.Text.RegularExpressions.Regex.IsMatch(token,@"\A[a-f0-9]{32}\z"));
            child=process;scopeAge=originalScope;childAge=originalChildAge;controller=alive;validateChild=originalChild;
            nonce=System.Text.Encoding.ASCII.GetBytes(token);
        }
        private int Remaining(bool ready=false,bool closing=false) {
            Require(!disposed && owner==Environment.ProcessId && thread==Environment.CurrentManagedThreadId &&
                scopeAge.IsRunning && childAge.IsRunning);
            long remaining=Math.Min(420000-scopeAge.ElapsedMilliseconds,60000-childAge.ElapsedMilliseconds);
            if(ready) remaining=Math.Min(remaining,5000-childAge.ElapsedMilliseconds);
            Require(remaining>0);
            Require(sourceContext!=null && PublicBuildImageCustody.Id(sourceContext,sourceClient)==sourceImage);
            if(!closing) {
                Require(controller() && !child.HasExited);
                validateChild(child);
            }
            return (int)remaining;
        }
        private void Await(System.Threading.Tasks.Task task,bool ready=false,bool closing=false) {
            while(!task.Wait(Math.Min(100,Remaining(ready,closing)))) {}
            task.GetAwaiter().GetResult();
            Remaining(ready,closing);
        }
        private byte[] Read(int count,bool ready=false,bool closing=false) {
            Require(count>0 && count<=16777216+4096);
            var value=new byte[count];int offset=0;
            while(offset<count) {
                var task=child.StandardOutput.BaseStream.ReadAsync(value,offset,count-offset);
                Await(task,ready,closing);
                int got=task.GetAwaiter().GetResult();Require(got>0);offset+=got;
            }
            return value;
        }
        private void Write(byte[] bytes,bool closing=false) {
            Require(bytes!=null && bytes.Length>0 && bytes.Length<=67108864);
            Remaining(false,closing);
            Await(child.StandardInput.BaseStream.WriteAsync(bytes,0,bytes.Length),false,closing);
            Await(child.StandardInput.BaseStream.FlushAsync(),false,closing);
        }
        private static bool Equal(byte[] left,byte[] right) =>
            System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(left,right);
        private static byte[] Digest(byte[] bytes) => System.Security.Cryptography.SHA256.HashData(bytes);
        private byte[] Frame(string magic,int maximum,bool closing=false) {
            byte[] header=Read(108,false,closing);
            Require(System.Text.Encoding.ASCII.GetString(header,0,8)==magic &&
                Equal(header.AsSpan(8,32).ToArray(),nonce) && Equal(header.AsSpan(40,32).ToArray(),sourcePin));
            uint length=System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(header.AsSpan(72,4));
            Require(length<=maximum);
            byte[] data=length==0?Array.Empty<byte>():Read((int)length,false,closing);
            Require(Equal(Digest(data),header.AsSpan(76,32).ToArray()));
            return data;
        }
        public static PublicSdkPublicationPipe Open(PublicSdkOutputLease sdk,System.Diagnostics.Process process,
            System.Diagnostics.Stopwatch originalScope,System.Diagnostics.Stopwatch originalChildAge,
            Func<bool> alive,Action<System.Diagnostics.Process> validateOriginalChild,string nonce,byte[] plan) {
            Require(sdk!=null && plan!=null && plan.Length>0 && plan.Length<=8192);
            // Failed admission consumes this SDK publication attempt before the first blocking read.
            Require(!Attempts.TryGetValue(sdk,out _));Attempts.Add(sdk,new object());
            var pipe=new PublicSdkPublicationPipe(process,originalScope,originalChildAge,alive,validateOriginalChild,nonce);
            byte[] raw=null;
            try {
                var source=sdk.PublicationSource();
                pipe.sourceContext=source.Item1;pipe.sourceClient=source.Item2;pipe.sourceImage=source.Item3;
                pipe.Remaining(true);
                Require(process.StartInfo.RedirectStandardInput && process.StartInfo.RedirectStandardOutput && process.StartInfo.RedirectStandardError);
                pipe.admitted=true; // Only after the trusted original-process validator succeeded.
                byte[] ready=pipe.Read(40,true);
                Require(System.Text.Encoding.ASCII.GetString(ready,0,8)=="FLTSRD01" && Equal(ready.AsSpan(8,32).ToArray(),pipe.nonce));
                raw=sdk.Take();
                pipe.sourcePin=Digest(raw);
                byte[] frozenPlan=(byte[])plan.Clone(),header=new byte[112];
                System.Text.Encoding.ASCII.GetBytes("FLTSIN01").CopyTo(header,0);pipe.nonce.CopyTo(header,8);
                System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(40,4),(uint)raw.Length);
                System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(44,4),(uint)frozenPlan.Length);
                pipe.sourcePin.CopyTo(header,48);Digest(frozenPlan).CopyTo(header,80);
                pipe.Write(header);pipe.Write(raw);pipe.Write(frozenPlan);
                pipe.manifest=pipe.Frame("FLTSOUT1",98304);
                Require(pipe.manifest.Length>0);pipe.Remaining();
                return pipe;
            } catch {pipe.Abort();throw;}
            finally {if(raw!=null)Array.Clear(raw,0,raw.Length);}
        }
        public byte[] Manifest() {Remaining();Require(manifest!=null);return (byte[])manifest.Clone();}
        public void RequireSource(System.Collections.IDictionary context,object client) {
            Remaining();Require(Object.ReferenceEquals(context,sourceContext) && Object.ReferenceEquals(client,sourceClient));
        }
        public byte[] Context(byte[] definition) {
            Require(!used);used=true;
            Remaining();Require(definition!=null && definition.Length>0 && definition.Length<=4096);
            byte[] frozen=(byte[])definition.Clone(),pin=Digest(frozen),request=new byte[37];
            request[0]=67;
            System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(request.AsSpan(1,4),(uint)frozen.Length);
            pin.CopyTo(request,5);Write(request);Write(frozen);
            byte[] payload=Frame("FLTSCTX1",16777216+64);
            Require(payload.Length>64 && payload.Length-64<=16777216 &&
                Equal(pin,payload.AsSpan(0,32).ToArray()) && Equal(Digest(manifest),payload.AsSpan(32,32).ToArray()));
            Remaining();contextReady=true;return payload.AsSpan(64).ToArray();
        }
        public byte[] VerifyReadback(byte[] archive) {
            Require(!readbackAttempted);readbackAttempted=true;
            Remaining();Require(contextReady && archive!=null && archive.Length>0 && archive.Length<=16777216);
            byte[] frozen=(byte[])archive.Clone(),pin=Digest(frozen),request=new byte[37];
            request[0]=66;
            System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(request.AsSpan(1,4),(uint)frozen.Length);
            pin.CopyTo(request,5);Write(request);Write(frozen);
            byte[] payload=Frame("FLTSCHK1",4096);
            Require(payload.Length>64 && Equal(pin,payload.AsSpan(0,32).ToArray()) &&
                Equal(Digest(manifest),payload.AsSpan(32,32).ToArray()));
            Remaining();return payload.AsSpan(64).ToArray();
        }
        private void Abort() {
            if(disposed)return;
            if(admitted) {
                try {child.StandardInput.Close();} catch {}
                try {if(!child.HasExited){child.Kill();child.WaitForExit(5000);}} catch {}
                child.Dispose();
            }
            disposed=true;
        }
        public void Dispose() {
            if(disposed)return;
            try {
                Require(admitted);
                Write(new byte[]{82},true);child.StandardInput.Close();
                Require(Frame("FLTSEND1",0,true).Length==0);
                Require(child.WaitForExit(Math.Min(5000,Remaining(false,true))) && child.ExitCode==0);
            } finally {Abort();}
        }
    }

    // Trusted worker supplies independently committed source/frame pins and original executable callbacks.
    // No PID lookup, metadata import, caller-selected entry point or native-resource cleanup authority.
    public sealed class PublicSdkPublicationChild : IDisposable {
        private readonly System.Diagnostics.Process child=new();
        private readonly System.Diagnostics.Stopwatch scope, age=System.Diagnostics.Stopwatch.StartNew();
        private readonly Func<bool> controller;
        private readonly Action<System.Diagnostics.Process> nativeValidate;
        private readonly string[] arguments;
        private readonly string executable, root, nonce, systemRoot;
        private readonly int owner=Environment.ProcessId,thread=Environment.CurrentManagedThreadId;
        private bool started, disposed, opened;
        private static void Require(bool value) {if(!value)throw new InvalidOperationException("Pinned publication child refused.");}
        private static void Pin(byte[] value,string expected,int maximum) {
            Require(value!=null && value.Length>0 && value.Length<=maximum && expected!=null &&
                System.Text.RegularExpressions.Regex.IsMatch(expected,@"\A[a-f0-9]{64}\z"));
            Require(Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(value)).ToLowerInvariant()==expected);
        }
        private PublicSdkPublicationChild(string program,byte[] bootstrap,string codePin,string directory,string token,
            System.Diagnostics.Stopwatch originalScope,Func<bool> alive,Action<System.Diagnostics.Process> validate) {
            Require(System.IO.Path.IsPathFullyQualified(program) && System.IO.Path.IsPathFullyQualified(directory) &&
                token!=null && System.Text.RegularExpressions.Regex.IsMatch(token,@"\A[a-f0-9]{32}\z") &&
                originalScope!=null && originalScope.IsRunning && alive!=null && validate!=null);
            executable=program;root=directory;nonce=token;scope=originalScope;controller=alive;nativeValidate=validate;
            systemRoot=OperatingSystem.IsWindows()?Environment.GetEnvironmentVariable("SystemRoot"):null;
            Require(!OperatingSystem.IsWindows() || !String.IsNullOrEmpty(systemRoot));
            string code=new System.Text.UTF8Encoding(false,true).GetString(bootstrap);
            arguments=new[]{"-I","-S","-B","-c",code,codePin,root,nonce};
            var info=new System.Diagnostics.ProcessStartInfo(executable) {
                UseShellExecute=false,CreateNoWindow=true,RedirectStandardInput=true,RedirectStandardOutput=true,RedirectStandardError=true};
            info.Environment.Clear();if(OperatingSystem.IsWindows())info.Environment["SystemRoot"]=systemRoot;
            foreach(string argument in arguments)info.ArgumentList.Add(argument);
            child.StartInfo=info;
        }
        private int Remaining(bool ready=false) {
            Require(!disposed && owner==Environment.ProcessId && thread==Environment.CurrentManagedThreadId &&
                scope.IsRunning && age.IsRunning && controller());
            long value=Math.Min(420000-scope.ElapsedMilliseconds,(ready?5000:60000)-age.ElapsedMilliseconds);
            Require(value>0);return (int)value;
        }
        public void Assert(System.Diagnostics.Process actual) {
            Remaining();Require(started && Object.ReferenceEquals(actual,child));
            nativeValidate(child);
            var info=child.StartInfo;
            Require(info.FileName==executable && !info.UseShellExecute && info.CreateNoWindow &&
                info.RedirectStandardInput && info.RedirectStandardOutput && info.RedirectStandardError &&
                info.Arguments=="" && info.ArgumentList.Count==arguments.Length);
            for(int i=0;i<arguments.Length;i++)Require(info.ArgumentList[i]==arguments[i]);
            Require(info.Environment.Count==(OperatingSystem.IsWindows()?1:0));
            if(OperatingSystem.IsWindows())Require(info.Environment["SystemRoot"]==systemRoot);
        }
        private void Write(byte[] value) {
            var task=child.StandardInput.BaseStream.WriteAsync(value,0,value.Length);
            while(!task.Wait(Math.Min(100,Remaining(true))))Assert(child);
            task.GetAwaiter().GetResult();Assert(child);Remaining(true);
        }
        public static PublicSdkPublicationChild Start(string executable,byte[] bootstrap,string bootstrapPin,
            byte[] codeFrame,string framePin,string root,string nonce,System.Diagnostics.Stopwatch originalScope,
            Func<bool> controller,Action<System.Diagnostics.Process> nativeStart,Action<System.Diagnostics.Process> nativeValidate) {
            Require(nativeStart!=null);Pin(bootstrap,bootstrapPin,65536);Pin(codeFrame,framePin,12582912);
            byte[] frozenBootstrap=(byte[])bootstrap.Clone(),frozenFrame=(byte[])codeFrame.Clone();
            Pin(frozenBootstrap,bootstrapPin,65536);Pin(frozenFrame,framePin,12582912);
            var value=new PublicSdkPublicationChild(executable,frozenBootstrap,framePin,root,nonce,originalScope,controller,nativeValidate);
            try {
                value.Remaining(true);nativeStart(value.child);value.started=true;value.Assert(value.child);
                byte[] header=new byte[4];
                System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(header,(uint)frozenFrame.Length);
                value.Write(header);value.Write(frozenFrame);
                return value;
            } catch {value.Dispose();throw;}
        }
        public System.Diagnostics.Process OriginalProcess() {Assert(child);return child;}
        public PublicSdkPublicationPipe Open(PublicSdkOutputLease sdk,byte[] plan) {
            Require(!opened);opened=true;Assert(child);
            return PublicSdkPublicationPipe.Open(sdk,child,scope,age,controller,Assert,nonce,plan);
        }
        public void Dispose() {
            if(disposed)return;disposed=true;
            if(started) {
                try {child.StandardInput.Close();}catch{}
                try {if(!child.HasExited){child.Kill();child.WaitForExit(5000);}}catch{}
            }
            child.Dispose();
        }
    }

    public static class PublicBuildImageCustody {
        private static readonly AuditImageCustodyCore Core=new(67108864,new string[] {"Fixture","Root","ImageName","SourceContextSha256","SdkImage"});
        public static bool Attempted(System.Collections.IDictionary context) => Core.Attempted(context);
        public static string Build(System.Collections.IDictionary context, object client, byte[] archive, Func<Tuple<int,byte[],byte[]>> operation) => Core.Build(context,client,archive,operation);
        public static string Id(System.Collections.IDictionary context, object client) => Core.Id(context,client);
        public static DateTimeOffset Started(System.Collections.IDictionary context, object client) => Core.Started(context,client);
        public static bool Closed(System.Collections.IDictionary context, object client) => Core.Closed(context,client);
        public static Tuple<int,byte[],byte[]> Inspect(System.Collections.IDictionary context, object client, Func<Tuple<int,byte[],byte[]>> operation) => Core.Inspect(context,client,operation);
        public static void Remove(System.Collections.IDictionary context, object client, Func<Tuple<int,byte[],byte[]>> operation) => Core.Remove(context,client,operation);
        public static void Absent(System.Collections.IDictionary context, object client) => Core.Absent(context,client);
        public static void ConfirmRemoval(System.Collections.IDictionary context, object client, Func<Tuple<int,byte[],byte[]>> operation) => Core.ConfirmRemoval(context,client,operation);
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
            internal bool Unknown, TransportStarted, RestartStarted;
            internal Profile(System.Collections.IDictionary context,object client) {
                Context=context;Client=client;Values=AuditNativeReply.Values(context,Keys);
            }
        }
        private static readonly string[] Keys={"Fixture","Root","ImageName"};
        private static readonly System.Runtime.CompilerServices.ConditionalWeakTable<object,Profile> Profiles=new();
        private static readonly byte[] RestartAcknowledgement=System.Text.Encoding.ASCII.GetBytes("fleetory historical restart stop dispatched\n");
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
        public static object VerifyTransportLoss(System.Collections.IDictionary context,System.Collections.IDictionary store,object client,
            string nonce,string dockerPath) {
            if(!Guid.TryParseExact(nonce,"D",out var id) || id==Guid.Empty || id.ToString("D")!=nonce) throw Refused();
            var p=Get(context,client);
            if(System.Threading.Interlocked.CompareExchange(ref p.Busy,1,0)!=0) throw Refused();
            try {
                string target=OwnedId(p,store);
                if(p.TransportStarted || p.Calls>=64) throw Refused();
                p.TransportStarted=true;
                p.Calls++;
                p.Unknown=true; // Transport loss never becomes an application reply or permits retry.
                string config=Path.Combine(p.Context["Root"].ToString(),"transport-docker-config");
                ExclusiveAuditDirectory.Create(config);
                var proof=HistoricalDockerTransport.Verify(dockerPath,config,target,nonce);
                if(OwnedId(p,store)!=target) throw Refused();
                return proof;
            } finally {System.Threading.Volatile.Write(ref p.Busy,0);}
        }
        public static bool StopForRestart(System.Collections.IDictionary context,System.Collections.IDictionary store,object client,
            string dockerPath,Func<string[],Tuple<int,byte[],byte[]>> operation) {
            if(operation==null) throw Refused();
            var p=Get(context,client);
            if(System.Threading.Interlocked.CompareExchange(ref p.Busy,1,0)!=0) throw Refused();
            try {
                string target=OwnedId(p,store);
                if(p.RestartStarted || p.Calls>=64) throw Refused();
                p.RestartStarted=true;
                p.Unknown=true;
                p.Calls++;
                string config=Path.Combine(p.Context["Root"].ToString(),"restart-docker-config");
                ExclusiveAuditDirectory.Create(config);
                var result=HistoricalDockerTransport.StopForRestart(dockerPath,config,target,operation);
                if(OwnedId(p,store)!=target) throw Refused();
                var raw=result.Item2;
                if(raw==null) return false;
                p.Replies.Add(Tuple.Create("restart-stop",System.Security.Cryptography.SHA256.HashData(result.Item1),raw));
                if(raw.Item1!=0 || raw.Item3.Length!=0 || !raw.Item2.AsSpan().SequenceEqual(RestartAcknowledgement)) return false;
                p.Unknown=false;
                Get(context,client);
                return true;
            } catch {p.Unknown=true;throw;}
            finally {System.Threading.Volatile.Write(ref p.Busy,0);}
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
                var args=new[]{"exec","-i","-e","SSL_CERT_FILE=/tmp/ca.pem","-e","SSL_CERT_DIR=/tmp/empty-ca-dir",id,"dotnet","/tool/ServerBackendProbe.dll","--historical-supervise",mode};
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
    // Only the live native controller can obtain the target through its in-process custody.
    internal static class HistoricalDockerTransport {
        private const string Assembly = "/tool/ServerBackendProbe.dll";
        private const byte Bound = 1;
        private const byte Exited = 3;
        private static InvalidOperationException Failed(string stage) =>
            new InvalidOperationException("Audit data fixture refused: controller-transport-"+stage);
        private static void Require(bool condition,string stage) {if(!condition) throw Failed(stage);}

        private static string Endpoint => OperatingSystem.IsWindows() ?
            "npipe:////./pipe/dockerDesktopLinuxEngine" : "unix:///var/run/docker.sock";

        internal static object Verify(string path,string config,string target,string nonce) {
            using(var time=new System.Threading.CancellationTokenSource(TimeSpan.FromSeconds(25))) {
                var endpoint=Endpoint;
                using(var original=new Client(path,config,endpoint,target,"--historical-transport-hold",nonce)) {
                    byte[] claim=original.Read(24,time.Token);
                    byte[] wrongBirth=(byte[])claim.Clone();
                    wrongBirth[16]^=1;
                    using(var wrong=new Client(path,config,endpoint,target,"--historical-transport-observe",nonce))
                        wrong.ExpectRefusal(wrongBirth,time.Token);
                    using(var copied=new Client(path,config,endpoint,target,"--historical-transport-observe",Guid.NewGuid().ToString("D")))
                        copied.ExpectRefusal(claim,time.Token);
                    using(var lost=new Client(path,config,endpoint,target,"--historical-transport-observe",nonce)) {
                        lost.Bind(claim,time.Token);
                        lost.Interrupt();
                        lost.ExpectEnd(time.Token);
                    }
                    using(var observer=new Client(path,config,endpoint,target,"--historical-transport-observe",nonce)) {
                        observer.Bind(claim,time.Token);
                        original.Interrupt();
                        original.ExpectEnd(time.Token);
                        observer.Send(new byte[]{Bound},time.Token);
                        observer.CloseInput();
                        byte[] outcome=observer.Read(2,time.Token);
                        Require((outcome[0]==1 || outcome[0]==2) && outcome[1]==Exited,"outcome");
                        observer.ExpectEnd(time.Token);
                        Require(observer.Exit(time.Token)==0,"observer-exit");
                        return new {
                            hostDockerClientIdentityVerified=true, originalHostClientTerminated=true,
                            observerBoundBeforeLoss=true, daemonChildAfterLoss=outcome[0]==1?"same-live":"held-exit",
                            heldDaemonChildExitVerified=true, wrongBirthRefused=true, copiedClaimRefused=true,
                            interruptedObserverNoTerminalReceipt=true, releasedApplicationBytes=0, applicationReplyAccepted=false
                        };
                    }
                }
            }
        }

        internal static Tuple<byte[],Tuple<int,byte[],byte[]>> StopForRestart(string path,string config,string target,
            Func<string[],Tuple<int,byte[],byte[]>> operation) {
            using(var time=new System.Threading.CancellationTokenSource(TimeSpan.FromSeconds(16))) {
                using(var observer=new Client(path,config,Endpoint,target,"--historical-restart-observe")) {
                    var claim=observer.Read(12,time.Token);
                    var arguments=new[]{"exec",target,"dotnet",Assembly,"--historical-restart-stop",Convert.ToHexString(claim).ToLowerInvariant()};
                    var sent=(string[])arguments.Clone();
                    var result=operation(sent);
                    var frozen=result==null?null:AuditNativeReply.Hold(result);
                    Require(sent.AsSpan().SequenceEqual(arguments),"restart-command");
                    observer.CloseInput();
                    Require(observer.Read(1,time.Token)[0]==Exited,"restart-held-exit");
                    observer.ExpectEnd(time.Token);
                    Require(observer.Exit(time.Token)==0,"restart-observer-exit");
                    return Tuple.Create(claim,frozen);
                }
            }
        }

        private sealed class Client : IDisposable {
            private readonly System.Diagnostics.Process process;
            private readonly Microsoft.Win32.SafeHandles.SafeProcessHandle windowsHandle;
            private readonly Microsoft.Win32.SafeHandles.SafeFileHandle linuxHandle;
            private readonly Stream input,output,error;

            internal Client(string executable,string config,string endpoint,string target,params string[] command) {
                string full=Resolve(executable);
                Require(String.Equals(Path.GetFileName(full),OperatingSystem.IsWindows()?"docker.exe":"docker",
                    OperatingSystem.IsWindows()?StringComparison.OrdinalIgnoreCase:StringComparison.Ordinal),"executable");
                var options=new System.Diagnostics.ProcessStartInfo(full) {
                    UseShellExecute=false,CreateNoWindow=true,RedirectStandardInput=true,RedirectStandardOutput=true,RedirectStandardError=true
                };
                options.Environment.Clear();
                if(OperatingSystem.IsWindows())
                    options.Environment["SystemRoot"]=Environment.GetEnvironmentVariable("SystemRoot");
                foreach(string word in new[]{"--config",config,"--host",endpoint,"exec","-i","-e","SSL_CERT_FILE=/tmp/ca.pem",
                    "-e","SSL_CERT_DIR=/tmp/empty-ca-dir",target,"dotnet",Assembly}) options.ArgumentList.Add(word);
                foreach(string word in command) options.ArgumentList.Add(word);
                process=System.Diagnostics.Process.Start(options);
                Require(process!=null,"start");
                try {
                    if(OperatingSystem.IsWindows()) windowsHandle=process.SafeHandle;
                    else {
                        int descriptor=OpenPidfd(process.Id,0);
                        Require(descriptor>=0,"host-pidfd");
                        linuxHandle=new Microsoft.Win32.SafeHandles.SafeFileHandle(new IntPtr(descriptor),ownsHandle:true);
                    }
                    Require(!process.HasExited && String.Equals(ActualImage(),full,
                        OperatingSystem.IsWindows()?StringComparison.OrdinalIgnoreCase:StringComparison.Ordinal) && !process.HasExited,"host-image");
                    input=process.StandardInput.BaseStream;
                    output=process.StandardOutput.BaseStream;
                    error=process.StandardError.BaseStream;
                } catch {
                    Dispose();
                    throw;
                }
            }

            private string ActualImage() {
                if(windowsHandle==null) return Resolve("/proc/"+process.Id+"/exe");
                var path=new System.Text.StringBuilder(32768);
                int length=path.Capacity;
                Require(QueryFullProcessImageName(windowsHandle,0,path,ref length) && length>0,"windows-image");
                return Resolve(path.ToString());
            }

            private static string Resolve(string path) {
                var file=new FileInfo(path);
                return file.ResolveLinkTarget(true)?.FullName ?? file.FullName;
            }

            internal byte[] Read(int length,System.Threading.CancellationToken token) {
                var bytes=new byte[length];
                output.ReadExactlyAsync(bytes.AsMemory(),token).AsTask().WaitAsync(token).GetAwaiter().GetResult();
                return bytes;
            }

            internal void Send(byte[] bytes,System.Threading.CancellationToken token) {
                input.WriteAsync(bytes.AsMemory(),token).AsTask().WaitAsync(token).GetAwaiter().GetResult();
                input.FlushAsync(token).WaitAsync(token).GetAwaiter().GetResult();
            }

            internal void CloseInput() => input.Dispose();

            internal void Bind(byte[] claim,System.Threading.CancellationToken token) {
                Send(claim,token);
                Require(Read(1,token)[0]==Bound,"observer-bind");
            }

            private static bool Empty(Stream stream,System.Threading.CancellationToken token) =>
                stream.ReadAsync(new byte[1].AsMemory(),token).AsTask().WaitAsync(token).GetAwaiter().GetResult()==0;

            internal void ExpectEnd(System.Threading.CancellationToken token) =>
                Require(Empty(output,token) && Empty(error,token),"trailing-bytes");

            internal int Exit(System.Threading.CancellationToken token) {
                process.WaitForExitAsync(token).GetAwaiter().GetResult();
                return process.ExitCode;
            }

            internal void ExpectRefusal(byte[] claim,System.Threading.CancellationToken token) {
                Send(claim,token);
                CloseInput();
                ExpectEnd(token);
                Require(Exit(token)==1,"negative-claim");
            }

            private bool Stop() {
                if(windowsHandle!=null) return TerminateProcess(windowsHandle,1);
                return linuxHandle!=null && SignalPidfd(linuxHandle,9,IntPtr.Zero,0)==0;
            }

            internal void Interrupt() =>
                Require(!process.HasExited && Stop() && process.WaitForExit(3000) && process.ExitCode!=0,"host-interruption");

            public void Dispose() {
                try {
                    if(!process.HasExited && Stop()) process.WaitForExit(3000);
                } finally {
                    linuxHandle?.Dispose();
                    process.Dispose();
                }
            }
        }

        [DllImport("kernel32",EntryPoint="QueryFullProcessImageNameW",CharSet=CharSet.Unicode,ExactSpelling=true,SetLastError=true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool QueryFullProcessImageName(Microsoft.Win32.SafeHandles.SafeProcessHandle handle,uint flags,
            System.Text.StringBuilder path,ref int length);
        [DllImport("kernel32",SetLastError=true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool TerminateProcess(Microsoft.Win32.SafeHandles.SafeProcessHandle handle,uint code);
        [DllImport("libc",EntryPoint="pidfd_open",SetLastError=true)]
        private static extern int OpenPidfd(int pid,uint flags);
        [DllImport("libc",EntryPoint="pidfd_send_signal",SetLastError=true)]
        private static extern int SignalPidfd(Microsoft.Win32.SafeHandles.SafeFileHandle handle,int signal,IntPtr info,uint flags);
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
