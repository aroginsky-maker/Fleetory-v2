#requires -Version 7.3
# A trusted-host byte lease, not release provenance or native-resource custody.
if (-not ('Fleetory.Pilot.NativeExecutableLease' -as [type])) {
    Add-Type -ErrorAction Stop -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;
namespace Fleetory.Pilot {
    public sealed class NativeExecutableLease : IDisposable {
        private static readonly ConditionalWeakTable<Process,NativeExecutableLease> Started=new();
        private readonly int owner=Environment.ProcessId, thread=Environment.CurrentManagedThreadId;
        private readonly string path, digest;
        private readonly FileStream file;
        private readonly string linuxIdentity;
        private readonly List<SafeFileHandle> directories=new();
        private bool closed;
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]
        private static extern SafeFileHandle CreateFileW(string name,uint access,uint share,IntPtr security,uint disposition,uint flags,IntPtr template);
        [StructLayout(LayoutKind.Explicit,Size=256)]
        private struct LinuxStatx {
            [FieldOffset(0)] internal uint Mask;
            [FieldOffset(16)] internal uint Links;
            [FieldOffset(28)] internal ushort Mode;
            [FieldOffset(32)] internal ulong Inode;
            [FieldOffset(136)] internal uint DeviceMajor;
            [FieldOffset(140)] internal uint DeviceMinor;
        }
        [DllImport("libc",EntryPoint="statx",SetLastError=true)]
        private static extern int Statx(int directory,string name,int flags,uint mask,out LinuxStatx value);
        private static string LinuxIdentity(int directory,string name,int flags) {
            Require(Statx(directory,name,flags,0x7ff,out var value)==0 && (value.Mask&0x105)==0x105);
            Require(value.Links==1 && (value.Mode&0xf000)==0x8000);
            return value.DeviceMajor+":"+value.DeviceMinor+":"+value.Inode;
        }
        private static void Require(bool value) {if(!value) throw new InvalidOperationException("Native executable lease refused.");}
        private static StringComparison Comparison => OperatingSystem.IsWindows()?StringComparison.OrdinalIgnoreCase:StringComparison.Ordinal;
        public NativeExecutableLease(string trustedPath,string expectedSha256) {
            Require(OperatingSystem.IsWindows() || OperatingSystem.IsLinux());
            Require(Path.IsPathFullyQualified(trustedPath) && expectedSha256!=null && expectedSha256.Length==64);
            foreach(char c in expectedSha256) Require(c>='0' && c<='9' || c>='a' && c<='f');
            path=Path.GetFullPath(trustedPath);digest=expectedSha256;
            try {
                Require((File.GetAttributes(path)&(FileAttributes.Directory|FileAttributes.ReparsePoint))==0);
                for(var parent=Directory.GetParent(path);parent!=null;parent=parent.Parent) {
                    Require((parent.Attributes&FileAttributes.ReparsePoint)==0);
                    if(OperatingSystem.IsWindows()) {
                        // Share normal directory I/O, but deny deletion/rename while launching by path.
                        var handle=CreateFileW(parent.FullName,0x80,3,IntPtr.Zero,3,0x02200000,IntPtr.Zero);
                        Require(!handle.IsInvalid);directories.Add(handle);
                        Require((parent.Attributes&FileAttributes.ReparsePoint)==0);
                    }
                }
                file=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read);
                Require(file.Length>0 && file.Length<=67108864);
                if(OperatingSystem.IsLinux()) linuxIdentity=LinuxIdentity(file.SafeFileHandle.DangerousGetHandle().ToInt32(),"",0x1000);
                Check();
            } catch {Dispose();throw;}
        }
        public void Check() {
            Require(!closed && owner==Environment.ProcessId && thread==Environment.CurrentManagedThreadId && file!=null);
            Require((File.GetAttributes(path)&(FileAttributes.Directory|FileAttributes.ReparsePoint))==0);
            if(OperatingSystem.IsLinux()) {
                Require(linuxIdentity==LinuxIdentity(file.SafeFileHandle.DangerousGetHandle().ToInt32(),"",0x1000));
                Require(linuxIdentity==LinuxIdentity(-100,path,0x100));
            }
            file.Position=0;
            Require(Convert.ToHexString(SHA256.HashData(file)).ToLowerInvariant()==digest);
            file.Position=0;
            using(var current=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read))
                Require(current.Length==file.Length && Convert.ToHexString(SHA256.HashData(current)).ToLowerInvariant()==digest);
        }
        public string GetLaunchPath() {
            Check();
            return OperatingSystem.IsLinux()?"/proc/"+owner+"/fd/"+file.SafeFileHandle.DangerousGetHandle().ToInt64():path;
        }
        public Tuple<string,string,long> Describe() { Check();return Tuple.Create(path,digest,file.Length); }
        public void ValidateRequest(string requested) {
            Check();
            Require(Path.IsPathFullyQualified(requested) && String.Equals(Path.GetFullPath(requested),path,Comparison));
        }
        public void Start(Process process) {
            Require(process!=null && !process.StartInfo.UseShellExecute && String.Equals(process.StartInfo.FileName,GetLaunchPath(),Comparison));
            bool launched=false;
            try {
                Require(process.Start());launched=true;
                string actual=null;
                var startup=Stopwatch.StartNew();
                while(actual==null) {
                    Require(!process.HasExited && startup.ElapsedMilliseconds<1000);
                    actual=process.MainModule?.FileName;
                    if(actual==null) System.Threading.Thread.Sleep(5);
                }
                Require(String.Equals(Path.GetFullPath(actual),path,Comparison));
                if(OperatingSystem.IsLinux()) Require(linuxIdentity==LinuxIdentity(-100,"/proc/"+process.Id+"/exe",0));
                var handle=process.Handle;
                Require(handle!=IntPtr.Zero && !process.HasExited);
                Started.Add(process,this);
            } catch {
                if(launched) {try {if(!process.HasExited) process.Kill(true);} catch {} try {process.WaitForExit(2000);} catch {}}
                throw;
            }
        }
        public static void AssertStarted(Process process) {
            Require(process!=null);
            Require(Started.TryGetValue(process,out var lease));
            lease.Check();
            Require(!process.HasExited);
        }
        public void Dispose() {
            if(closed) return;
            closed=true;file?.Dispose();
            foreach(var handle in directories) handle.Dispose();
            directories.Clear();
        }
    }
}
'@
}
