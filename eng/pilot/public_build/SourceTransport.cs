using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

// Bounded transport only. The source child owns no native resources.
// This class confers no Docker, SDK or original-input admission authority.
namespace Fleetory.Pilot;

public sealed class PublicBuildSourceTransport : IDisposable
{
    private readonly Process child;
    private readonly Stopwatch age;
    private readonly int deadline;
    private bool taken, frameVerified, attempted, disposed;
    private Task<int> unexpectedOutput;
    private readonly byte[] monitorByte=new byte[1];
    public PublicBuildSourceTransport(Process sourceOnlyChild, Stopwatch originalAge, int deadlineMilliseconds)
    {
        if (sourceOnlyChild == null || originalAge == null || !originalAge.IsRunning ||
            deadlineMilliseconds <= 0 || deadlineMilliseconds > 420000)
            throw new ArgumentException("Invalid source-only transport");
        child = sourceOnlyChild; age = originalAge; deadline = deadlineMilliseconds;
    }
    private int Remaining()
    {
        long remaining = deadline - age.ElapsedMilliseconds;
        if (disposed || remaining <= 0 || child.HasExited)
            throw new IOException("Source-only peer unavailable");
        return (int)remaining;
    }
    private void Await(Task task)
    {
        if (!task.Wait(Remaining())) throw new TimeoutException("Source-only transport deadline");
        task.GetAwaiter().GetResult();
    }
    private byte[] Read(int count)
    {
        byte[] result = new byte[count]; int offset = 0;
        while (offset < count)
        {
            Remaining();
            Task<int> task = child.StandardOutput.BaseStream.ReadAsync(result, offset, count-offset);
            Await(task); int actual = task.GetAwaiter().GetResult();
            if (actual <= 0) throw new IOException("Truncated source frame");
            offset += actual;
        }
        return result;
    }
    public byte[] Take(byte[] expectedDigest)
    {
        if (taken || expectedDigest == null || expectedDigest.Length != 32)
            throw new InvalidOperationException("Source frame attempt refused");
        taken = true; // Consume before the first blocking read, including failed attempts.
        byte[] header = Read(60);
        if (Encoding.ASCII.GetString(header, 0, 8) != "FLTPUB01") throw new IOException("Source magic refused");
        uint size = ((uint)header[8]<<24)|((uint)header[9]<<16)|((uint)header[10]<<8)|header[11];
        if (size == 0 || size > 64*1024*1024) throw new IOException("Source length refused");
        byte[] declared = new byte[32]; Buffer.BlockCopy(header,12,declared,0,32);
        if (!CryptographicOperations.FixedTimeEquals(declared,expectedDigest)) throw new IOException("Source pin refused");
        bool nonzero = false; for (int i=44;i<60;i++) nonzero |= header[i]!=0;
        if (!nonzero) throw new IOException("Source nonce refused");
        byte[] body = Read((int)size);
        if (!CryptographicOperations.FixedTimeEquals(SHA256.HashData(body),expectedDigest)) throw new IOException("Source bytes refused");
        Remaining(); frameVerified=true; return body;
    }
    public void RequestBeforeSdk()
    {
        if (!frameVerified || attempted) throw new InvalidOperationException("Source permit attempt refused");
        attempted=true; Remaining();
        Await(child.StandardInput.BaseStream.WriteAsync(new byte[]{83},0,1));
        Await(child.StandardInput.BaseStream.FlushAsync());
        if (Read(1)[0] != 1) throw new IOException("Source permit refused");
        Remaining();
        unexpectedOutput=child.StandardOutput.BaseStream.ReadAsync(monitorByte,0,1);
    }
    public bool IsAlive()
    {
        try
        {
            Remaining();
            return frameVerified && (unexpectedOutput==null || !unexpectedOutput.IsCompleted);
        }
        catch (IOException) { return false; }
    }
    public void Dispose()
    {
        if (disposed) return; disposed=true;
        // This Process is only the source child; never the resource-owning worker.
        try { child.StandardInput.Close(); } catch (IOException) { }
        if (!child.WaitForExit(1000)) { child.Kill(); if (!child.WaitForExit(5000)) throw new IOException("Source child exit unconfirmed"); }
        child.Dispose();
    }
}
