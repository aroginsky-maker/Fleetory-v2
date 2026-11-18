using System.Buffers.Binary;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace ServerBackendProbe;

// A private Linux fixture entrypoint for exactly one real application operation.
internal static partial class HistoricalProbeProcess
{
    internal const string Mode = "observation-history-read";
    private const string EntryAssembly = "/tool/ServerBackendProbe.dll";
    private const int RequestLimit = 4096;
    private const int ReplyLimit = 128 * 1024;
    private const int IncompleteExit = 65;
    private static readonly byte[] Ready = "fleetory historical probe ready\n"u8.ToArray();

    internal static async Task<int> SuperviseAsync()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(35));
        var cancellation = timeout.Token;
        try
        {
            if (!OperatingSystem.IsLinux() || typeof(HistoricalProbeProcess).Assembly.Location != EntryAssembly)
                throw Refused();
            using var input = Console.OpenStandardInput();
            var request = await ReceiveAsync(input, RequestLimit + 1, cancellation);
            try
            {
                if (request.Length < 2 || request[0] > 2)
                    throw Refused();
                var result = await RunOwnedAsync(request[0], request.AsMemory(1), cancellation);
                await Console.Out.WriteLineAsync(JsonSerializer.Serialize(result).AsMemory(), cancellation);
                return 0;
            }
            finally
            {
                Array.Clear(request);
            }
        }
        catch (Exception)
        {
            await Console.Error.WriteLineAsync("Historical probe process refused.");
            return 1;
        }
    }

    internal static async Task<int> RunLeafAsync(Func<Stream, Task<int>> operation)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(12));
        try
        {
            if (!OperatingSystem.IsLinux() || typeof(HistoricalProbeProcess).Assembly.Location != EntryAssembly)
                throw Refused();
            var output = Console.OpenStandardOutput();
            await output.WriteAsync(Ready, deadline.Token);
            await output.FlushAsync(deadline.Token);
            using var input = Console.OpenStandardInput();
            var header = new byte[4];
            await input.ReadExactlyAsync(header, deadline.Token);
            var count = BinaryPrimitives.ReadInt32BigEndian(header);
            if (count is < 1 or > RequestLimit)
                throw Refused();
            var packet = new byte[count];
            try
            {
                await input.ReadExactlyAsync(packet, deadline.Token);
                if (await input.ReadAsync(header.AsMemory(0, 1), deadline.Token) != 0)
                    throw Refused();
                using var privatePacket = new MemoryStream(packet, writable: false);
                return await operation(privatePacket);
            }
            finally
            {
                Array.Clear(packet);
            }
        }
        catch (EndOfStreamException)
        {
            return IncompleteExit;
        }
        catch (Exception)
        {
            await Console.Error.WriteLineAsync("Historical probe leaf refused.");
            return 1;
        }
    }

    private static async Task<object> RunOwnedAsync(byte fault, ReadOnlyMemory<byte> request, CancellationToken cancellation)
    {
        var executable = Environment.ProcessPath ?? throw Refused();
        var command = new ProcessStartInfo(executable)
        {
            UseShellExecute = false, RedirectStandardInput = true,
            RedirectStandardOutput = true, RedirectStandardError = true
        };
        command.ArgumentList.Add(EntryAssembly);
        command.ArgumentList.Add("--historical-leaf");
        var trust = ReadPrivateFixtureTrust();
        command.Environment.Clear();
        command.Environment.Add("HOME", trust.Home);
        command.Environment.Add("SSL_CERT_FILE", trust.Certificate);
        command.Environment.Add("SSL_CERT_DIR", trust.EmptyStore);
        using var process = Process.Start(command) ?? throw Refused();
        using var input = process.StandardInput.BaseStream;
        var descriptor = PidfdOpen(process.Id, 0);
        if (descriptor < 0)
            throw Refused();
        using var held = new SafeFileHandle(new IntPtr(descriptor), ownsHandle: true);
        var bound = false;
        bool clean;
        object evidence;
        try
        {
            var stdout = process.StandardOutput.BaseStream;
            var ready = new byte[Ready.Length];
            await stdout.ReadExactlyAsync(ready, cancellation);
            if (!ready.AsSpan().SequenceEqual(Ready) || HasExited(descriptor, 0) || process.HasExited)
                throw Refused();
            var birth = ObserveOwnedBirth(process.Id, executable);
            if (ObserveOwnedBirth(process.Id, executable) != birth || HasExited(descriptor, 0) || process.HasExited)
                throw Refused();
            bound = true;

            if (fault == 2)
                Signal(held, descriptor);
            else
                await SendAsync(input, request, fault == 1, cancellation);
            await input.DisposeAsync();
            var replyTask = ReceiveAsync(stdout, ReplyLimit, cancellation);
            var errorTask = ReceiveAsync(process.StandardError.BaseStream, 4096, cancellation);
            await Task.WhenAll(replyTask, errorTask, process.WaitForExitAsync(cancellation));
            var reply = await replyTask;
            if (!HasExited(descriptor, 0) || (await errorTask).Length != 0 || !MatchesOutcome(fault, process.ExitCode, reply.Length))
                throw Refused();
            evidence = new
            {
                schema = "fleetory.historical-dotnet-probe.v1",
                mode = Mode,
                fault,
                heldBirthVerified = true,
                heldExitVerified = true,
                childExitCode = process.ExitCode,
                payloadBytesReleased = fault == 0 ? request.Length : 0,
                stdout = Convert.ToBase64String(reply)
            };
        }
        finally
        {
            clean = await CloseOwnedAsync(input, held, descriptor, bound);
        }
        if (!clean)
            throw Refused();
        return evidence;
    }

    private static async Task<bool> CloseOwnedAsync(Stream input, SafeFileHandle held, int descriptor, bool bound)
    {
        bool inputClosed;
        try
        {
            await input.DisposeAsync();
            inputClosed = true;
        }
        catch (Exception)
        {
            // A pipe failure cannot remove the obligation to stop the verified leaf.
            inputClosed = false;
        }
        try
        {
            if (!bound || HasExited(descriptor, 0))
                return inputClosed;
            Signal(held, descriptor);
            return HasExited(descriptor, 3000) && inputClosed;
        }
        catch (Exception)
        {
            return false;
        }
    }

    private static (string Home, string Certificate, string EmptyStore) ReadPrivateFixtureTrust()
    {
        if (!OperatingSystem.IsLinux())
            throw Refused();
        var parent = Path.TrimEndingDirectorySeparator(Path.GetTempPath());
        var certificate = Path.Combine(parent, "ca.pem");
        var empty = Path.Combine(parent, "empty-ca-dir");
        if (Environment.GetEnvironmentVariable("SSL_CERT_FILE") != certificate || Environment.GetEnvironmentVariable("SSL_CERT_DIR") != empty)
            throw Refused();
        var directory = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
        RequirePrivatePath(parent, directory, FileAttributes.Directory);
        RequirePrivatePath(certificate, UnixFileMode.UserRead | UnixFileMode.UserWrite, 0);
        RequirePrivatePath(empty, directory, FileAttributes.Directory);
        if (Directory.EnumerateFileSystemEntries(empty).Any())
            throw Refused();
        return (parent, certificate, empty);
    }

    private static void RequirePrivatePath(string path, UnixFileMode mode, FileAttributes kind)
    {
        if (!OperatingSystem.IsLinux() ||
            (File.GetAttributes(path) & (FileAttributes.ReparsePoint | FileAttributes.Directory)) != kind ||
            File.GetUnixFileMode(path) != mode)
            throw Refused();
    }

    private static bool MatchesOutcome(byte fault, int exit, int replyLength) => fault switch
    {
        0 => exit is 0 or 1 && replyLength > 0,
        1 => exit == IncompleteExit && replyLength == 0,
        2 => exit == 137 && replyLength == 0,
        _ => false
    };

    private static async Task SendAsync(Stream stream, ReadOnlyMemory<byte> request, bool truncate, CancellationToken cancellation)
    {
        var size = new byte[4];
        BinaryPrimitives.WriteInt32BigEndian(size, request.Length);
        await stream.WriteAsync(size, cancellation);
        if (!truncate)
            await stream.WriteAsync(request, cancellation);
        await stream.FlushAsync(cancellation);
    }

    private static async Task<byte[]> ReceiveAsync(Stream input, int maximum, CancellationToken cancellation)
    {
        var buffer = new byte[maximum + 1];
        try
        {
            var used = 0;
            while (used < buffer.Length)
            {
                var read = await input.ReadAsync(buffer.AsMemory(used), cancellation);
                if (read == 0)
                    return buffer[..used];
                used += read;
            }
            throw Refused();
        }
        finally
        {
            Array.Clear(buffer);
        }
    }

    private static ulong ObserveOwnedBirth(int pid, string executable)
    {
        var path = "/proc/" + pid.ToString(CultureInfo.InvariantCulture);
        var stat = File.ReadAllText(path + "/stat");
        var end = stat.LastIndexOf(')');
        if (end < 0 || end + 2 >= stat.Length)
            throw Refused();
        var fields = stat[(end + 2)..].Split(' ', StringSplitOptions.RemoveEmptyEntries);
        var expected = new FileInfo(executable).ResolveLinkTarget(true)?.FullName ?? executable;
        if (fields.Length < 20 || fields[0] is "Z" or "X" ||
            fields[1] != Environment.ProcessId.ToString(CultureInfo.InvariantCulture) ||
            new FileInfo(path + "/exe").ResolveLinkTarget(true)?.FullName != expected ||
            !ulong.TryParse(fields[19], NumberStyles.None, CultureInfo.InvariantCulture, out var birth) || birth == 0)
            throw Refused();
        return birth;
    }

    private static void Signal(SafeFileHandle held, int descriptor)
    {
        if (PidfdSendSignal(held, 9, IntPtr.Zero, 0) != 0 && !HasExited(descriptor, 0))
            throw Refused();
    }

    private static bool HasExited(int descriptor, int milliseconds)
    {
        var poll = new PollDescriptor(descriptor);
        var ready = Poll(ref poll, 1, milliseconds);
        if (ready < 0 || (ready != 0 && (poll.Returned & 1) == 0))
            throw Refused();
        return ready == 1;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PollDescriptor(int fd)
    {
        internal int Descriptor = fd;
        internal short Events = 1;
        internal short Returned = 0;
    }

    [LibraryImport("libc", EntryPoint = "pidfd_open", SetLastError = true)]
    private static partial int PidfdOpen(int pid, uint flags);

    [LibraryImport("libc", EntryPoint = "pidfd_send_signal", SetLastError = true)]
    private static partial int PidfdSendSignal(SafeFileHandle fd, int signal, IntPtr info, uint flags);

    [LibraryImport("libc", EntryPoint = "poll", SetLastError = true)]
    private static partial int Poll(ref PollDescriptor descriptor, nuint count, int milliseconds);

    private static InvalidOperationException Refused() => new("Historical probe process refused.");
}
