using System.Buffers.Binary;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace ServerBackendProbe;

// The fixed private Linux fixture entrypoint for historical controller probes.
internal static partial class HistoricalProbeProcess
{
    private const string EntryAssembly = "/tool/ServerBackendProbe.dll";
    private const int RequestLimit = 4096;
    private const int ReplyLimit = 128 * 1024;
    private const int IncompleteExit = 65;
    private static readonly byte[] Ready = "fleetory historical probe ready\n"u8.ToArray();

    internal static bool IsMode(string mode) => mode is
        "audit-health" or "history-users" or "observation-history-read" or "observation-reader-denial";

    internal static bool IsTransportNonce(string value) =>
        Guid.TryParseExact(value, "D", out var nonce) && nonce != Guid.Empty && nonce.ToString("D") == value;

    internal static async Task<int> HoldTransportAsync(string nonce)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        try
        {
            RequireProbeRuntime();
            await RunOwnedAsync("observation-history-read", 1, ReadOnlyMemory<byte>.Empty, deadline.Token, nonce);
            // The fault-only entrypoint never emits an application success reply.
            return IncompleteExit;
        }
        catch (Exception)
        {
            return 1;
        }
    }

    internal static async Task<int> ObserveTransportAsync(string nonce)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var cancellation = deadline.Token;
        try
        {
            RequireProbeRuntime();
            using var input = Console.OpenStandardInput();
            using var output = Console.OpenStandardOutput();
            var claim = new byte[24];
            await input.ReadExactlyAsync(claim, cancellation);
            var parent = BinaryPrimitives.ReadInt32LittleEndian(claim);
            var parentBirth = BinaryPrimitives.ReadUInt64LittleEndian(claim.AsSpan(4));
            var child = BinaryPrimitives.ReadInt32LittleEndian(claim.AsSpan(12));
            var childBirth = BinaryPrimitives.ReadUInt64LittleEndian(claim.AsSpan(16));
            if (parent <= 1 || child <= 1 || parent == child || parentBirth == 0 || childBirth == 0)
                throw Refused();

            var descriptor = PidfdOpen(child, 0);
            if (descriptor < 0)
                throw Refused();
            using var held = new SafeFileHandle(new IntPtr(descriptor), ownsHandle: true);
            var executable = Environment.ProcessPath ?? throw Refused();
            var parentCommand = new[] { EntryAssembly, "--historical-transport-hold", nonce };
            var childCommand = new[] { EntryAssembly, "--historical-leaf", "observation-history-read" };
            if (ObserveBirth(parent, executable, command: parentCommand) != parentBirth ||
                ObserveBirth(child, executable, parent, childCommand) != childBirth ||
                ObserveBirth(parent, executable, command: parentCommand) != parentBirth ||
                HasExited(descriptor, 0))
                throw Refused();

            await WriteTransportByteAsync(output, 1, cancellation);
            var control = new byte[1];
            await input.ReadExactlyAsync(control, cancellation);
            if (control[0] != 1 || await input.ReadAsync(control, cancellation) != 0)
                throw Refused();

            // This is the same read-only descriptor held before the original client disconnected.
            await WriteTransportByteAsync(output, HasExited(descriptor, 0) ? (byte)2 : (byte)1, cancellation);
            if (!HasExited(descriptor, 12000))
                throw Refused();
            await WriteTransportByteAsync(output, 3, cancellation);
            return 0;
        }
        catch (Exception)
        {
            return 1;
        }
    }

    private const string DaemonPath = "/usr/sbin/immudb";
    private const string DaemonDirectory = "/data";
    private const string DaemonPidFile = DaemonDirectory + "/immudb.pid";
    private const string RestartAcknowledgement = "fleetory historical restart stop dispatched";

    internal static async Task<int> ObserveRestartAsync()
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(16));
        try
        {
            RequireProbeRuntime();
            using var input = Console.OpenStandardInput();
            using var output = Console.OpenStandardOutput();
            var daemon = ReadDaemonPid();
            using var held = HoldDaemon(daemon, out var birth, out var descriptor);
            var claim = new byte[12];
            BinaryPrimitives.WriteInt32LittleEndian(claim, daemon);
            BinaryPrimitives.WriteUInt64LittleEndian(claim.AsSpan(4), birth);
            await output.WriteAsync(claim, deadline.Token);
            await output.FlushAsync(deadline.Token);
            if (await input.ReadAsync(new byte[1], deadline.Token) != 0 || !HasExited(descriptor, 12000))
                throw Refused();
            await WriteTransportByteAsync(output, 3, deadline.Token);
            return 0;
        }
        catch (Exception)
        {
            return 1;
        }
    }

    internal static int StopHistoricalDaemon(string encoded)
    {
        try
        {
            RequireProbeRuntime();
            if (encoded.Length != 24)
                throw Refused();
            var claim = Convert.FromHexString(encoded);
            if (Convert.ToHexStringLower(claim) != encoded)
                throw Refused();
            var daemon = ReadDaemonPid();
            using var held = HoldDaemon(daemon, out var birth, out _);
            if (daemon != BinaryPrimitives.ReadInt32LittleEndian(claim) ||
                birth != BinaryPrimitives.ReadUInt64LittleEndian(claim.AsSpan(4)) ||
                PidfdSendSignal(held, 15, IntPtr.Zero, 0) != 0)
                throw Refused();
            Console.WriteLine(RestartAcknowledgement);
            return 0;
        }
        catch (Exception)
        {
            return 1;
        }
    }

    private static int ReadDaemonPid()
    {
        RequirePrivatePath(DaemonDirectory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute, FileAttributes.Directory);
        var file = new FileInfo(DaemonPidFile);
        if (file.Length is < 1 or > 12 ||
            (file.Attributes & (FileAttributes.ReparsePoint | FileAttributes.Directory)) != 0)
            throw Refused();
        var text = File.ReadAllText(DaemonPidFile).Trim();
        if (!int.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out var pid) ||
            pid <= 1 || pid.ToString(CultureInfo.InvariantCulture) != text)
            throw Refused();
        return pid;
    }

    private static SafeFileHandle HoldDaemon(int pid, out ulong birth, out int descriptor)
    {
        descriptor = PidfdOpen(pid, 0);
        if (descriptor < 0)
            throw Refused();
        var held = new SafeFileHandle(new IntPtr(descriptor), ownsHandle: true);
        try
        {
            birth = ObserveBirth(pid, DaemonPath);
            if (ObserveBirth(pid, DaemonPath) != birth || HasExited(descriptor, 0))
                throw Refused();
            return held;
        }
        catch
        {
            held.Dispose();
            throw;
        }
    }

    private static async Task WriteTransportByteAsync(Stream output, byte value, CancellationToken cancellation)
    {
        await output.WriteAsync(new[] { value }, cancellation);
        await output.FlushAsync(cancellation);
    }

    private static async Task HoldBeforePayloadAsync(int child, ulong birth, string executable, CancellationToken cancellation)
    {
        var claim = new byte[24];
        BinaryPrimitives.WriteInt32LittleEndian(claim, Environment.ProcessId);
        BinaryPrimitives.WriteUInt64LittleEndian(claim.AsSpan(4), ObserveBirth(Environment.ProcessId, executable));
        BinaryPrimitives.WriteInt32LittleEndian(claim.AsSpan(12), child);
        BinaryPrimitives.WriteUInt64LittleEndian(claim.AsSpan(16), birth);
        using var output = Console.OpenStandardOutput();
        await output.WriteAsync(claim, cancellation);
        await output.FlushAsync(cancellation);
        await Task.Delay(TimeSpan.FromSeconds(10), cancellation);
    }

    private static void RequireProbeRuntime()
    {
        if (!OperatingSystem.IsLinux() || typeof(HistoricalProbeProcess).Assembly.Location != EntryAssembly)
            throw Refused();
    }

    internal static async Task<int> SuperviseAsync(string mode)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(35));
        var cancellation = timeout.Token;
        try
        {
            RequireProbeRuntime();
            using var input = Console.OpenStandardInput();
            var request = await ReceiveAsync(input, RequestLimit + 1, cancellation);
            try
            {
                if (!IsMode(mode) || request.Length < 2 || request[0] > 2)
                    throw Refused();
                var result = await RunOwnedAsync(mode, request[0], request.AsMemory(1), cancellation);
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
            RequireProbeRuntime();
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

    private static async Task<object> RunOwnedAsync(string mode, byte fault, ReadOnlyMemory<byte> request, CancellationToken cancellation, string? transportNonce = null)
    {
        var executable = Environment.ProcessPath ?? throw Refused();
        var command = new ProcessStartInfo(executable)
        {
            UseShellExecute = false, RedirectStandardInput = true,
            RedirectStandardOutput = true, RedirectStandardError = true
        };
        command.ArgumentList.Add(EntryAssembly);
        command.ArgumentList.Add("--historical-leaf");
        command.ArgumentList.Add(mode);
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
            var birth = ObserveBirth(process.Id, executable, Environment.ProcessId);
            if (ObserveBirth(process.Id, executable, Environment.ProcessId) != birth || HasExited(descriptor, 0) || process.HasExited)
                throw Refused();
            bound = true;

            if (transportNonce is not null)
                await HoldBeforePayloadAsync(process.Id, birth, executable, cancellation);
            else if (fault == 2)
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
                mode,
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

    private static ulong ObserveBirth(int pid, string executable, int? parent = null, string[]? command = null)
    {
        var path = "/proc/" + pid.ToString(CultureInfo.InvariantCulture);
        var stat = File.ReadAllText(path + "/stat");
        var end = stat.LastIndexOf(')');
        if (end < 0 || end + 2 >= stat.Length)
            throw Refused();
        var fields = stat[(end + 2)..].Split(' ', StringSplitOptions.RemoveEmptyEntries);
        var expected = new FileInfo(executable).ResolveLinkTarget(true)?.FullName ?? executable;
        if (fields.Length < 20 || fields[0] is "Z" or "X" ||
            (parent is not null && fields[1] != parent.Value.ToString(CultureInfo.InvariantCulture)) ||
            new FileInfo(path + "/exe").ResolveLinkTarget(true)?.FullName != expected ||
            !ulong.TryParse(fields[19], NumberStyles.None, CultureInfo.InvariantCulture, out var birth) || birth == 0)
            throw Refused();
        if (command is not null)
        {
            var actual = File.ReadAllText(path + "/cmdline").Split('\0');
            if (actual.Length != command.Length + 2 || actual[^1] != "" || !actual.AsSpan(1, command.Length).SequenceEqual(command))
                throw Refused();
        }
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
