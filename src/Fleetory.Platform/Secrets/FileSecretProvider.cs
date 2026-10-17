using System.Collections.Concurrent;
using System.Text;
using Fleetory.Platform.Contracts.Secrets;

namespace Fleetory.Platform.Secrets;

public sealed class FileSecretProvider : ISecretProvider
{
    private const int MaximumSecretBytes = 16 * 1024;
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private readonly string directory;
    private readonly ConcurrentDictionary<string, Lazy<string>> cache = new(StringComparer.Ordinal);

    public FileSecretProvider(string directory)
    {
        if (string.IsNullOrWhiteSpace(directory) || !Path.IsPathFullyQualified(directory))
        {
            throw new InvalidOperationException("Fleetory:Secrets:Directory must be an absolute path.");
        }

        this.directory = Path.GetFullPath(directory);
    }

    public string GetRequiredSecret(string name)
    {
        SecretName.Validate(name);

        return cache.GetOrAdd(name, key => new Lazy<string>(
            () => ReadSecret(key), LazyThreadSafetyMode.ExecutionAndPublication)).Value;
    }

    private string ReadSecret(string name)
    {
        var path = Path.Combine(directory, name);
        try
        {
            if (!OperatingSystem.IsWindows())
            {
                var mode = File.GetUnixFileMode(path);
                const UnixFileMode unsafeBits = UnixFileMode.GroupRead | UnixFileMode.GroupWrite |
                    UnixFileMode.GroupExecute | UnixFileMode.OtherRead | UnixFileMode.OtherWrite |
                    UnixFileMode.OtherExecute;
                if ((mode & unsafeBits) != 0)
                {
                    throw new InvalidOperationException("Secret file permissions are too broad.");
                }
            }

            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            var bytes = new byte[MaximumSecretBytes + 1];
            var length = 0;
            while (length < bytes.Length)
            {
                var count = stream.Read(bytes, length, bytes.Length - length);
                if (count == 0)
                {
                    break;
                }

                length += count;
            }

            if (length > MaximumSecretBytes)
            {
                throw new InvalidOperationException("Secret file is too large.");
            }

            var secret = StrictUtf8.GetString(bytes, 0, length).TrimEnd('\r', '\n');
            if (string.IsNullOrWhiteSpace(secret))
            {
                throw new InvalidOperationException("Secret file is empty.");
            }

            return secret;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or DecoderFallbackException)
        {
            throw new InvalidOperationException("Required secret file could not be read.");
        }
    }

}
