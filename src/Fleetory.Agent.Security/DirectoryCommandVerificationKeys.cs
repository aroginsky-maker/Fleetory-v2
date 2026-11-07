using Fleetory.Core.Contracts;

namespace Fleetory.Agent.Security;

/// <summary>Reads target-bound public keys from an Agent-local, externally provisioned trust directory.</summary>
public sealed class DirectoryCommandVerificationKeys : ICommandVerificationKeys
{
    private const int MaximumPublicKeyBytes = 1024;
    private readonly DeviceId _localDeviceId;
    private readonly string _directory;

    public DirectoryCommandVerificationKeys(DeviceId localDeviceId, string directory)
    {
        if (localDeviceId.Value == Guid.Empty || string.IsNullOrWhiteSpace(directory) ||
            !Path.IsPathFullyQualified(directory) || !Directory.Exists(directory))
        {
            throw new ArgumentException("A device identity and existing absolute trust directory are required.");
        }

        _localDeviceId = localDeviceId;
        _directory = Path.GetFullPath(directory);
        ValidateDirectory();
    }

    private void ValidateDirectory()
    {
        if ((File.GetAttributes(_directory) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidOperationException("Command trust directory must not be a symbolic link.");
        }

        if (OperatingSystem.IsWindows())
        {
            WindowsAgentStorageAcl.ValidateDirectory(_directory, "Command trust directory");
        }
        else
        {
            const UnixFileMode unsafeBits = UnixFileMode.GroupWrite | UnixFileMode.OtherWrite;
            if ((File.GetUnixFileMode(_directory) & unsafeBits) != 0)
            {
                throw new InvalidOperationException("Command trust directory must not be writable by other users.");
            }
        }
    }

    public async ValueTask<ReadOnlyMemory<byte>?> FindPublicKeyAsync(
        DeviceId targetDeviceId,
        string keyId,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (targetDeviceId != _localDeviceId || !IsValidKeyId(keyId))
        {
            return null;
        }

        ValidateDirectory();
        var path = Path.Combine(_directory, $"{targetDeviceId.Value:N}-{keyId}.spki");
        try
        {
            var file = new FileInfo(path);
            if (!file.Exists)
            {
                return null;
            }

            if ((file.Attributes & FileAttributes.ReparsePoint) != 0 || file.Length is < 1 or > MaximumPublicKeyBytes)
            {
                throw new InvalidOperationException("Command trust file is invalid.");
            }

            if (OperatingSystem.IsWindows())
            {
                WindowsAgentStorageAcl.ValidateFile(path, "Command trust file");
            }
            else
            {
                const UnixFileMode unsafeBits = UnixFileMode.GroupWrite | UnixFileMode.OtherWrite;
                if ((File.GetUnixFileMode(path) & unsafeBits) != 0)
                {
                    throw new InvalidOperationException("Command trust file must not be writable by other users.");
                }
            }

            // Metadata can change before open; enforce the limit again while reading.
            await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read,
                bufferSize: MaximumPublicKeyBytes, options: FileOptions.Asynchronous | FileOptions.SequentialScan);
            return await ReadPublicKeyBytesAsync(stream, cancellationToken).ConfigureAwait(false);
        }
        catch (FileNotFoundException)
        {
            return null;
        }
    }

    internal static async ValueTask<byte[]> ReadPublicKeyBytesAsync(
        Stream stream, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var bytes = new byte[MaximumPublicKeyBytes + 1];
        var length = await stream.ReadAtLeastAsync(bytes, bytes.Length,
            throwOnEndOfStream: false, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (length is < 1 or > MaximumPublicKeyBytes)
        {
            throw new InvalidOperationException("Command trust file is invalid.");
        }

        return bytes[..length];
    }

    private static bool IsValidKeyId(string? keyId) =>
        !string.IsNullOrEmpty(keyId) &&
        keyId.Length <= 128 &&
        keyId.All(character =>
            character is >= 'a' and <= 'z' or >= 'A' and <= 'Z' or >= '0' and <= '9' or '.' or '_' or '-');
}
