using Fleetory.Core.Contracts;

namespace Fleetory.Agent.Security;

/// <summary>Reads target-bound public keys from an Agent-local, externally provisioned trust directory.</summary>
public sealed class DirectoryCommandVerificationKeys : ICommandVerificationKeys
{
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
        if ((File.GetAttributes(_directory) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidOperationException("Command trust directory must not be a symbolic link.");
        }

        if (!OperatingSystem.IsWindows())
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

        var path = Path.Combine(_directory, $"{targetDeviceId.Value:N}-{keyId}.spki");
        try
        {
            var file = new FileInfo(path);
            if (!file.Exists)
            {
                return null;
            }

            if ((file.Attributes & FileAttributes.ReparsePoint) != 0 || file.Length is < 1 or > 1024)
            {
                throw new InvalidOperationException("Command trust file is invalid.");
            }

            if (!OperatingSystem.IsWindows())
            {
                const UnixFileMode unsafeBits = UnixFileMode.GroupWrite | UnixFileMode.OtherWrite;
                if ((File.GetUnixFileMode(path) & unsafeBits) != 0)
                {
                    throw new InvalidOperationException("Command trust file must not be writable by other users.");
                }
            }

            var bytes = await File.ReadAllBytesAsync(path, cancellationToken);
            if (bytes.Length is < 1 or > 1024)
            {
                throw new InvalidOperationException("Command trust file is invalid.");
            }

            return bytes;
        }
        catch (FileNotFoundException)
        {
            return null;
        }
    }

    private static bool IsValidKeyId(string? keyId) =>
        !string.IsNullOrEmpty(keyId) &&
        keyId.Length <= 128 &&
        keyId.All(character =>
            character is >= 'a' and <= 'z' or >= 'A' and <= 'Z' or >= '0' and <= '9' or '.' or '_' or '-');
}
