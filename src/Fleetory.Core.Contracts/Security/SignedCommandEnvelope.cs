using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Fleetory.Core.Contracts;

/// <summary>
/// Version-one command signature material. This is a Core security contract, not the Agent v2 wire protocol.
/// </summary>
public sealed class SignedCommandEnvelope
{
    private static readonly byte[] DomainSeparator = "Fleetory.Command.v1"u8.ToArray();
    private readonly byte[] _payload;
    private readonly byte[] _signature;

    public SignedCommandEnvelope(
        DeviceId targetDeviceId,
        Guid commandId,
        string commandType,
        ReadOnlySpan<byte> payload,
        DateTimeOffset issuedAt,
        DateTimeOffset expiresAt,
        string nonce,
        string signingKeyId,
        ReadOnlySpan<byte> signature,
        int formatVersion = 1)
    {
        TargetDeviceId = targetDeviceId;
        CommandId = commandId;
        CommandType = commandType;
        _payload = payload.ToArray();
        IssuedAt = issuedAt;
        ExpiresAt = expiresAt;
        Nonce = nonce;
        SigningKeyId = signingKeyId;
        _signature = signature.ToArray();
        FormatVersion = formatVersion;
    }

    public DeviceId TargetDeviceId { get; }
    public Guid CommandId { get; }
    public string CommandType { get; }
    public ReadOnlyMemory<byte> Payload => _payload.ToArray();
    public DateTimeOffset IssuedAt { get; }
    public DateTimeOffset ExpiresAt { get; }
    public string Nonce { get; }
    public string SigningKeyId { get; }
    public ReadOnlyMemory<byte> Signature => _signature.ToArray();
    public int FormatVersion { get; }

    public byte[] GetSigningBytes()
    {
        using var stream = new MemoryStream();
        WriteField(stream, DomainSeparator);
        WriteInt32(stream, FormatVersion);
        WriteField(stream, Encoding.UTF8.GetBytes(TargetDeviceId.Value.ToString("N")));
        WriteField(stream, Encoding.UTF8.GetBytes(CommandId.ToString("N")));
        WriteField(stream, Encoding.UTF8.GetBytes(CommandType));
        WriteField(stream, SHA256.HashData(_payload));
        WriteInt64(stream, IssuedAt.UtcTicks);
        WriteInt64(stream, ExpiresAt.UtcTicks);
        WriteField(stream, Encoding.UTF8.GetBytes(Nonce));
        WriteField(stream, Encoding.UTF8.GetBytes(SigningKeyId));
        return stream.ToArray();
    }

    private static void WriteField(Stream stream, ReadOnlySpan<byte> value)
    {
        WriteInt32(stream, value.Length);
        stream.Write(value);
    }

    private static void WriteInt32(Stream stream, int value)
    {
        Span<byte> bytes = stackalloc byte[sizeof(int)];
        BinaryPrimitives.WriteInt32BigEndian(bytes, value);
        stream.Write(bytes);
    }

    private static void WriteInt64(Stream stream, long value)
    {
        Span<byte> bytes = stackalloc byte[sizeof(long)];
        BinaryPrimitives.WriteInt64BigEndian(bytes, value);
        stream.Write(bytes);
    }
}
