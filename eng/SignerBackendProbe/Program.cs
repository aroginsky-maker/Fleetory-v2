using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using Fleetory.CommandSigning;
using Fleetory.Core.Contracts;

namespace SignerBackendProbe;

// Generated-only fixture protocol. No paths, endpoint, key name or DeviceId supplied by callers.
internal static class Program
{
    private const string FixtureKey = "fleetory-recovery-fixture";
    private const int InputLimit = 16384;

    public static async Task<int> Main(string[] args)
    {
        if (args.Length != 1 || args[0] is not ("accepted" or "denied" or "wrong-key" or "wrong-version" or "tls-denied"))
        {
            return Report("invalid-input", 64);
        }
        try
        {
            if (await ReadInputAsync() is not { } packet) { return Report("invalid-input", 64); }
            return await ProbeAsync(args[0], packet.Token, packet.PublicKey);
        }
        catch (Exception error) when (error is JsonException or FormatException)
        {
            return Report("invalid-input", 64);
        }
        catch (HttpRequestException error)
        {
            return Report("http-" + (int)(error.StatusCode ?? 0), 1);
        }
        catch (CryptographicException)
        {
            return Report("crypto", 1);
        }
        catch (Exception)
        {
            // Raw exceptions and peer-controlled bodies may contain fixture credentials.
            return Report("unexpected", 1);
        }
    }

    private static async Task<(string Token, byte[] PublicKey)?> ReadInputAsync()
    {
        var bytes = new byte[InputLimit + 1];
        using var input = Console.OpenStandardInput();
        var count = 0;
        while (count < bytes.Length)
        {
            var read = await input.ReadAsync(bytes.AsMemory(count));
            if (read == 0) { break; }
            count += read;
        }
        if (count is 0 or > InputLimit) { return null; }
        using var json = JsonDocument.Parse(bytes.AsMemory(0, count), new JsonDocumentOptions { MaxDepth = 4 });
        if (json.RootElement.ValueKind != JsonValueKind.Object) { return null; }
        var fields = new HashSet<string>(StringComparer.Ordinal);
        foreach (var field in json.RootElement.EnumerateObject())
        {
            if (field.Name is not ("token" or "publicKey") || !fields.Add(field.Name) ||
                field.Value.ValueKind != JsonValueKind.String)
            {
                return null;
            }
        }
        if (fields.Count != 2) { return null; }
        var token = json.RootElement.GetProperty("token").GetString()!;
        var encoded = json.RootElement.GetProperty("publicKey").GetString()!;
        return token.Length is < 1 or > 8192 || token.Any(c => c <= ' ' || c >= '\u007f') || encoded.Length > 256
            ? null : (token, Convert.FromBase64String(encoded));
    }

    private static async Task<int> ProbeAsync(string mode, string token, byte[] publicKey)
    {
        var device = new DeviceId(Guid.NewGuid());
        if (mode == "wrong-key")
        {
            using var other = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            publicKey = other.ExportSubjectPublicKeyInfo();
        }
        using var signer = new OpenBaoCommandSigner(new Uri("https://localhost:8200/"), token,
            FixtureKey, mode == "wrong-version" ? 2 : 1, publicKey);
        try
        {
            var envelope = await signer.SignInventoryRefreshAsync(device);
            if (mode != "accepted") { return Report("unexpected-acceptance", 1); }
            using var key = ECDsa.Create();
            key.ImportSubjectPublicKeyInfo(publicKey, out _);
            if (envelope.TargetDeviceId != device || envelope.CommandId == Guid.Empty ||
                envelope.CommandType != AgentCommandTypes.InventoryRefresh || !envelope.Payload.IsEmpty ||
                envelope.SigningKeyId != FixtureKey + "-v1" ||
                !key.VerifyData(envelope.GetSigningBytes(), envelope.Signature.Span, HashAlgorithmName.SHA256,
                    DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
            {
                return Report("invalid-envelope", 1);
            }
            // The envelope is never emitted, persisted, dispatched or executed by an Agent.
            return Report("accepted", 0);
        }
        catch (HttpRequestException error) when (mode == "denied" && error.StatusCode == HttpStatusCode.Forbidden)
        {
            return Report("forbidden", 0);
        }
        catch (HttpRequestException error) when (mode == "wrong-version" && error.StatusCode == HttpStatusCode.InternalServerError)
        {
            return Report("key-version-500", 0);
        }
        catch (HttpRequestException error) when (mode == "tls-denied" && error.HttpRequestError == HttpRequestError.SecureConnectionError)
        {
            return Report("tls", 0);
        }
        catch (CryptographicException) when (mode == "wrong-key")
        {
            return Report("key-pin", 0);
        }
    }

    private static int Report(string category, int code)
    {
        Console.WriteLine(JsonSerializer.Serialize(new { category, agentCommandDispatched = false }));
        return code;
    }
}
