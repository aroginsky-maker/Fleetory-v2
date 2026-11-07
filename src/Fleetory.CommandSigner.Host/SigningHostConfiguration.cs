using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Serialization;
using Fleetory.CommandSigning;
using Fleetory.Core.Contracts;
using Fleetory.Security.Infrastructure;
using Npgsql;

namespace Fleetory.CommandSigner.Host;

internal sealed record SigningHostConfiguration(IPAddress Address, int Port, int RateLimit)
{
    internal static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        AllowDuplicateProperties = false
    };

    public static SigningHostConfiguration Read(WebApplicationBuilder builder)
    {
        var settings = builder.Configuration;
        if (settings.GetSection("Kestrel:Endpoints").Exists() ||
            !IPAddress.TryParse(settings["Signer:BindAddress"] ?? "127.0.0.1", out var address) ||
            address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any) ||
            address.IsIPv4MappedToIPv6 && address.MapToIPv4().Equals(IPAddress.Any))
        {
            throw new InvalidOperationException("Signer requires one explicit bind address and no additional endpoints.");
        }
        var port = settings.GetValue<int?>("Signer:Port") ?? 9443;
        var rate = settings.GetValue<int?>("Signer:RequestsPerMinute") ?? 10;
        if (port < (builder.Environment.IsDevelopment() ? 0 : 1) || port > 65535 || rate is < 1 or > 60)
        {
            throw new InvalidOperationException("Signer port or request rate is invalid.");
        }
        return new SigningHostConfiguration(address, port, rate);
    }

    public static SigningClientAuthorizationPolicy LoadPolicy(FileSecretProvider secrets)
    {
        var roots = new X509Certificate2Collection();
        var intermediates = new X509Certificate2Collection();
        try
        {
            var json = secrets.GetRequiredSecret("signer-policy");
            if (json.Contains("PRIVATE KEY", StringComparison.Ordinal))
            {
                throw new InvalidOperationException("Signer policy must contain only public trust material.");
            }
            var policy = JsonSerializer.Deserialize<PolicyDocument>(json, Json)
                ?? throw new InvalidOperationException("Signer policy is missing.");
            if (policy.Callers is null || policy.Callers.Any(caller => caller is null || caller.DeviceIds is null))
            {
                throw new ArgumentException("Signer callers are missing.");
            }
            if ((policy.RootsPem?.Contains("PRIVATE KEY", StringComparison.Ordinal) ?? false) ||
                (policy.IntermediatesPem?.Contains("PRIVATE KEY", StringComparison.Ordinal) ?? false))
            {
                throw new InvalidOperationException("Signer policy must contain only public trust material.");
            }
            roots.ImportFromPem(policy.RootsPem);
            if (!string.IsNullOrEmpty(policy.IntermediatesPem)) { intermediates.ImportFromPem(policy.IntermediatesPem); }
            var grants = policy.Callers.Select(caller => new SigningClientGrant(caller.CallerId,
                caller.CertificateSha256, caller.DeviceIds.Select(id => new DeviceId(id)).ToArray(),
                caller.NotBefore, caller.ExpiresAt)).ToArray();
            return new SigningClientAuthorizationPolicy(roots.Cast<X509Certificate2>().ToArray(),
                intermediates.Cast<X509Certificate2>().ToArray(), grants);
        }
        catch (Exception exception) when (exception is JsonException or CryptographicException or ArgumentException)
        {
            throw new InvalidOperationException("Signer policy is invalid.");
        }
        finally
        {
            foreach (var certificate in roots) { certificate.Dispose(); }
            foreach (var certificate in intermediates) { certificate.Dispose(); }
        }
    }

    public static NpgsqlDataSource LoadDatabase(FileSecretProvider secrets)
    {
        try
        {
            var settings = new NpgsqlConnectionStringBuilder(secrets.GetRequiredSecret("signer-postgresql"));
            var local = settings.Host is { } host && (host == "localhost" || Path.IsPathFullyQualified(host) ||
                IPAddress.TryParse(host, out var ip) && IPAddress.IsLoopback(ip));
            if (!local && settings.SslMode != SslMode.VerifyFull || !string.IsNullOrEmpty(settings.Options))
            {
                throw new InvalidOperationException("Signer database requires local transport or verified TLS and no session options.");
            }
            settings.Timeout = 5;
            settings.CommandTimeout = 5;
            settings.MaxPoolSize = 8;
            return NpgsqlDataSource.Create(settings.ConnectionString);
        }
        catch (ArgumentException)
        {
            throw new InvalidOperationException("Signer database configuration is invalid.");
        }
    }

    private sealed record PolicyDocument(string RootsPem, string? IntermediatesPem, CallerDocument[] Callers);
    private sealed record CallerDocument(string CallerId, string CertificateSha256, Guid[] DeviceIds,
        DateTimeOffset NotBefore, DateTimeOffset ExpiresAt);
}
