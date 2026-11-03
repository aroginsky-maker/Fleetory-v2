using System.Security.Cryptography;
using System.Text.Json;
using Fleetory.CommandSigner.Host;
using Fleetory.Platform.Contracts.Secrets;
using Fleetory.Security.Infrastructure;
using Fleetory.Server;
using Npgsql;

namespace RecoveryConfiguration;

// Configuration-only probe: never calls Start/Run, opens a database or invokes an issuer.
internal static class Program
{
    private static readonly Dictionary<string, string> Errors = new(StringComparer.Ordinal)
    {
        ["Required secret file could not be read."] = "unreadable-secret",
        ["Secret file is empty."] = "empty-secret",
        ["Secret file is too large."] = "large-secret",
        ["Secret file permissions are too broad."] = "file-permissions",
        ["Secret directory permissions are too broad."] = "directory-permissions",
        ["Secret directory is missing or is a symbolic link."] = "directory-link",
        ["Unknown Fleetory:Secrets:Provider."] = "provider",
        ["OpenBao secrets cannot be combined with a file secret directory or direct connection string."] = "provider-mix",
        ["Use either Fleetory:Secrets:Directory or ConnectionStrings:Fleetory, not both."] = "provider-mix",
        ["Non-development Admin Gateway requires OIDC authentication."] = "oidc",
        ["Gateway TLS material is invalid."] = "tls",
        ["Signer policy is invalid."] = "policy",
        ["Signer database requires local transport or verified TLS and no session options."] = "database",
        ["Recovery database binding is invalid."] = "database"
    };

    public static async Task<int> Main(string[] args)
    {
        if (args is ["public-key"])
        {
            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            await Console.Out.WriteLineAsync(JsonSerializer.Serialize(new { publicKey = Convert.ToBase64String(key.ExportSubjectPublicKeyInfo()) }));
            return 0;
        }
        if (args.Length < 2 || args[0] is not ("server" or "signer")) { return 64; }
        var output = Console.Out;
        var error = Console.Error;
        var category = "accepted";
        var code = 0;
        Console.SetOut(TextWriter.Null);
        Console.SetError(TextWriter.Null);
        try { await ProbeAsync(args[0], args[1..]); }
        catch (Exception exception) when (exception is InvalidOperationException or ArgumentException or
            CryptographicException or FormatException or IOException)
        {
            if (exception is InvalidOperationException && Errors.TryGetValue(exception.Message, out var known))
            {
                category = known;
                code = 2;
            }
            else { category = "unexpected"; code = 70; }
        }
        finally { Console.SetOut(output); Console.SetError(error); }
        await output.WriteLineAsync(JsonSerializer.Serialize(new
        {
            role = args[0], category, servicesStarted = false, databaseOpened = false,
            issuerActivated = false, originalMaterialApprovalInferred = false
        }));
        return code;
    }

    private static async Task ProbeAsync(string role, string[] arguments)
    {
        await using var app = role == "server" ? FleetoryApplication.Build(arguments) : SigningHostApplication.Build(arguments);
        if (!app.Environment.IsProduction() || app.Lifetime.ApplicationStarted.IsCancellationRequested)
        {
            throw new InvalidOperationException("Configuration probe requires an unstarted production-environment builder.");
        }
        var provider = role == "server" ? app.Services.GetRequiredService<ISecretProvider>() :
            new FileSecretProvider("/tmp/material/signer");
        if (provider is not FileSecretProvider) { throw new InvalidOperationException("Wrong configuration provider."); }
        string[] names = role == "server"
            ? ["fleetory-postgresql", "agent-gateway-root-ca", "agent-gateway-server-cert", "agent-gateway-server-key",
               "admin-gateway-root-ca", "admin-gateway-server-cert", "admin-gateway-server-key", "audit-immudb-password", "infrastructure-ca"]
            : ["infrastructure-ca", "signer-policy", "signer-postgresql", "signer-server-ca", "signer-server-cert",
               "signer-server-key", "signer-transit-public-key", "signer-transit-token"];
        foreach (var name in names) { _ = provider.GetRequiredSecret(name); }
        var databaseName = role == "server" ? "fleetory" : "fleetory_signer";
        var userName = role == "server" ? "fleetory_server" : "fleetory_signer";
        var connection = new NpgsqlConnectionStringBuilder(provider.GetRequiredSecret(
            role == "server" ? "fleetory-postgresql" : "signer-postgresql"));
        if (connection.Host != "postgres" || connection.Database != databaseName || connection.Username != userName ||
            connection.SslMode != SslMode.VerifyFull || connection.RootCertificate != "/tmp/material/" + role + "/infrastructure-ca" ||
            !string.IsNullOrEmpty(connection.Options))
        {
            throw new InvalidOperationException("Recovery database binding is invalid.");
        }
    }
}
