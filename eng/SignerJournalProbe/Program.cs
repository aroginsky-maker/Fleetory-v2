using System.Security.Authentication;
using System.Text.Json;
using Fleetory.CommandSigner.Host;
using Fleetory.Security.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Npgsql;

namespace SignerJournalProbe;

// Generated fixture only: fixed loopback database, role and private worker directory.
internal static class Program
{
    private const string Secrets = "/run/fleetory-native/signer";
    private const string Unavailable = "Signer journal is unavailable or its runtime permissions are unsafe.";
    private static readonly Dictionary<string, string> DeniedSql = new(StringComparer.Ordinal)
    {
        ["update"] = "UPDATE signer.signing_results SET signing_key_id=signing_key_id WHERE FALSE;",
        ["delete"] = "DELETE FROM signer.signing_requests WHERE FALSE;",
        ["schema"] = "CREATE SCHEMA forbidden_fixture;",
        ["revocation"] = "INSERT INTO signer.client_certificate_revocations (certificate_sha256,incident_reference,operator_reference,approver_reference,evidence_sha256) SELECT repeat('A',64),'test','one','two',repeat('B',64) WHERE FALSE;",
        ["owner"] = "SET ROLE fleetory_signer_owner;"
    };

    public static async Task<int> Main(string[] args)
    {
        if (args.Length != 1 || args[0] is not ("ready" or "unsafe" or "password" or "tls" or "plaintext") && !DeniedSql.ContainsKey(args[0]))
        {
            return Report("invalid-input", 64);
        }
        var output = Console.Out;
        var error = Console.Error;
        Console.SetOut(TextWriter.Null);
        Console.SetError(TextWriter.Null);
        string category;
        try { category = await ProbeAsync(args[0]); }
        catch (Exception) { category = "unexpected"; }
        finally { Console.SetOut(output); Console.SetError(error); }
        return Report(category, category is "ready" or "unsafe-permissions" or "authentication" or "tls" or "plaintext" or "privilege" ? 0 : 1);
    }

    private static async Task<string> ProbeAsync(string mode)
    {
        var provider = new FileSecretProvider(Secrets);
        var settings = new NpgsqlConnectionStringBuilder(provider.GetRequiredSecret("signer-postgresql"));
        if (settings.Host != "127.0.0.1" || settings.Port != 5432 || settings.Database != "fleetory_signer" ||
            settings.Username != "fleetory_signer" || !string.IsNullOrEmpty(settings.Options) ||
            settings.SslMode != (mode == "plaintext" ? SslMode.Disable : SslMode.VerifyFull) ||
            settings.GssEncryptionMode != GssEncryptionMode.Disable ||
            settings.RootCertificate != Secrets + "/infrastructure-ca")
        {
            return "invalid-binding";
        }
        await using var app = SigningHostApplication.Build([
            "--environment=Production", "--Signer:SecretsDirectory=" + Secrets,
            "--Signer:BindAddress=127.0.0.1", "--Signer:Port=19443",
            "--Logging:LogLevel:Default=None",
            "--Signer:TransitAddress=https://127.0.0.1:8200", "--Signer:TransitKey=recovery-only", "--Signer:TransitKeyVersion=1"
        ]);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var source = app.Services.GetRequiredService<NpgsqlDataSource>();
        var readinessType = typeof(SigningHostApplication).Assembly.GetType(
            "Fleetory.CommandSigner.Host.SigningJournalReadiness", throwOnError: true)!;
        var readiness = (IHostedService)app.Services.GetRequiredService(readinessType);
        var result = await ExerciseAsync(mode, source, readiness, deadline.Token);
        return !app.Environment.IsProduction() || app.Lifetime.ApplicationStarted.IsCancellationRequested ? "unexpected" : result;
    }

    private static async Task<string> ExerciseAsync(string mode, NpgsqlDataSource source, IHostedService readiness, CancellationToken cancellation)
    {
        try
        {
            if (mode is "ready" or "unsafe")
            {
                if (!await VerifyTransportAsync(source, cancellation)) { return "unexpected"; }
                await readiness.StartAsync(cancellation);
                return mode == "unsafe" ? "unexpected-acceptance" : "ready";
            }
            await using var connection = await source.OpenConnectionAsync(cancellation);
            if (DeniedSql.TryGetValue(mode, out var sql))
            {
                await using var command = new NpgsqlCommand(sql, connection);
                await command.ExecuteNonQueryAsync(cancellation);
            }
            return "unexpected-acceptance";
        }
        catch (Exception exception) when (ExpectedFailure(mode, exception) is { } category)
        { return category; }
    }

    private static string? ExpectedFailure(string mode, Exception exception) => (mode, exception) switch
    {
        ("unsafe", InvalidOperationException { Message: Unavailable }) => "unsafe-permissions",
        ("password", PostgresException { SqlState: PostgresErrorCodes.InvalidPassword }) => "authentication",
        ("plaintext", PostgresException { SqlState: PostgresErrorCodes.InvalidAuthorizationSpecification }) => "plaintext",
        ("tls", NpgsqlException { InnerException: AuthenticationException }) => "tls",
        (_, PostgresException { SqlState: PostgresErrorCodes.InsufficientPrivilege }) when DeniedSql.ContainsKey(mode) => "privilege",
        _ => null
    };

    private static async Task<bool> VerifyTransportAsync(NpgsqlDataSource source, CancellationToken cancellation)
    {
        await using var proof = source.CreateCommand("""
            SELECT current_user='fleetory_signer' AND current_user=session_user
                AND current_database()='fleetory_signer' AND ssl AND version IN ('TLSv1.2','TLSv1.3')
            FROM pg_stat_ssl WHERE pid=pg_backend_pid();
            """);
        return await proof.ExecuteScalarAsync(cancellation) is true;
    }

    private static int Report(string category, int code)
    {
        Console.WriteLine(JsonSerializer.Serialize(new { category, httpHostStarted = false, issuerActivated = false }));
        return code;
    }
}
