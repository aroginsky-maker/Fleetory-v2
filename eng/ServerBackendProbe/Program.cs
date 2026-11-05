using System.Text.Json;
using Fleetory.Core.Persistence;
using Fleetory.Platform.Persistence;
using Fleetory.Security.Infrastructure;
using Fleetory.Server;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Npgsql;

namespace ServerBackendProbe;

internal static class Program
{
    internal const string PrivateDirectory = "/run/fleetory-native/server";
    private static readonly HashSet<string> Modes = new(StringComparer.Ordinal)
    {
        "schema", "db-ready", "db-write", "db-rollback", "db-atomic", "db-password", "db-tls", "db-plaintext",
        "db-update", "db-delete", "db-schema", "db-temp", "db-owner", "db-queue-delete",
        "audit-prepare", "audit-publish", "audit-repeat", "audit-conflict", "audit-password", "audit-readonly",
        "audit-database", "audit-tls", "audit-verify", "audit-health",
        "pump-auth", "pump-lostack", "pump-deliver", "pump-empty", "pump-update", "pipeline-pending", "pipeline-verify",
        "db-worker-write", "worker-denied", "worker-retain", "worker-drain", "worker-restart", "worker-verify",
        "db-host-write", "host-degraded", "host-drain"
    };

    public static async Task<int> Main(string[] args)
    {
        if (args.Length != 1 || !Modes.Contains(args[0])) { return 64; }
        var originalOut = Console.Out;
        var originalError = Console.Error;
        object result;
        var exit = 0;
        Console.SetOut(TextWriter.Null);
        Console.SetError(TextWriter.Null);
        try { result = await RunAsync(args[0]); }
        catch (Exception exception)
        {
            result = new { category = "unexpected", errorType = exception.GetType().Name,
                causeType = exception.InnerException?.GetType().Name, location = exception.TargetSite?.Name,
                controlStatus = exception.Data["fixtureHttpStatus"] as int?,
                tlsFailure = exception.Data["fixtureTlsFailure"] as string };
            exit = 1;
        }
        finally { Console.SetOut(originalOut); Console.SetError(originalError); }
        await originalOut.WriteLineAsync(JsonSerializer.Serialize(result));
        return exit;
    }

    private static async Task<object> RunAsync(string mode)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(18));
        if (mode is "pipeline-pending" or "pipeline-verify" or "worker-verify")
        {
            await PipelineFixtureControl.ExecuteAsync(mode, deadline.Token);
            return new { category = mode, httpHostStarted = false, issuerActivated = false };
        }
        if (mode is "audit-prepare" or "audit-verify" or "audit-health")
        {
            await AuditFixtureControl.ExecuteAsync(mode, deadline.Token);
            return new { category = mode, httpHostStarted = false, issuerActivated = false };
        }
        var files = new FileSecretProvider(PrivateDirectory);
        var binding = new NpgsqlConnectionStringBuilder(files.GetRequiredSecret("fleetory-postgresql"));
        if (binding.Host != "127.0.0.1" || binding.Database != "fleetory" || binding.Username != "fleetory_server" ||
            binding.Port != 5432 || binding.GssEncryptionMode != GssEncryptionMode.Disable || !string.IsNullOrEmpty(binding.Options) ||
            binding.RootCertificate != PrivateDirectory + "/infrastructure-ca" ||
            binding.SslMode != (mode == "db-plaintext" ? SslMode.Disable : SslMode.VerifyFull))
        { throw new InvalidOperationException("Invalid generated fixture binding."); }
        await using var app = FleetoryApplication.Build([
            "--environment=Production", "--Logging:LogLevel:Default=None",
            "--Logging:WorkerObservation:LogLevel:Default=Error",
            "--Fleetory:Secrets:Provider=File", "--Fleetory:Secrets:Directory=" + PrivateDirectory,
            "--Fleetory:Web:Port=19580", "--Fleetory:AgentGateway:Enabled=true", "--Fleetory:AgentGateway:Port=19581",
            "--Fleetory:AdminGateway:Enabled=true", "--Fleetory:AdminGateway:Port=19582", "--Fleetory:AdminGateway:BindAddress=127.0.0.1",
            "--Fleetory:AdminGateway:Oidc:Enabled=true", "--Fleetory:AdminGateway:Oidc:Authority=https://127.0.0.1:19999/realms/fixture",
            "--Fleetory:AdminGateway:Oidc:Audience=fleetory-fixture", "--Fleetory:AdminGateway:Oidc:ClientId=fleetory-fixture",
            "--Fleetory:AuditExport:Enabled=true", "--Fleetory:AuditExport:Sink=Immudb", "--Fleetory:AuditExport:Address=https://127.0.0.1:8090",
            "--Fleetory:AuditExport:Username=" + (mode == "audit-readonly" ? "fixture_reader" : "fixture_writer"),
            "--Fleetory:AuditExport:Database=" + (mode == "audit-database" ? "missingfixture" : "fleetoryaudit")
        ]);
        await using var scope = app.Services.CreateAsyncScope();
        var platform = scope.ServiceProvider.GetRequiredService<PlatformDbContext>();
        var core = scope.ServiceProvider.GetRequiredService<CoreDbContext>();
        if (mode == "schema")
        {
            var sql = platform.GetService<IMigrator>().GenerateScript() + core.GetService<IMigrator>().GenerateScript();
            if (sql.Length is < 1 or > 131072) { throw new InvalidOperationException("Unbounded fixture schema."); }
            return new { category = "schema", sql };
        }
        if (mode.StartsWith("worker-", StringComparison.Ordinal))
        {
            var lifecycle = await WorkerCases.ExecuteAsync(mode, app.Services, scope.ServiceProvider, platform, deadline.Token);
            if (!app.Environment.IsProduction() || app.Lifetime.ApplicationStarted.IsCancellationRequested)
            { throw new InvalidOperationException("Fixture HTTP host started."); }
            return new { category = mode, lifecycle, httpHostStarted = false, issuerActivated = false };
        }
        if (mode is "host-degraded" or "host-drain")
        {
            var lifecycle = await HostCases.ExecuteAsync(mode, app, platform, deadline.Token);
            return new { category = mode, lifecycle, httpHostStarted = true, issuerActivated = false };
        }
        var category = mode switch
        {
            _ when mode.StartsWith("db-", StringComparison.Ordinal) =>
                await DatabaseCases.ExecuteAsync(mode, app.Services, scope.ServiceProvider, platform, core, deadline.Token),
            _ when mode.StartsWith("pump-", StringComparison.Ordinal) =>
                await PumpCases.ExecuteAsync(mode, app.Services, platform, deadline.Token),
            _ => await AuditCases.ExecuteAsync(mode, app.Services, deadline.Token)
        };
        if (!app.Environment.IsProduction() || app.Lifetime.ApplicationStarted.IsCancellationRequested)
        { throw new InvalidOperationException("Fixture host started."); }
        return new { category, httpHostStarted = false, issuerActivated = false };
    }
}
