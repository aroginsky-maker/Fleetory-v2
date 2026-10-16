using System.Net;
using Fleetory.Core.Contracts;
using Fleetory.Core.Persistence;
using Fleetory.Platform.Contracts;
using Fleetory.Platform.Persistence;
using Fleetory.Server;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;

namespace Fleetory.Persistence.Tests;

[Collection(PostgreSqlTestCollection.Name)]
public sealed class PostgreSqlPersistenceTests(PostgreSqlTestFixture fixture)
{
    [Fact]
    public async Task PostgreSql_connection_is_available_and_test_database_is_explicit()
    {
        var connectionString = RequireConnectionString();
        var builder = new NpgsqlConnectionStringBuilder(connectionString);

        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand("SELECT current_database()", connection);
        var actualDatabase = Assert.IsType<string>(await command.ExecuteScalarAsync());

        Assert.Equal(builder.Database, actualDatabase);
        Assert.Contains("test", actualDatabase, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Owned_context_migrations_create_expected_schemas_tables_and_history()
    {
        var connectionString = RequireConnectionString();
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();

        Assert.True(await DatabaseObjectExistsAsync(
            connection,
            "SELECT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'platform')"));
        Assert.True(await DatabaseObjectExistsAsync(
            connection,
            "SELECT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'core')"));
        Assert.True(await DatabaseObjectExistsAsync(
            connection,
            "SELECT to_regclass('platform.person_projections') IS NOT NULL"));
        Assert.True(await DatabaseObjectExistsAsync(
            connection,
            "SELECT to_regclass('platform.audit_events') IS NOT NULL"));
        Assert.True(await DatabaseObjectExistsAsync(
            connection,
            "SELECT to_regclass('platform.audit_export_queue') IS NOT NULL"));
        Assert.True(await DatabaseObjectExistsAsync(
            connection,
            "SELECT to_regclass('platform.authorization_scopes') IS NOT NULL"));
        Assert.True(await DatabaseObjectExistsAsync(
            connection,
            "SELECT to_regclass('platform.authorization_roles') IS NOT NULL"));
        Assert.True(await DatabaseObjectExistsAsync(
            connection,
            "SELECT to_regclass('platform.authorization_assignments') IS NOT NULL"));
        Assert.True(await DatabaseObjectExistsAsync(
            connection,
            "SELECT to_regclass('core.devices') IS NOT NULL"));
        Assert.True(await DatabaseObjectExistsAsync(
            connection,
            "SELECT to_regclass('platform.\"__EFMigrationsHistory\"') IS NOT NULL"));
        Assert.True(await DatabaseObjectExistsAsync(
            connection,
            "SELECT to_regclass('core.\"__EFMigrationsHistory\"') IS NOT NULL"));

        Assert.Equal(
            1L,
            await ExecuteScalarInt64Async(
                connection,
                "SELECT COUNT(*) FROM platform.\"__EFMigrationsHistory\" " +
                "WHERE \"MigrationId\" = '202609280001_InitialPlatformPersistence'"));
        Assert.Equal(
            1L,
            await ExecuteScalarInt64Async(
                connection,
                "SELECT COUNT(*) FROM platform.\"__EFMigrationsHistory\" " +
                "WHERE \"MigrationId\" = '202610160001_AddPlatformAuditOutbox'"));
        Assert.Equal(
            1L,
            await ExecuteScalarInt64Async(
                connection,
                "SELECT COUNT(*) FROM platform.\"__EFMigrationsHistory\" " +
                "WHERE \"MigrationId\" = '202610160002_AddPlatformAuthorization'"));
        Assert.Equal(
            1L,
            await ExecuteScalarInt64Async(
                connection,
                "SELECT COUNT(*) FROM core.\"__EFMigrationsHistory\" " +
                "WHERE \"MigrationId\" = '202609280002_InitialCorePersistence'"));

        const string crossContextForeignKeySql = """
            SELECT COUNT(*)
            FROM pg_constraint constraint_row
            JOIN pg_class source_table ON source_table.oid = constraint_row.conrelid
            JOIN pg_namespace source_schema ON source_schema.oid = source_table.relnamespace
            JOIN pg_class target_table ON target_table.oid = constraint_row.confrelid
            JOIN pg_namespace target_schema ON target_schema.oid = target_table.relnamespace
            WHERE constraint_row.contype = 'f'
              AND source_schema.nspname IN ('platform', 'core')
              AND target_schema.nspname IN ('platform', 'core')
              AND source_schema.nspname <> target_schema.nspname
            """;

        await using var foreignKeyCommand = new NpgsqlCommand(crossContextForeignKeySql, connection);
        var crossContextForeignKeys = Convert.ToInt64(await foreignKeyCommand.ExecuteScalarAsync());
        Assert.Equal(0L, crossContextForeignKeys);
    }

    [Fact]
    public async Task Semantic_identifiers_and_utc_timestamps_round_trip_without_collapsing_contexts()
    {
        var personId = new PersonId(Guid.NewGuid());
        var deviceId = new DeviceId(Guid.NewGuid());
        var timestamp = new DateTimeOffset(2026, 9, 28, 12, 34, 56, TimeSpan.FromHours(3));

        await using (var scope = fixture.Services.CreateAsyncScope())
        {
            var platform = scope.ServiceProvider.GetRequiredService<PlatformDbContext>();
            var core = scope.ServiceProvider.GetRequiredService<CoreDbContext>();

            platform.People.Add(PersonProjectionRecord.Create(personId, "Ada Lovelace", timestamp));
            core.Devices.Add(DeviceRecord.Create(deviceId, "NB-00421", timestamp));

            await platform.SaveChangesAsync();
            await core.SaveChangesAsync();
        }

        await using (var scope = fixture.Services.CreateAsyncScope())
        {
            var platform = scope.ServiceProvider.GetRequiredService<PlatformDbContext>();
            var core = scope.ServiceProvider.GetRequiredService<CoreDbContext>();

            var person = await platform.People.SingleAsync(row => row.PersonId == personId);
            var device = await core.Devices.SingleAsync(row => row.DeviceId == deviceId);

            Assert.Equal(personId, person.PersonId);
            Assert.Equal(deviceId, device.DeviceId);
            Assert.Equal(TimeSpan.Zero, person.UpdatedAt.Offset);
            Assert.Equal(TimeSpan.Zero, device.UpdatedAt.Offset);
            Assert.NotEqual(typeof(PersonId), typeof(DeviceId));
        }
    }

    [Fact]
    public async Task Revision_concurrency_token_rejects_stale_updates()
    {
        var personId = new PersonId(Guid.NewGuid());
        var initialTime = new DateTimeOffset(2026, 9, 28, 10, 0, 0, TimeSpan.Zero);

        await using (var setupScope = fixture.Services.CreateAsyncScope())
        {
            var setup = setupScope.ServiceProvider.GetRequiredService<PlatformDbContext>();
            setup.People.Add(PersonProjectionRecord.Create(personId, "Initial", initialTime));
            await setup.SaveChangesAsync();
        }

        await using var firstScope = fixture.Services.CreateAsyncScope();
        await using var secondScope = fixture.Services.CreateAsyncScope();
        var first = firstScope.ServiceProvider.GetRequiredService<PlatformDbContext>();
        var second = secondScope.ServiceProvider.GetRequiredService<PlatformDbContext>();

        var firstCopy = await first.People.SingleAsync(row => row.PersonId == personId);
        var secondCopy = await second.People.SingleAsync(row => row.PersonId == personId);

        firstCopy.UpdateDisplayName("First writer", initialTime.AddMinutes(1));
        await first.SaveChangesAsync();

        secondCopy.UpdateDisplayName("Stale writer", initialTime.AddMinutes(2));
        await Assert.ThrowsAsync<DbUpdateConcurrencyException>(
            async () => await second.SaveChangesAsync());
    }

    [Fact]
    public async Task Readiness_is_healthy_when_postgresql_is_available()
    {
        var connectionString = RequireConnectionString();
        var arguments = new[]
        {
            $"--ConnectionStrings:Fleetory={connectionString}"
        };

        await using var app = FleetoryApplication.Build(arguments);
        app.Urls.Clear();
        app.Urls.Add(CreateLoopbackListenUrl());
        await app.StartAsync();

        try
        {
            var server = app.Services.GetRequiredService<IServer>();
            var addresses = server.Features.Get<IServerAddressesFeature>()?.Addresses;
            var address = Assert.Single(
                addresses ?? throw new InvalidOperationException("Server address feature is unavailable."));

            using var client = new HttpClient { BaseAddress = new Uri(address) };
            using var liveResponse = await client.GetAsync("/health/live");
            using var readyResponse = await client.GetAsync("/health/ready");

            Assert.Equal(HttpStatusCode.OK, liveResponse.StatusCode);
            Assert.Equal(HttpStatusCode.OK, readyResponse.StatusCode);
        }
        finally
        {
            await app.StopAsync();
        }
    }

    [Fact]
    public async Task Liveness_stays_healthy_and_readiness_becomes_unhealthy_when_postgresql_is_unavailable()
    {
        var connectionString = CreateUnavailableConnectionString(RequireConnectionString());
        var stoppedDisposableContainer = false;

        if (fixture.UsesDisposableContainer)
        {
            await fixture.StopDisposablePostgreSqlAsync();
            stoppedDisposableContainer = true;
        }

        try
        {
            var (liveStatus, readyStatus) = await GetHealthStatusesAsync(connectionString);

            Assert.Equal(HttpStatusCode.OK, liveStatus);
            Assert.Equal(HttpStatusCode.ServiceUnavailable, readyStatus);
        }
        finally
        {
            if (stoppedDisposableContainer)
            {
                await fixture.StartDisposablePostgreSqlAsync();
            }
        }
    }

    private string RequireConnectionString() =>
        string.IsNullOrWhiteSpace(fixture.ConnectionString)
            ? throw new InvalidOperationException("PostgreSQL test connection string is unavailable.")
            : fixture.ConnectionString;

    private static async Task<bool> DatabaseObjectExistsAsync(
        NpgsqlConnection connection,
        string sql)
    {
        await using var command = new NpgsqlCommand(sql, connection);
        return Assert.IsType<bool>(await command.ExecuteScalarAsync());
    }

    private static async Task<long> ExecuteScalarInt64Async(
        NpgsqlConnection connection,
        string sql)
    {
        await using var command = new NpgsqlCommand(sql, connection);
        return Convert.ToInt64(await command.ExecuteScalarAsync());
    }

    private string CreateUnavailableConnectionString(string connectionString)
    {
        var builder = new NpgsqlConnectionStringBuilder(connectionString)
        {
            Timeout = 1,
            CommandTimeout = 1,
            Pooling = false
        };

        if (!fixture.UsesDisposableContainer)
        {
            builder.Host = IPAddress.Loopback.ToString();
            builder.Port = 1;
        }

        return builder.ConnectionString;
    }

    private static async Task<(HttpStatusCode Live, HttpStatusCode Ready)> GetHealthStatusesAsync(
        string connectionString)
    {
        var arguments = new[]
        {
            $"--ConnectionStrings:Fleetory={connectionString}"
        };

        await using var app = FleetoryApplication.Build(arguments);
        app.Urls.Clear();
        app.Urls.Add(CreateLoopbackListenUrl());
        await app.StartAsync();

        try
        {
            var server = app.Services.GetRequiredService<IServer>();
            var addresses = server.Features.Get<IServerAddressesFeature>()?.Addresses;
            var address = Assert.Single(
                addresses ?? throw new InvalidOperationException("Server address feature is unavailable."));

            using var client = new HttpClient { BaseAddress = new Uri(address) };
            using var liveResponse = await client.GetAsync("/health/live");
            using var readyResponse = await client.GetAsync("/health/ready");

            return (liveResponse.StatusCode, readyResponse.StatusCode);
        }
        finally
        {
            await app.StopAsync();
        }
    }

    private static string CreateLoopbackListenUrl() =>
        new UriBuilder(Uri.UriSchemeHttp, IPAddress.Loopback.ToString(), 0)
            .Uri
            .GetLeftPart(UriPartial.Authority);
}
