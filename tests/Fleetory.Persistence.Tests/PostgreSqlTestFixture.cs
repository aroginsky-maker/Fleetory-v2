using Fleetory.Core;
using Fleetory.Core.Persistence;
using Fleetory.Platform;
using Fleetory.Platform.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using Testcontainers.PostgreSql;

namespace Fleetory.Persistence.Tests;

public sealed class PostgreSqlTestFixture : IAsyncLifetime
{
    public const string ExternalConnectionStringEnvironmentVariable =
        "FLEETORY_TEST_CONNECTION_STRING";

    public const string PostgreSqlImage = "postgres:18.6";

    private PostgreSqlContainer? _container;
    private ServiceProvider? _services;

    public string ConnectionString { get; private set; } = string.Empty;

    public bool UsesDisposableContainer => _container is not null;

    public IServiceProvider Services => _services
        ?? throw new InvalidOperationException("PostgreSQL test fixture is not initialized.");

    public async Task InitializeAsync()
    {
        var externalConnectionString = Environment.GetEnvironmentVariable(
            ExternalConnectionStringEnvironmentVariable);

        if (string.IsNullOrWhiteSpace(externalConnectionString))
        {
            await StartDisposableContainerAsync().ConfigureAwait(false);
        }
        else
        {
            ValidateExternalTestConnectionString(externalConnectionString);
            ConnectionString = externalConnectionString;
            await ResetOwnedSchemasAsync(ConnectionString).ConfigureAwait(false);
        }

        try
        {
            await ConfigureServicesAndApplyMigrationsAsync().ConfigureAwait(false);
        }
        catch
        {
            await DisposeResourcesAsync().ConfigureAwait(false);
            throw;
        }
    }

    public async Task DisposeAsync()
    {
        await DisposeResourcesAsync().ConfigureAwait(false);
    }

    public async Task StopDisposablePostgreSqlAsync()
    {
        var container = _container
            ?? throw new InvalidOperationException(
                "The current PostgreSQL integration-test run uses an external test database.");

        await container.StopAsync().ConfigureAwait(false);
    }

    public async Task StartDisposablePostgreSqlAsync()
    {
        var container = _container
            ?? throw new InvalidOperationException(
                "The current PostgreSQL integration-test run uses an external test database.");

        await container.StartAsync().ConfigureAwait(false);
        ConnectionString = container.GetConnectionString();
    }

    private async Task StartDisposableContainerAsync()
    {
        var suffix = Guid.NewGuid().ToString("N")[..12];
        var databaseName = $"fleetory_test_{suffix}";
        var username = $"fleetory_test_{suffix}";
        var password = $"FleetoryTest-{Guid.NewGuid():N}-A1!";

        _container = new PostgreSqlBuilder(PostgreSqlImage)
            .WithDatabase(databaseName)
            .WithUsername(username)
            .WithPassword(password)
            .Build();

        try
        {
            await _container.StartAsync().ConfigureAwait(false);
            ConnectionString = _container.GetConnectionString();
        }
        catch (Exception exception)
        {
            await _container.DisposeAsync().ConfigureAwait(false);
            _container = null;
            throw new InvalidOperationException(
                "PostgreSQL integration verification requires Docker " +
                $"or an explicit {ExternalConnectionStringEnvironmentVariable}.",
                exception);
        }
    }

    private async Task ConfigureServicesAndApplyMigrationsAsync()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionStrings:Fleetory"] = ConnectionString
            })
            .Build();

        var services = new ServiceCollection();
        services.AddLogging();
        new PlatformModule().RegisterServices(services, configuration);
        new CoreModule().RegisterServices(services, configuration);
        _services = services.BuildServiceProvider();

        await using var scope = _services.CreateAsyncScope();
        var platform = scope.ServiceProvider.GetRequiredService<PlatformDbContext>();
        var core = scope.ServiceProvider.GetRequiredService<CoreDbContext>();

        await platform.Database.MigrateAsync().ConfigureAwait(false);
        await core.Database.MigrateAsync().ConfigureAwait(false);
    }

    private async Task DisposeResourcesAsync()
    {
        try
        {
            if (_services is not null)
            {
                await _services.DisposeAsync().ConfigureAwait(false);
                _services = null;
            }
        }
        finally
        {
            if (_container is not null)
            {
                await _container.DisposeAsync().ConfigureAwait(false);
                _container = null;
            }
        }
    }

    private static void ValidateExternalTestConnectionString(string connectionString)
    {
        NpgsqlConnectionStringBuilder builder;
        try
        {
            builder = new NpgsqlConnectionStringBuilder(connectionString);
        }
        catch (ArgumentException exception)
        {
            throw new InvalidOperationException(
                $"{ExternalConnectionStringEnvironmentVariable} is not a valid PostgreSQL connection string.",
                exception);
        }

        var databaseName = builder.Database;
        if (string.IsNullOrWhiteSpace(databaseName) ||
            !databaseName.Contains("test", StringComparison.OrdinalIgnoreCase) ||
            databaseName.Equals("postgres", StringComparison.OrdinalIgnoreCase) ||
            databaseName.Equals("template0", StringComparison.OrdinalIgnoreCase) ||
            databaseName.Equals("template1", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                $"{ExternalConnectionStringEnvironmentVariable} must explicitly target a test database " +
                "whose name contains 'test'.");
        }
    }

    private static async Task ResetOwnedSchemasAsync(string connectionString)
    {
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync().ConfigureAwait(false);

        const string sql =
            "DROP SCHEMA IF EXISTS platform CASCADE; " +
            "DROP SCHEMA IF EXISTS core CASCADE;";

        await using var command = new NpgsqlCommand(sql, connection);
        await command.ExecuteNonQueryAsync().ConfigureAwait(false);
    }
}
