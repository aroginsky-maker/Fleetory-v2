using Fleetory.Core.Persistence;
using Fleetory.Platform.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql;
using Testcontainers.PostgreSql;

namespace Fleetory.Persistence.Tests;

public sealed class IdempotentMigrationScriptTests
{
    [Fact]
    public async Task Both_context_scripts_apply_twice_to_fresh_postgresql()
    {
        // A dedicated fresh database is essential: MigrateAsync does not exercise
        // raw SQL inside the procedural IF blocks of idempotent deployment SQL.
        await using var postgres = new PostgreSqlBuilder(PostgreSqlTestFixture.PostgreSqlImage)
            .WithDatabase("fleetory_test_idempotent")
            .WithUsername("fleetory_test")
            .WithPassword($"FleetoryTest-{Guid.NewGuid():N}-A1!")
            .Build();
        await postgres.StartAsync();
        var connectionString = postgres.GetConnectionString();
        await using var platform = new PlatformDbContext(
            new DbContextOptionsBuilder<PlatformDbContext>()
                .UseNpgsql(connectionString, options => options.MigrationsHistoryTable(
                    "__EFMigrationsHistory", PlatformDbContext.SchemaName)).Options);
        await using var core = new CoreDbContext(
            new DbContextOptionsBuilder<CoreDbContext>()
                .UseNpgsql(connectionString, options => options.MigrationsHistoryTable(
                    "__EFMigrationsHistory", CoreDbContext.SchemaName)).Options);
        var scripts = new[] { platform.GetService<IMigrator>().GenerateScript(
                options: MigrationsSqlGenerationOptions.Idempotent),
            core.GetService<IMigrator>().GenerateScript(
                options: MigrationsSqlGenerationOptions.Idempotent) };
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();
        for (var pass = 0; pass < 2; pass++)
        {
            foreach (var script in scripts)
            {
                await using var command = new NpgsqlCommand(script, connection);
                await command.ExecuteNonQueryAsync();
            }
            Assert.Equal(platform.Database.GetMigrations(),
                await platform.Database.GetAppliedMigrationsAsync());
            Assert.Equal(core.Database.GetMigrations(),
                await core.Database.GetAppliedMigrationsAsync());
            Assert.Empty(await platform.Database.GetPendingMigrationsAsync());
            Assert.Empty(await core.Database.GetPendingMigrationsAsync());
        }
    }
}
