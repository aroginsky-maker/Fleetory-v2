using Microsoft.EntityFrameworkCore;

namespace Fleetory.Core.Persistence;

internal static class CoreDbContextOptions
{
    public static void Configure(
        DbContextOptionsBuilder optionsBuilder,
        string connectionString)
    {
        ArgumentNullException.ThrowIfNull(optionsBuilder);
        ArgumentException.ThrowIfNullOrWhiteSpace(connectionString);

        optionsBuilder.UseNpgsql(
            connectionString,
            npgsql => npgsql.MigrationsHistoryTable(
                "__EFMigrationsHistory",
                CoreDbContext.SchemaName));
    }
}
