using Microsoft.EntityFrameworkCore;

namespace Fleetory.Platform.Persistence;

internal static class PlatformDbContextOptions
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
                PlatformDbContext.SchemaName));
    }
}
