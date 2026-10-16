using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace Fleetory.Platform.Persistence;

public sealed class PlatformDbContextFactory : IDesignTimeDbContextFactory<PlatformDbContext>
{
    public PlatformDbContext CreateDbContext(string[] args)
    {
        var connectionString = Environment.GetEnvironmentVariable(
            "FLEETORY_MIGRATION_CONNECTION_STRING");

        if (string.IsNullOrWhiteSpace(connectionString))
        {
            throw new InvalidOperationException(
                "FLEETORY_MIGRATION_CONNECTION_STRING is required for design-time migrations.");
        }

        var optionsBuilder = new DbContextOptionsBuilder<PlatformDbContext>();
        PlatformDbContextOptions.Configure(optionsBuilder, connectionString);
        return new PlatformDbContext(optionsBuilder.Options);
    }
}
