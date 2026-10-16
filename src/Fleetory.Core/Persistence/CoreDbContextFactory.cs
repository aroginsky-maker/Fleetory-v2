using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace Fleetory.Core.Persistence;

public sealed class CoreDbContextFactory : IDesignTimeDbContextFactory<CoreDbContext>
{
    public CoreDbContext CreateDbContext(string[] args)
    {
        var connectionString = Environment.GetEnvironmentVariable(
            "FLEETORY_MIGRATION_CONNECTION_STRING");

        if (string.IsNullOrWhiteSpace(connectionString))
        {
            throw new InvalidOperationException(
                "FLEETORY_MIGRATION_CONNECTION_STRING is required for design-time migrations.");
        }

        var optionsBuilder = new DbContextOptionsBuilder<CoreDbContext>();
        CoreDbContextOptions.Configure(optionsBuilder, connectionString);
        return new CoreDbContext(optionsBuilder.Options);
    }
}
