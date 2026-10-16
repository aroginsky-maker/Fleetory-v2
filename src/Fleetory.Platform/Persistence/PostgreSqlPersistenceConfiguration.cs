using Microsoft.Extensions.Configuration;
using Npgsql;

namespace Fleetory.Platform.Persistence;

internal static class PostgreSqlPersistenceConfiguration
{
    internal const string ConnectionStringName = "Fleetory";

    public static string GetRequiredConnectionString(IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        var connectionString = configuration.GetConnectionString(ConnectionStringName);
        if (string.IsNullOrWhiteSpace(connectionString))
        {
            throw new InvalidOperationException(
                "ConnectionStrings:Fleetory is required for PostgreSQL persistence.");
        }

        NpgsqlConnectionStringBuilder builder;
        try
        {
            builder = new NpgsqlConnectionStringBuilder(connectionString);
        }
        catch (ArgumentException exception)
        {
            throw new InvalidOperationException(
                "ConnectionStrings:Fleetory is not a valid PostgreSQL connection string.",
                exception);
        }

        if (string.IsNullOrWhiteSpace(builder.Host) || string.IsNullOrWhiteSpace(builder.Database))
        {
            throw new InvalidOperationException(
                "ConnectionStrings:Fleetory must define both Host and Database.");
        }

        return connectionString;
    }
}
