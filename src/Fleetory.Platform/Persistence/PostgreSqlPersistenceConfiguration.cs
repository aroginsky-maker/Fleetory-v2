using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Fleetory.Platform.Contracts.Secrets;

namespace Fleetory.Platform.Persistence;

internal static class PostgreSqlPersistenceConfiguration
{
    internal const string ConnectionStringName = "Fleetory";

    public static string GetRequiredConnectionString(
        IConfiguration configuration,
        IServiceProvider serviceProvider)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        var connectionString = serviceProvider.GetService<ISecretProvider>()?
            .GetRequiredSecret(FleetorySecretNames.PostgreSqlConnectionString)
            ?? configuration.GetConnectionString(ConnectionStringName);
        if (string.IsNullOrWhiteSpace(connectionString))
        {
            throw new InvalidOperationException(
                "ConnectionStrings:Fleetory is required for PostgreSQL persistence.");
        }

        PostgreSqlConnectionStringValidator.Validate(connectionString);

        return connectionString;
    }
}
