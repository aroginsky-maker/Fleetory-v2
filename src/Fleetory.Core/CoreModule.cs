using Fleetory.Core.Persistence;
using Fleetory.ModuleAbstractions;
using Fleetory.Platform.Contracts.Secrets;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Fleetory.Core;

public sealed class CoreModule : FleetoryModuleBase
{
    public override string Name => "Core";

    public override void RegisterServices(
        IServiceCollection services,
        IConfiguration configuration)
    {
        base.RegisterServices(services, configuration);

        services.AddDbContext<CoreDbContext>((serviceProvider, options) =>
        {
            var connectionString = serviceProvider.GetService<ISecretProvider>()?
                .GetRequiredSecret(FleetorySecretNames.PostgreSqlConnectionString)
                ?? configuration.GetConnectionString("Fleetory");
            if (string.IsNullOrWhiteSpace(connectionString))
            {
                throw new InvalidOperationException(
                    "PostgreSQL connection string is required for Core persistence.");
            }

            CoreDbContextOptions.Configure(options, connectionString);
        });
    }
}
