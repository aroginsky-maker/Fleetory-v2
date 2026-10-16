using Fleetory.Core.Persistence;
using Fleetory.ModuleAbstractions;
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

        var connectionString = configuration.GetConnectionString("Fleetory");
        if (string.IsNullOrWhiteSpace(connectionString))
        {
            throw new InvalidOperationException(
                "ConnectionStrings:Fleetory is required for Core PostgreSQL persistence.");
        }

        services.AddDbContext<CoreDbContext>(options =>
            CoreDbContextOptions.Configure(options, connectionString));
    }
}
