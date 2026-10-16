using Fleetory.ModuleAbstractions;
using Fleetory.Platform.Authorization;
using Fleetory.Platform.Audit;
using Fleetory.Platform.Contracts;
using Fleetory.Platform.Modules;
using Fleetory.Platform.Persistence;
using Fleetory.Platform.Search;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Fleetory.SharedKernel;

namespace Fleetory.Platform;

public sealed class PlatformModule : FleetoryModuleBase
{
    public override string Name => "Platform";

    public override void RegisterServices(
        IServiceCollection services,
        IConfiguration configuration)
    {
        base.RegisterServices(services, configuration);

        var connectionString = PostgreSqlPersistenceConfiguration
            .GetRequiredConnectionString(configuration);

        services.AddSingleton<IModuleRegistry, ModuleRegistry>();
        services.AddSingleton<ISearchService, SearchService>();
        services.AddSingleton<IClock, SystemClock>();
        services.AddScoped<IAuditWriter, PostgreSqlAuditWriter>();
        services.AddScoped<IAuthorizationService, PostgreSqlAuthorizationService>();
        if (configuration.GetValue<bool>("Fleetory:AuditExport:Enabled"))
        {
            services.AddSingleton<PostgreSqlAuditExportPump>();
            services.AddHostedService<AuditExportWorker>();
        }
        services.AddSingleton(new PostgreSqlConnectionSettings(connectionString));
        services.AddDbContext<PlatformDbContext>(options =>
            PlatformDbContextOptions.Configure(options, connectionString));
        services.AddHealthChecks()
            .AddCheck<PostgreSqlReadinessHealthCheck>(
                "postgresql",
                failureStatus: HealthStatus.Unhealthy,
                tags: ["ready"]);
    }
}
