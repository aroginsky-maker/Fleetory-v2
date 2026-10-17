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
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Fleetory.Platform.Contracts.Secrets;
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

        services.AddSingleton<IModuleRegistry, ModuleRegistry>();
        services.AddSingleton<ISearchService, SearchService>();
        services.AddSingleton<IClock, SystemClock>();
        services.AddScoped<IAuditWriter, PostgreSqlAuditWriter>();
        services.AddScoped<IAuthorizationService, PostgreSqlAuthorizationService>();
        if (configuration.GetValue<bool>("Fleetory:AuditExport:Enabled"))
        {
            if (configuration["Fleetory:AuditExport:Sink"] == "Immudb")
            {
                services.TryAddSingleton<IAuditExportSink>(serviceProvider =>
                {
                    var address = configuration["Fleetory:AuditExport:Address"];
                    var username = configuration["Fleetory:AuditExport:Username"];
                    if (!Uri.TryCreate(address, UriKind.Absolute, out var uri) ||
                        string.IsNullOrWhiteSpace(username))
                    {
                        throw new InvalidOperationException("Immudb audit export requires Address and Username.");
                    }

                    var password = serviceProvider.GetRequiredService<ISecretProvider>()
                        .GetRequiredSecret(FleetorySecretNames.AuditImmudbPassword);
                    var environment = serviceProvider.GetRequiredService<IHostEnvironment>();
                    return new ImmudbAuditExportSink(uri, username, password,
                        allowInsecureLoopback: environment.IsDevelopment());
                });
            }
            services.AddSingleton<PostgreSqlAuditExportPump>();
            services.AddHostedService<AuditExportWorker>();
        }
        services.AddSingleton(serviceProvider => new PostgreSqlConnectionSettings(
            PostgreSqlPersistenceConfiguration.GetRequiredConnectionString(configuration, serviceProvider)));
        services.AddDbContext<PlatformDbContext>((serviceProvider, options) =>
            PlatformDbContextOptions.Configure(options,
                PostgreSqlPersistenceConfiguration.GetRequiredConnectionString(configuration, serviceProvider)));
        services.AddHealthChecks()
            .AddCheck<PostgreSqlReadinessHealthCheck>(
                "postgresql",
                failureStatus: HealthStatus.Unhealthy,
                tags: ["ready"]);
    }
}
