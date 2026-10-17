using Fleetory.Core.Persistence;
using Fleetory.Core.Contracts;
using Fleetory.Core.Security;
using Fleetory.ModuleAbstractions;
using Fleetory.Platform.Contracts.Secrets;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Fleetory.SharedKernel;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace Fleetory.Core;

public sealed class CoreModule : FleetoryModuleBase
{
    public override string Name => "Core";

    public override void RegisterServices(
        IServiceCollection services,
        IConfiguration configuration)
    {
        base.RegisterServices(services, configuration);

        services.TryAddSingleton<IClock, SystemClock>();
        services.AddScoped<IAgentCertificateBindingStore, PostgreSqlAgentCertificateBindingStore>();
        services.AddScoped<IAgentCertificateBindingVerifier, AgentCertificateBindingVerifier>();
        services.AddScoped<AgentCertificateRevocationService>();

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

    public override void MapEndpoints(IEndpointRouteBuilder endpoints)
    {
        if (endpoints.ServiceProvider.GetRequiredService<IConfiguration>()
            .GetValue<bool>("Fleetory:AgentGateway:Enabled"))
        {
            endpoints.MapGet("/agent/identity", static () => Results.NoContent());
        }

        if (endpoints.ServiceProvider.GetRequiredService<IConfiguration>()
            .GetValue<bool>("Fleetory:AdminGateway:Enabled"))
        {
            endpoints.MapPost(
                "/admin/devices/{deviceId:guid}/certificates/{fingerprint}/revoke",
                AdminCertificateEndpoints.RevokeAsync);
        }
    }
}
