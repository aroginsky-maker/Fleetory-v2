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
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.RateLimiting;
using Fleetory.Platform.Contracts.Secrets;
using Fleetory.SharedKernel;

namespace Fleetory.Platform;

public sealed class PlatformModule : FleetoryModuleBase
{
    public override string Name => "Platform";

    public override void MapEndpoints(IEndpointRouteBuilder endpoints)
    {
        if (!endpoints.ServiceProvider.GetRequiredService<IConfiguration>()
            .GetValue<bool>("Fleetory:AdminGateway:Enabled"))
        {
            return;
        }

        endpoints.MapPost("/admin/authorization/roles",
            AuthorizationAdministrationEndpoints.CreateRoleAsync)
            .RequireRateLimiting(AdminSecurityPolicyNames.AdminRateLimit);
        endpoints.MapPost("/admin/authorization/roles/{roleId:guid}/replacements",
            AuthorizationAdministrationEndpoints.ReplaceRoleAsync)
            .RequireRateLimiting(AdminSecurityPolicyNames.AdminRateLimit);
        endpoints.MapGet("/admin/authorization/roles/{roleId:guid}/versions",
            AuthorizationAdministrationEndpoints.GetRoleVersionsAsync)
            .RequireRateLimiting(AdminSecurityPolicyNames.AdminRateLimit);
        endpoints.MapPost("/admin/authorization/scopes",
            AuthorizationAdministrationEndpoints.CreateScopeAsync)
            .RequireRateLimiting(AdminSecurityPolicyNames.AdminRateLimit);
        endpoints.MapDelete("/admin/authorization/roles/{roleId:guid}",
            AuthorizationAdministrationEndpoints.RetireRoleAsync)
            .RequireRateLimiting(AdminSecurityPolicyNames.AdminRateLimit);
        endpoints.MapDelete("/admin/authorization/scopes/{scopeId:guid}",
            AuthorizationAdministrationEndpoints.RetireScopeAsync)
            .RequireRateLimiting(AdminSecurityPolicyNames.AdminRateLimit);
        endpoints.MapPost("/admin/authorization/roles/{roleId:guid}/assignments",
            AuthorizationAdministrationEndpoints.AssignRoleAsync)
            .RequireRateLimiting(AdminSecurityPolicyNames.AdminRateLimit);
        endpoints.MapDelete("/admin/authorization/assignments/{assignmentId:guid}",
            AuthorizationAdministrationEndpoints.RevokeAssignmentAsync)
            .RequireRateLimiting(AdminSecurityPolicyNames.AdminRateLimit);
    }

    public override void RegisterServices(
        IServiceCollection services,
        IConfiguration configuration)
    {
        base.RegisterServices(services, configuration);

        services.AddSingleton<IModuleRegistry, ModuleRegistry>();
        services.AddSingleton<ISearchService, SearchService>();
        services.AddSingleton<IClock, SystemClock>();
        services.AddScoped<PostgreSqlAuditWriter>();
        services.AddScoped<IAuditWriter>(provider => provider.GetRequiredService<PostgreSqlAuditWriter>());
        services.AddScoped<IAuthorizationService, PostgreSqlAuthorizationService>();
        services.AddScoped<PostgreSqlAuthorizationAdministration>();
        var auditExportEnabled = configuration.GetValue<bool>("Fleetory:AuditExport:Enabled");
        if (auditExportEnabled)
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
                        allowInsecureLoopback: environment.IsDevelopment(),
                        allowDefaultAdminCredential: environment.IsDevelopment());
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
        var healthChecks = services.AddHealthChecks()
            .AddCheck<PostgreSqlReadinessHealthCheck>(
                "postgresql",
                failureStatus: HealthStatus.Unhealthy,
                tags: ["ready"]);
        if (auditExportEnabled)
        {
            healthChecks.AddCheck<AuditExportBacklogHealthCheck>(
                "audit_export_backlog",
                failureStatus: HealthStatus.Degraded,
                tags: ["ready"]);
        }
    }
}
