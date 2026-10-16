using Fleetory.Assets;
using Fleetory.CMDB;
using Fleetory.Core;
using Fleetory.Integrations;
using Fleetory.ITSM;
using Fleetory.ModuleAbstractions;
using Fleetory.Monitoring;
using Fleetory.Platform;
using Fleetory.Platform.Contracts.Secrets;
using Fleetory.Platform.Persistence;
using Fleetory.Platform.Secrets;
using Fleetory.Server.Infrastructure;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;

namespace Fleetory.Server;

public static class FleetoryApplication
{
    public static WebApplication Build(string[]? args = null)
    {
        var builder = WebApplication.CreateBuilder(args ?? Array.Empty<string>());

        builder.Configuration.AddEnvironmentVariables(prefix: "FLEETORY_");

        ConfigureSecrets(builder);

        builder.Logging.ClearProviders();
        builder.Logging.AddJsonConsole(options => options.IncludeScopes = true);

        builder.Services.AddHealthChecks();

        var modules = CreateModules();
        ValidateModules(modules);

        foreach (var module in modules)
        {
            module.RegisterServices(builder.Services, builder.Configuration);
        }

        builder.Services.AddSingleton<IReadOnlyCollection<IFleetoryModule>>(modules);

        var app = builder.Build();

        app.UseMiddleware<CorrelationIdMiddleware>();

        app.MapHealthChecks("/health/live", new HealthCheckOptions
        {
            Predicate = static _ => false
        });

        app.MapHealthChecks("/health/ready", new HealthCheckOptions
        {
            Predicate = static _ => true
        });

        foreach (var module in modules)
        {
            module.MapEndpoints(app);
            if (app.Logger.IsEnabled(LogLevel.Information))
            {
                app.Logger.LogInformation("Fleetory module registered: {ModuleName}", module.Name);
            }
        }

        return app;
    }

    private static void ConfigureSecrets(WebApplicationBuilder builder)
    {
        var directory = builder.Configuration["Fleetory:Secrets:Directory"];
        var directConnectionString = builder.Configuration.GetConnectionString("Fleetory");

        if (!string.IsNullOrWhiteSpace(directory) && directConnectionString is not null)
        {
            throw new InvalidOperationException(
                "Use either Fleetory:Secrets:Directory or ConnectionStrings:Fleetory, not both.");
        }

        if (string.IsNullOrWhiteSpace(directory))
        {
            if (!builder.Environment.IsDevelopment())
            {
                throw new InvalidOperationException(
                    "Non-development environments require Fleetory:Secrets:Directory and reject direct connection strings.");
            }

            return;
        }

        var provider = new FileSecretProvider(directory);
        var connectionString = provider.GetRequiredSecret(FleetorySecretNames.PostgreSqlConnectionString);
        PostgreSqlConnectionStringValidator.Validate(connectionString);

        builder.Services.AddSingleton<ISecretProvider>(provider);
    }

    private static IFleetoryModule[] CreateModules() =>
    [
        new PlatformModule(),
        new CoreModule(),
        new AssetsModule(),
        new ITSMModule(),
        new CMDBModule(),
        new MonitoringModule(),
        new IntegrationsModule()
    ];

    private static void ValidateModules(IReadOnlyCollection<IFleetoryModule> modules)
    {
        var duplicateName = modules
            .GroupBy(module => module.Name, StringComparer.Ordinal)
            .FirstOrDefault(group => group.Count() > 1);

        if (duplicateName is not null)
        {
            throw new InvalidOperationException($"Duplicate Fleetory module name: {duplicateName.Key}.");
        }
    }
}
