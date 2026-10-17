using Fleetory.Assets;
using Fleetory.CMDB;
using Fleetory.Core;
using Fleetory.Core.Contracts;
using Fleetory.Core.Security;
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

        var secrets = ConfigureSecrets(builder);
        var gateway = GatewayStartup.Configure(builder, secrets);

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

        if (gateway is not null)
        {
            app.Use(async (context, next) =>
            {
                if (context.Connection.LocalPort == gateway.AgentPort)
                {
                    if (context.Request.Path != "/agent/identity" &&
                        context.Request.Path != "/agent/enroll")
                    {
                        context.Response.StatusCode = StatusCodes.Status404NotFound;
                        return;
                    }

                    var certificate = await context.Connection.GetClientCertificateAsync(
                        context.RequestAborted);
                    if (certificate is null ||
                        !AgentCertificateIdentity.TryReadDeviceId(certificate, out var deviceId))
                    {
                        context.Response.StatusCode = StatusCodes.Status403Forbidden;
                        return;
                    }

                    if (context.Request.Path == "/agent/identity")
                    {
                        var verifier = context.RequestServices
                            .GetRequiredService<IAgentCertificateBindingVerifier>();
                        var status = await verifier.VerifyAsync(
                            deviceId, certificate, context.RequestAborted);
                        if (status != AgentCertificateStatus.Accepted)
                        {
                            context.Response.StatusCode = StatusCodes.Status403Forbidden;
                            return;
                        }
                    }
                }
                else if (context.Connection.LocalPort == gateway.AdminPort)
                {
                    if (!context.Request.Path.StartsWithSegments("/admin") ||
                        await context.Connection.GetClientCertificateAsync(
                            context.RequestAborted) is null)
                    {
                        context.Response.StatusCode = StatusCodes.Status404NotFound;
                        return;
                    }
                }
                else if (context.Request.Path.StartsWithSegments("/agent") ||
                    context.Request.Path.StartsWithSegments("/admin"))
                {
                    context.Response.StatusCode = StatusCodes.Status404NotFound;
                    return;
                }

                await next(context);
            });
        }

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

    private static FileSecretProvider? ConfigureSecrets(WebApplicationBuilder builder)
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

            return null;
        }

        var provider = new FileSecretProvider(directory);
        var connectionString = provider.GetRequiredSecret(FleetorySecretNames.PostgreSqlConnectionString);
        PostgreSqlConnectionStringValidator.Validate(connectionString);

        builder.Services.AddSingleton<ISecretProvider>(provider);
        return provider;
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
