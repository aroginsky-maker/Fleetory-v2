using Fleetory.Assets;
using Fleetory.CMDB;
using Fleetory.Core;
using Fleetory.Core.Contracts;
using Fleetory.Core.Security;
using Microsoft.AspNetCore.Authentication;
using Fleetory.Integrations;
using Fleetory.ITSM;
using Fleetory.ModuleAbstractions;
using Fleetory.Monitoring;
using Fleetory.Platform;
using Fleetory.Platform.Contracts.Secrets;
using Fleetory.Platform.Contracts;
using Fleetory.Platform.Persistence;
using Fleetory.Platform.Secrets;
using Fleetory.SharedKernel;
using Fleetory.Server.Infrastructure;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.RateLimiting;

namespace Fleetory.Server;

public static class FleetoryApplication
{
    public static WebApplication Build(string[]? args = null)
    {
        var builder = WebApplication.CreateBuilder(args ?? Array.Empty<string>());

        builder.Configuration.AddEnvironmentVariables(prefix: "FLEETORY_");

        var secrets = ConfigureSecrets(builder);
        var gateway = GatewayStartup.Configure(builder, secrets);
        var adminOidcEnabled = AdminOidcAuthentication.Configure(builder);

        builder.Logging.ClearProviders();
        builder.Logging.AddJsonConsole(options => options.IncludeScopes = true);

        builder.Services.AddHealthChecks();
        var adminRateLimit = builder.Configuration.GetValue<int?>("Fleetory:AdminGateway:RateLimitPerMinute") ?? 30;
        if (adminRateLimit is < 1 or > 300)
        {
            throw new InvalidOperationException("Fleetory:AdminGateway:RateLimitPerMinute must be between 1 and 300.");
        }

        var agentRotationRateLimit = builder.Configuration.GetValue<int?>(
            "Fleetory:AgentGateway:RotationIntentRateLimitPerMinute") ?? 30;
        if (agentRotationRateLimit is < 1 or > 300)
        {
            throw new InvalidOperationException(
                "Fleetory:AgentGateway:RotationIntentRateLimitPerMinute must be between 1 and 300.");
        }

        builder.Services.AddRateLimiter(options =>
        {
            options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
            options.AddFixedWindowLimiter(AdminSecurityPolicyNames.AdminRateLimit, limiter =>
            {
                limiter.PermitLimit = adminRateLimit;
                limiter.Window = TimeSpan.FromMinutes(1);
                limiter.QueueLimit = 0;
                limiter.AutoReplenishment = true;
            });
            options.AddPolicy(AgentSecurityPolicyNames.RotationIntentRateLimit, context =>
                RateLimitPartition.GetFixedWindowLimiter(
                    context.Connection.ClientCertificate?.Thumbprint ??
                    context.Connection.RemoteIpAddress?.ToString() ?? "unknown-agent",
                    _ => new FixedWindowRateLimiterOptions
                    {
                        PermitLimit = agentRotationRateLimit,
                        Window = TimeSpan.FromMinutes(1),
                        QueueLimit = 0,
                        AutoReplenishment = true
                    }));
        });

        var modules = CreateModules();
        ValidateModules(modules);

        foreach (var module in modules)
        {
            module.RegisterServices(builder.Services, builder.Configuration);
        }

        builder.Services.AddSingleton<IReadOnlyCollection<IFleetoryModule>>(modules);

        var app = builder.Build();

        app.UseRouting();
        app.UseRateLimiter();
        app.UseMiddleware<CorrelationIdMiddleware>();

        if (gateway is not null)
        {
            app.Use(async (context, next) =>
            {
                if (context.Connection.LocalPort == gateway.AgentPort)
                {
                    if (context.Request.Path != "/agent/identity" &&
                        context.Request.Path != "/agent/enroll" &&
                        context.Request.Path != "/agent/rotation-intents")
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

                    if (context.Request.Path == "/agent/identity" ||
                        context.Request.Path == "/agent/rotation-intents")
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
                    var adminCertificate = await context.Connection.GetClientCertificateAsync(
                        context.RequestAborted);
                    if (!context.Request.Path.StartsWithSegments("/admin") || adminCertificate is null)
                    {
                        context.Response.StatusCode = StatusCodes.Status404NotFound;
                        return;
                    }

                    if (adminOidcEnabled)
                    {
                        if (!AdminCertificateIdentity.TryReadActor(adminCertificate, out var actor) ||
                            actor is null)
                        {
                            context.Response.StatusCode = StatusCodes.Status403Forbidden;
                            return;
                        }

                        var authentication = await context.AuthenticateAsync(AdminOidcAuthentication.Scheme);
                        var clientId = context.RequestServices.GetRequiredService<IConfiguration>()
                            ["Fleetory:AdminGateway:Oidc:ClientId"]!;
                        if (!authentication.Succeeded ||
                            !AdminOidcAuthentication.MatchesMfaActor(
                                authentication.Principal!, actor.SubjectId, clientId))
                        {
                            await context.RequestServices.GetRequiredService<IAuditWriter>()
                                .WriteAsync(new AuditRecord(
                                    actor, "admin.oidc.denied", null,
                                    new CorrelationId(context.TraceIdentifier),
                                    context.RequestServices.GetRequiredService<IClock>().UtcNow),
                                    context.RequestAborted);
                            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                            return;
                        }
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

    private static ISecretProvider? ConfigureSecrets(WebApplicationBuilder builder)
    {
        var providerName = builder.Configuration["Fleetory:Secrets:Provider"] ?? "File";
        var directory = builder.Configuration["Fleetory:Secrets:Directory"];
        var directConnectionString = builder.Configuration.GetConnectionString("Fleetory");

        if (providerName == "OpenBao")
        {
            if (directory is not null || directConnectionString is not null)
            {
                throw new InvalidOperationException(
                    "OpenBao secrets cannot be combined with a file secret directory or direct connection string.");
            }

            var tokenDirectory = builder.Configuration["Fleetory:Secrets:TokenDirectory"];
            var addressValue = builder.Configuration["Fleetory:Secrets:Address"];
            if (string.IsNullOrWhiteSpace(tokenDirectory) ||
                !Uri.TryCreate(addressValue, UriKind.Absolute, out var address))
            {
                throw new InvalidOperationException("OpenBao requires TokenDirectory and Address.");
            }

            var token = new FileSecretProvider(tokenDirectory).GetRequiredSecret("openbao-token");
            var openBao = new OpenBaoSecretProvider(address, token,
                allowInsecureLoopback: builder.Environment.IsDevelopment());
            var openBaoConnectionString = openBao.GetRequiredSecret(FleetorySecretNames.PostgreSqlConnectionString);
            PostgreSqlConnectionStringValidator.Validate(openBaoConnectionString);
            builder.Services.AddSingleton<ISecretProvider>(openBao);
            return openBao;
        }

        if (providerName != "File")
        {
            throw new InvalidOperationException("Unknown Fleetory:Secrets:Provider.");
        }

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
