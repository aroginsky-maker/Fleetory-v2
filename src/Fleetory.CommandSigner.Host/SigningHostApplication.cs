using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.RateLimiting;
using Fleetory.CommandSigning;
using Fleetory.Core.Contracts;
using Fleetory.ModuleAbstractions;
using Fleetory.Security.Infrastructure;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Npgsql;

namespace Fleetory.CommandSigner.Host;

public static class SigningHostApplication
{
    public static WebApplication Build(string[]? args = null)
    {
        var builder = WebApplication.CreateSlimBuilder(new WebApplicationOptions
        {
            Args = args ?? [], ApplicationName = typeof(SigningHostApplication).Assembly.FullName
        });
        builder.Configuration.Sources.Clear();
        builder.Configuration.AddEnvironmentVariables("FLEETORY_SIGNER_");
        builder.Configuration.AddCommandLine(args ?? []);
        builder.Logging.ClearProviders();
        builder.Logging.AddJsonConsole();
        builder.Logging.AddFilter("Microsoft.AspNetCore", LogLevel.Warning);
        var configuration = SigningHostConfiguration.Read(builder);
        var secrets = new FileSecretProvider(builder.Configuration["Signer:SecretsDirectory"] ?? "");
        SigningClientAuthorizationPolicy? policy = null;
        MutualTlsMaterial? tls = null;
        NpgsqlDataSource? source = null;
        OpenBaoCommandSigner? transit = null;
        try
        {
            policy = SigningHostConfiguration.LoadPolicy(secrets);
            tls = MutualTlsMaterial.Load(secrets, "signer-server-ca", "signer-server-cert", "signer-server-key",
                X509EndEntityPolicy.HasDigitalSignatureUsage);
            source = SigningHostConfiguration.LoadDatabase(secrets);
            var allowHttp = builder.Environment.IsDevelopment() &&
                builder.Configuration.GetValue<bool>("Signer:AllowLoopbackHttpTransit");
            var key = Convert.FromBase64String(secrets.GetRequiredSecret("signer-transit-public-key"));
            transit = new OpenBaoCommandSigner(new Uri(builder.Configuration["Signer:TransitAddress"] ?? "", UriKind.Absolute),
                secrets.GetRequiredSecret("signer-transit-token"), builder.Configuration["Signer:TransitKey"] ?? "",
                builder.Configuration.GetValue<int>("Signer:TransitKeyVersion"), key, allowHttp);
            builder.Services.AddSingleton(_ => policy);
            builder.Services.AddSingleton(_ => tls);
            builder.Services.AddSingleton(_ => source);
            builder.Services.AddSingleton(_ => transit);
            builder.Services.AddSingleton<PostgreSqlSigningRequestJournal>();
            builder.Services.AddSingleton<ISigningRequestJournal>(services => services.GetRequiredService<PostgreSqlSigningRequestJournal>());
            builder.Services.AddSingleton<AuthorizedCommandSigner>();
            builder.Services.AddSingleton<SigningJournalReadiness>();
            builder.Services.AddHostedService(services => services.GetRequiredService<SigningJournalReadiness>());
            builder.WebHost.ConfigureKestrel(options =>
            {
                options.AddServerHeader = false;
                options.Limits.MaxRequestBodySize = 1024;
                options.Limits.MaxRequestHeadersTotalSize = 16 * 1024;
                options.Limits.MaxConcurrentConnections = 64;
                options.Limits.RequestHeadersTimeout = TimeSpan.FromSeconds(5);
                options.Listen(configuration.Address, configuration.Port, listen => listen.UseHttps(https =>
                {
                    https.ServerCertificate = tls.ServerCertificate;
                    https.ServerCertificateChain = tls.ServerCertificateChain;
                    https.SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13;
                    https.HandshakeTimeout = TimeSpan.FromSeconds(5);
                    https.ClientCertificateMode = ClientCertificateMode.RequireCertificate;
                    https.ClientCertificateValidation = (certificate, _, _) => policy.GetAuthorizedCaller(certificate) is not null;
                }));
            });
            ConfigureRateLimit(builder, configuration.RateLimit);
            var app = builder.Build();
            ConfigurePipeline(app);
            return app;
        }
        catch
        {
            transit?.Dispose(); source?.Dispose(); tls?.Dispose(); policy?.Dispose();
            throw;
        }
    }

    private static void ConfigureRateLimit(WebApplicationBuilder builder, int permits)
    {
        builder.Services.AddRateLimiter(options =>
        {
            options.GlobalLimiter = PartitionedRateLimiter.CreateChained<HttpContext>(
                PartitionedRateLimiter.Create<HttpContext, string>(_ => RateLimitPartition.GetConcurrencyLimiter(
                    "signer", _ => new ConcurrencyLimiterOptions { PermitLimit = 4, QueueLimit = 0 })),
                PartitionedRateLimiter.Create<HttpContext, string>(_ => RateLimitPartition.GetFixedWindowLimiter(
                    "signer", _ => new FixedWindowRateLimiterOptions
                    {
                        PermitLimit = permits, Window = TimeSpan.FromMinutes(1), QueueLimit = 0
                    })));
            options.OnRejected = async (rejection, _) =>
                await RejectAsync(rejection.HttpContext, 429, SigningRejectionReason.RateLimited);
        });
    }

    private static void ConfigurePipeline(WebApplication app)
    {
        app.Use(async (context, next) =>
        {
            var original = context.RequestAborted;
            using var lifetime = CancellationTokenSource.CreateLinkedTokenSource(original);
            lifetime.CancelAfter(TimeSpan.FromSeconds(20));
            context.RequestAborted = lifetime.Token;
            context.Response.Headers.CacheControl = "no-store";
            try
            {
                var certificate = await context.Connection.GetClientCertificateAsync(lifetime.Token);
                if (!context.Request.IsHttps || app.Services.GetRequiredService<SigningClientAuthorizationPolicy>()
                    .GetAuthorizedCaller(certificate) is null)
                {
                    await RejectAsync(context, 403, SigningRejectionReason.Forbidden);
                    return;
                }
                await next(context);
            }
            catch (SigningRequestConflictException) { await RejectAsync(context, 409, SigningRejectionReason.Duplicate); }
            catch (UnauthorizedAccessException) { await RejectAsync(context, 403, SigningRejectionReason.Forbidden); }
            catch (OperationCanceledException) { await RejectAsync(context, 503, SigningRejectionReason.Cancelled); }
            catch (Exception exception) when (exception is NpgsqlException or HttpRequestException or
                CryptographicException or InvalidOperationException or IOException)
            {
                await RejectAsync(context, 503, SigningRejectionReason.Unavailable);
            }
            finally { context.RequestAborted = original; }
        });
        app.UseRouting();
        app.UseRateLimiter();
        app.MapGet("/health/live", () => Results.NoContent());
        app.MapGet("/health/ready", async (SigningJournalReadiness readiness, HttpContext context) =>
            Results.StatusCode(await readiness.IsReadyAsync(context.RequestAborted) ? 204 : 503));
        app.MapPost("/signing/inventory-refresh", SignInventoryRefreshAsync);
        app.MapFallback("/{**path}", async context => await RejectAsync(context, 404, SigningRejectionReason.InvalidRequest));
    }

    private static async Task<IResult> SignInventoryRefreshAsync(HttpContext context, AuthorizedCommandSigner signer)
    {
        var request = await BoundedJsonRequestReader.ReadAsync<SigningRequestBody>(context, 1024, SigningHostConfiguration.Json);
        if (request is null || request.RequestId == Guid.Empty || request.DeviceId == Guid.Empty)
        {
            await RejectAsync(context, 400, SigningRejectionReason.InvalidRequest);
            return Results.Empty;
        }
        context.Items["SignerRequestId"] = request.RequestId;
        context.Items["SignerDeviceId"] = request.DeviceId;
        var signed = await signer.SignInventoryRefreshAsync(request.RequestId,
            context.Connection.ClientCertificate, new DeviceId(request.DeviceId), context.RequestAborted);
        var envelope = signed.Envelope;
        return Results.Json(new SigningResponse(request.RequestId, envelope.TargetDeviceId.Value,
            envelope.CommandId, envelope.FormatVersion, envelope.CommandType, envelope.IssuedAt, envelope.ExpiresAt,
            envelope.Nonce, envelope.SigningKeyId, Convert.ToBase64String(envelope.Signature.Span)));
    }

    private static async Task RejectAsync(HttpContext context, int status, SigningRejectionReason reason)
    {
        if (context.Response.HasStarted) { return; }
        var certificate = context.Connection.ClientCertificate;
        if (certificate is not null)
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            try
            {
                var eventId = await context.RequestServices.GetRequiredService<PostgreSqlSigningRequestJournal>()
                    .RecordRejectionAsync(certificate.GetCertHashString(HashAlgorithmName.SHA256), reason,
                        context.Items["SignerRequestId"] as Guid?, context.Items["SignerDeviceId"] as Guid?, deadline.Token);
                context.Response.Headers["X-Fleetory-Audit-Id"] = eventId.ToString("N");
            }
            catch (Exception exception) when (exception is NpgsqlException or OperationCanceledException)
            {
                status = 503;
                context.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("SigningAudit")
                    .LogError("Signer rejection journal is unavailable.");
            }
        }
        context.Response.StatusCode = status;
    }

    private sealed record SigningRequestBody(Guid RequestId, Guid DeviceId);
    public sealed record SigningResponse(Guid RequestId, Guid DeviceId, Guid CommandId, int FormatVersion,
        string CommandType, DateTimeOffset IssuedAt, DateTimeOffset ExpiresAt, string Nonce, string SigningKeyId, string Signature);
}
