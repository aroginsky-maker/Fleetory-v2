using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Logging;
namespace Fleetory.AdminLogin;

public sealed class LoopbackCallbackReceiver : IAsyncDisposable
{
    private readonly TaskCompletionSource<Uri> _response = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private WebApplication? _app;
    private LoopbackCallbackReceiver() { }

    public static async Task<LoopbackCallbackReceiver> StartAsync(CancellationToken cancellationToken)
    {
        var receiver = new LoopbackCallbackReceiver();
        var builder = WebApplication.CreateSlimBuilder(new WebApplicationOptions
        {
            Args = [], ApplicationName = typeof(LoopbackCallbackReceiver).Assembly.FullName
        });
        builder.Configuration.Sources.Clear();
        builder.Logging.ClearProviders(); // Authorization codes must never enter request logs.
        builder.WebHost.ConfigureKestrel(server =>
        {
            server.AddServerHeader = false;
            server.Limits.MaxRequestLineSize = 8192;
            server.Limits.MaxRequestHeadersTotalSize = 8192;
            server.Limits.MaxRequestBodySize = 0;
            server.Limits.MaxConcurrentConnections = 4;
            server.Limits.RequestHeadersTimeout = TimeSpan.FromSeconds(5);
            server.Listen(IPAddress.Loopback, 48329);
        });
        receiver._app = builder.Build();
        receiver._app.Run(async context =>
        {
            context.Response.Headers.CacheControl = "no-store";
            context.Response.Headers["Referrer-Policy"] = "no-referrer";
            context.Response.Headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'";
            context.Response.ContentType = "text/plain; charset=utf-8";
            if (context.Request.Method != "GET" || context.Request.Host.Value != "127.0.0.1:48329" ||
                context.Request.PathBase.HasValue || context.Request.Path.Value != "/auth/callback" ||
                context.Request.QueryString.Value is not { Length: > 1 and <= 8192 })
            {
                context.Response.StatusCode = 400;
                return;
            }
            var uri = new Uri(OidcLoginProtocol.RedirectUriString + context.Request.QueryString.Value);
            if (!receiver._response.TrySetResult(uri)) { context.Response.StatusCode = 409; return; }
            await context.Response.WriteAsync("Authorization response received. You can close this tab.");
        });
        try { await receiver._app.StartAsync(cancellationToken); return receiver; }
        catch { await receiver._app.DisposeAsync(); throw; }
    }

    public Task<Uri> WaitAsync(CancellationToken cancellationToken) => _response.Task.WaitAsync(cancellationToken);

    public async ValueTask DisposeAsync()
    {
        _response.TrySetCanceled();
        if (_app is not null)
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            try { await _app.StopAsync(timeout.Token); }
            finally { await _app.DisposeAsync(); _app = null; }
        }
    }
}
