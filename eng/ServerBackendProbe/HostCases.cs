using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using Fleetory.Platform.Persistence;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace ServerBackendProbe;

internal static class HostCases
{
    private static readonly int[] Ports = [19580, 19581, 19582];

    internal static async Task<object> ExecuteAsync(string mode, WebApplication app,
        PlatformDbContext platform, CancellationToken cancellation)
    {
        if (!app.Environment.IsProduction() || app.Lifetime.ApplicationStarted.IsCancellationRequested)
        { throw new InvalidOperationException("Unexpected native host state."); }
        await platform.Database.OpenConnectionAsync(cancellation);
        await DatabaseCases.VerifyAsync(platform, "platform.person_projections", cancellation);
        var registered = mode is "host-registered" or "host-revoked";
        WorkerCases.RequireQueue(await WorkerCases.ReadQueueAsync(platform, cancellation), registered ? 0 : 1, 0);
        await WorkerCases.RequireHealthAsync(app.Services, registered ? HealthStatus.Healthy : HealthStatus.Degraded, cancellation);
        var worker = WorkerCases.GetUnstartedWorker(app.Services);
        using var observation = new WorkerObservation();
        app.Services.GetRequiredService<ILoggerFactory>().AddProvider(observation);
        foreach (var port in Ports) { await ProbePortAsync(port, false, cancellation); }
        var expected = mode == "host-degraded" ? HealthStatus.Degraded : HealthStatus.Healthy;
        var stop = new Stopwatch();
        object? clientTls = null;
        object? registeredBoundary = null;
        object? revokedBoundary = null;
        try
        {
            await app.StartAsync(cancellation);
            if (!app.Lifetime.ApplicationStarted.IsCancellationRequested)
            { throw new InvalidOperationException("Native host startup not observed."); }
            await WaitForWorkerAsync(mode, worker, observation, platform, cancellation);
            await WorkerCases.RequireHealthAsync(app.Services, expected, cancellation);
            RequireGetRoute(app, "/agent/identity");
            RequireGetRoute(app, "/admin/authorization/roles/{roleId:guid}/versions");
            await VerifyHttpAsync(expected.ToString(), cancellation);
            foreach (var port in Ports) { await ProbePortAsync(port, true, cancellation); }
            if (mode == "host-drain") { clientTls = await ClientTlsCases.ExecuteAsync(app.Services, cancellation); }
            if (registered)
            {
                using var tls = new TlsObservation();
                var boundary = await RegistryCases.ExecuteAsync(app.Services, tls,
                    mode == "host-revoked" ? CredentialState.Revoked : CredentialState.Registered, cancellation);
                if (mode == "host-revoked") { revokedBoundary = boundary; }
                else { registeredBoundary = boundary; }
            }
            await WorkerCases.RequireHealthAsync(app.Services, expected, cancellation);
        }
        finally
        {
            using var stopDeadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            stop.Start();
            await app.StopAsync(stopDeadline.Token).WaitAsync(stopDeadline.Token);
            stop.Stop();
        }
        if (!app.Lifetime.ApplicationStopped.IsCancellationRequested ||
            worker.ExecuteTask is not { IsCompleted: true, IsFaulted: false })
        { throw new InvalidOperationException("Native host shutdown incomplete."); }
        foreach (var port in Ports) { await ProbePortAsync(port, false, cancellation); }
        WorkerCases.RequireQueue(await WorkerCases.ReadQueueAsync(platform, cancellation), mode == "host-degraded" ? 1 : 0, 0);
        if ((mode == "host-degraded" && observation.Errors < 1) || (mode != "host-degraded" && observation.Errors != 0))
        { throw new InvalidOperationException("Native host worker failure drift."); }
        return new { processId = Environment.ProcessId, applicationStarted = true, applicationStopped = true,
            workerExecutionCompleted = true, stopElapsedMilliseconds = stop.ElapsedMilliseconds,
            claimFailures = observation.Errors, livenessBody = "Healthy", readinessBody = expected.ToString(),
            readinessStatusCode = 200, publicPrivilegedPathRefusals = 2, listeningPorts = Ports,
            closedPortRefusals = 3, initialClosedPortRefusals = 3, clientTls, registeredBoundary, revokedBoundary };
    }

    private static async Task WaitForWorkerAsync(string mode, BackgroundService worker, WorkerObservation observation,
        PlatformDbContext platform, CancellationToken cancellation)
    {
        while (true)
        {
            if (worker.ExecuteTask is null || worker.ExecuteTask.IsCompleted)
            { throw new InvalidOperationException("Hosted worker did not remain active."); }
            var queue = await WorkerCases.ReadQueueAsync(platform, cancellation);
            if (mode == "host-degraded"
                ? observation.Errors >= 1 && queue is { Rows: 1, Attempts: 0, ClearLease: true }
                : queue.Rows == 0) { return; }
            await Task.Delay(TimeSpan.FromMilliseconds(50), cancellation);
        }
    }

    private static async Task VerifyHttpAsync(string expected, CancellationToken cancellation)
    {
        using var client = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false })
        { BaseAddress = new Uri("http://127.0.0.1:19580/"), Timeout = TimeSpan.FromSeconds(2) };
        await RequireResponseAsync(client, "health/live", HttpStatusCode.OK, "Healthy", cancellation);
        await RequireResponseAsync(client, "health/ready", HttpStatusCode.OK, expected, cancellation);
        await RequireResponseAsync(client, "admin/authorization/roles/00000000-0000-4000-8000-000000000001/versions", HttpStatusCode.NotFound, "", cancellation);
        await RequireResponseAsync(client, "agent/identity", HttpStatusCode.NotFound, "", cancellation);
    }

    private static void RequireGetRoute(WebApplication app, string pattern)
    {
        var routes = app.Services.GetRequiredService<EndpointDataSource>().Endpoints.OfType<RouteEndpoint>()
            .Where(endpoint => endpoint.RoutePattern.RawText == pattern &&
                endpoint.Metadata.GetMetadata<HttpMethodMetadata>()?.HttpMethods.Contains("GET", StringComparer.Ordinal) == true).ToArray();
        if (routes.Length != 1) { throw new InvalidOperationException("Native private GET route missing or ambiguous."); }
    }

    private static async Task RequireResponseAsync(HttpClient client, string path, HttpStatusCode status,
        string expected, CancellationToken cancellation)
    {
        using var response = await client.GetAsync(path, HttpCompletionOption.ResponseHeadersRead, cancellation);
        if (response.StatusCode != status) { throw new InvalidOperationException("Native HTTP status drift."); }
        await using var stream = await response.Content.ReadAsStreamAsync(cancellation);
        var bytes = new byte[65];
        var length = 0;
        while (length < bytes.Length)
        {
            var read = await stream.ReadAsync(bytes.AsMemory(length), cancellation);
            if (read == 0) { break; }
            length += read;
        }
        if (length > 64 || System.Text.Encoding.UTF8.GetString(bytes, 0, length) != expected)
        { throw new InvalidOperationException("Native HTTP body drift."); }
    }

    private static async Task ProbePortAsync(int port, bool open, CancellationToken cancellation)
    {
        using var client = new TcpClient(AddressFamily.InterNetwork);
        try
        {
            await client.ConnectAsync(IPAddress.Loopback, port, cancellation);
            if (!open) { throw new InvalidOperationException("Unexpected native listener."); }
        }
        catch (SocketException exception) when (!open && exception.SocketErrorCode == SocketError.ConnectionRefused)
        { /* Only native refusal proves closure; timeouts or other errors do not pass. */ }
    }
}
