using System.Diagnostics;
using Fleetory.Platform.Persistence;
using Microsoft.AspNetCore.Builder;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Hosting;

namespace ServerBackendProbe;

internal static class FreshPairHost
{
    internal static async Task<object> ExecuteAsync(WebApplication app, PlatformDbContext platform, CancellationToken cancellation)
    {
        using var input = await FixtureAuditClient.ReadPacketAsync(cancellation);
        var packet = input.RootElement;
        if (!app.Environment.IsProduction() || app.Lifetime.ApplicationStarted.IsCancellationRequested)
        { throw new InvalidOperationException("Fresh pair host already started."); }
        // Both native stores must match before StartAsync can run or the worker can claim anything.
        var before = await PreflightAsync(packet, platform, cancellation);
        await WorkerCases.RequireHealthAsync(app.Services, HealthStatus.Healthy, cancellation);
        var worker = WorkerCases.GetUnstartedWorker(app.Services);
        foreach (var port in new[] { 19580, 19581, 19582 }) { await HostCases.ProbePortAsync(port, false, cancellation); }
        var timer = new Stopwatch();
        try
        {
            await app.StartAsync(cancellation);
            if (!app.Lifetime.ApplicationStarted.IsCancellationRequested || worker.ExecuteTask is null || worker.ExecuteTask.IsCompleted)
            { throw new InvalidOperationException("Fresh pair native worker lifecycle drift."); }
            await WorkerCases.RequireHealthAsync(app.Services, HealthStatus.Healthy, cancellation);
            await HostCases.VerifyHttpAsync("Healthy", cancellation);
            foreach (var port in new[] { 19580, 19581, 19582 }) { await HostCases.ProbePortAsync(port, true, cancellation); }
        }
        finally
        {
            using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            timer.Start();
            await app.StopAsync(stop.Token).WaitAsync(stop.Token);
            timer.Stop();
        }
        if (!app.Lifetime.ApplicationStopped.IsCancellationRequested || worker.ExecuteTask is not { IsCompleted: true, IsFaulted: false })
        { throw new InvalidOperationException("Fresh pair host did not stop."); }
        foreach (var port in new[] { 19580, 19581, 19582 }) { await HostCases.ProbePortAsync(port, false, cancellation); }
        var after = await FreshPairControl.InspectAsync("pair-read", packet, platform.Database.GetDbConnection(), cancellation);
        var beforeJson = System.Text.Json.JsonSerializer.SerializeToElement(before);
        var afterJson = System.Text.Json.JsonSerializer.SerializeToElement(after);
        foreach (var field in new[] { "eventsSha256", "eventCount", "queueRows" })
        { if (!System.Text.Json.JsonElement.DeepEquals(beforeJson.GetProperty(field), afterJson.GetProperty(field))) { throw new InvalidOperationException("Fresh pair host changed audit data."); } }
        foreach (var field in new[] { "db", "txId", "txHash" })
        { if (!System.Text.Json.JsonElement.DeepEquals(beforeJson.GetProperty("state").GetProperty(field), afterJson.GetProperty("state").GetProperty(field))) { throw new InvalidOperationException("Fresh pair host changed audit tip."); } }
        return new { category = "pair-host", applicationStarts = 1, applicationStops = 1, readiness = "Healthy", healthBodies = 2,
            publicPrivatePathRefusals = 2, listeningPorts = 3, initialClosedPorts = 3, finalClosedPorts = 3,
            workerStopped = true, stopMilliseconds = timer.ElapsedMilliseconds, nonemptyDataUnchanged = true, issuerActivated = false };
    }

    private static async Task<object> PreflightAsync(System.Text.Json.JsonElement packet, PlatformDbContext platform, CancellationToken cancellation)
    {
        try { return await FreshPairControl.InspectAsync("pair-read", packet, platform.Database.GetDbConnection(), cancellation); }
        catch (InvalidOperationException error) when (error.Message is
            "Fresh pair field count drift." or "Fresh pair field drift." or "Fresh pair event identity drift." or
            "Fresh pair missing event." or "Fresh pair row count drift." or "Fresh pair audit key set drift." or
            "Fresh pair audit revision drift." or "Fresh pair audit changed during readback.")
        { throw new FreshPairPreflightException(); }
    }
}

internal sealed class FreshPairPreflightException : Exception;
