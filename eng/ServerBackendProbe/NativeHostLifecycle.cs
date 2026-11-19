using System.Diagnostics;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Hosting;

namespace ServerBackendProbe;

internal static class NativeHostLifecycle
{
    internal static void RequireUnstarted(WebApplication app)
    {
        if (!app.Environment.IsProduction() || app.Lifetime.ApplicationStarted.IsCancellationRequested)
        { throw new InvalidOperationException("Native recovery host already started."); }
    }

    internal static async Task<long> ExecuteAsync(WebApplication app, CancellationToken cancellation)
    {
        RequireUnstarted(app);
        await WorkerCases.RequireHealthAsync(app.Services, HealthStatus.Healthy, cancellation);
        var worker = WorkerCases.GetUnstartedWorker(app.Services);
        foreach (var port in new[] { 19580, 19581, 19582 }) { await HostCases.ProbePortAsync(port, false, cancellation); }
        var timer = new Stopwatch();
        try
        {
            await app.StartAsync(cancellation);
            if (!app.Lifetime.ApplicationStarted.IsCancellationRequested || worker.ExecuteTask is null || worker.ExecuteTask.IsCompleted)
            { throw new InvalidOperationException("Native recovery worker lifecycle drift."); }
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
        { throw new InvalidOperationException("Native recovery host did not stop."); }
        foreach (var port in new[] { 19580, 19581, 19582 }) { await HostCases.ProbePortAsync(port, false, cancellation); }
        return timer.ElapsedMilliseconds;
    }
}
