using System.Diagnostics;
using Fleetory.Platform.Contracts;
using Fleetory.Platform.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace ServerBackendProbe;

internal static class WorkerCases
{
    internal static async Task<object> ExecuteAsync(string mode, IServiceProvider root, IServiceProvider scoped,
        PlatformDbContext platform, CancellationToken cancellation)
    {
        await platform.Database.OpenConnectionAsync(cancellation);
        await DatabaseCases.VerifyAsync(platform, "platform.person_projections", cancellation);
        var initial = await ReadQueueAsync(platform, cancellation);
        var initialAttempts = mode == "worker-drain" ? 1 : 0;
        RequireQueue(initial, 1, initialAttempts);
        var before = mode == "worker-restart" ? HealthStatus.Healthy : HealthStatus.Degraded;
        await RequireHealthAsync(root, before, cancellation);
        var type = typeof(PlatformDbContext).Assembly.GetType("Fleetory.Platform.Audit.AuditExportWorker", throwOnError: true)!;
        var registered = root.GetServices<IHostedService>().Where(service => service.GetType() == type).ToArray();
        if (registered.Length != 1 || registered[0] is not BackgroundService worker || worker.ExecuteTask is not null)
        { throw new InvalidOperationException("Native worker registration drift."); }
        using var observation = new WorkerObservation();
        root.GetRequiredService<ILoggerFactory>().AddProvider(observation);
        await worker.StartAsync(cancellation);
        var stop = new Stopwatch();
        try
        {
            while (true)
            {
                if (worker.ExecuteTask is null || worker.ExecuteTask.IsCompleted)
                { throw new InvalidOperationException("Native worker stopped unexpectedly."); }
                var queue = await ReadQueueAsync(platform, cancellation);
                var ready = mode switch
                {
                    "worker-denied" => observation.Errors == 1 && queue is { Rows: 1, Attempts: 0, ClearLease: true },
                    "worker-retain" => queue is { Rows: 1, Attempts: 1, ClearLease: true },
                    "worker-drain" or "worker-restart" => queue.Rows == 0,
                    _ => throw new InvalidOperationException("Unknown native worker case.")
                };
                if (ready) { break; }
                await Task.Delay(TimeSpan.FromMilliseconds(50), cancellation);
            }
        }
        finally
        {
            using var stopDeadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            stop.Start();
            await worker.StopAsync(stopDeadline.Token).WaitAsync(stopDeadline.Token);
            stop.Stop();
            if (worker.ExecuteTask is not { IsCompleted: true, IsFaulted: false })
            { throw new InvalidOperationException("Native worker shutdown incomplete."); }
        }
        var drained = mode is "worker-drain" or "worker-restart";
        RequireQueue(await ReadQueueAsync(platform, cancellation), drained ? 0 : 1, mode == "worker-retain" ? 1 : 0);
        var after = drained ? HealthStatus.Healthy : HealthStatus.Degraded;
        await RequireHealthAsync(root, after, cancellation);
        if (observation.Errors != (mode == "worker-denied" ? 1 : 0))
        { throw new InvalidOperationException("Native worker failure category drift."); }
        if (mode == "worker-drain")
        {
            await scoped.GetRequiredService<IAuditWriter>().WriteAsync(DatabaseCases.CreateRecord("Fixture.Worker.AfterStop"), cancellation);
            // Longer than the worker's ordinary empty-batch poll interval, after its task has completed.
            await Task.Delay(TimeSpan.FromMilliseconds(1200), cancellation);
            RequireQueue(await ReadQueueAsync(platform, cancellation), 1, 0);
            await RequireHealthAsync(root, HealthStatus.Healthy, cancellation);
        }
        return new { processId = Environment.ProcessId, started = true, executionCompleted = true,
            stopElapsedMilliseconds = stop.ElapsedMilliseconds, claimFailures = observation.Errors,
            beforeHealth = before.ToString(), afterHealth = after.ToString(),
            afterStopPendingVerified = mode == "worker-drain" };
    }

    private static async Task<QueueState> ReadQueueAsync(PlatformDbContext platform, CancellationToken cancellation)
    {
        await using var command = platform.Database.GetDbConnection().CreateCommand();
        command.CommandText = "SELECT count(*),COALESCE(MAX(attempt_count),0),COALESCE(bool_and(lease_id IS NULL AND leased_until IS NULL),true) FROM platform.audit_export_queue;";
        await using var reader = await command.ExecuteReaderAsync(cancellation);
        if (!await reader.ReadAsync(cancellation)) { throw new InvalidOperationException("Worker queue state unavailable."); }
        return new QueueState(reader.GetInt64(0), reader.GetInt32(1), reader.GetBoolean(2));
    }

    private static void RequireQueue(QueueState queue, long rows, int attempts)
    {
        if (queue.Rows != rows || queue.Attempts != attempts || !queue.ClearLease)
        { throw new InvalidOperationException("Worker queue state drift."); }
    }

    private static async Task RequireHealthAsync(IServiceProvider root, HealthStatus expected, CancellationToken cancellation)
    {
        var result = await root.GetRequiredService<HealthCheckService>().CheckHealthAsync(
            registration => registration.Name == "audit_export_backlog", cancellation);
        if (result.Entries.Count != 1 || result.Status != expected)
        { throw new InvalidOperationException("Native backlog health drift."); }
    }

    private sealed record QueueState(long Rows, int Attempts, bool ClearLease);
}
