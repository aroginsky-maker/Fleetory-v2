using System.Collections.Concurrent;
using Fleetory.ModuleAbstractions;
using Fleetory.Platform.Audit;
using Fleetory.Platform.Contracts;
using Fleetory.Platform.Persistence;
using Fleetory.SharedKernel;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Npgsql;

namespace Fleetory.Persistence.Tests;

[Collection(PostgreSqlTestCollection.Name)]
public sealed class PostgreSqlAuditExportTests(PostgreSqlTestFixture fixture)
{
    [Fact]
    public async Task Audit_export_health_degrades_for_stale_pending_events_and_recovers_after_delivery()
    {
        await ClearQueueAsync();
        var clock = new AdjustableClock(DateTimeOffset.UtcNow);
        var check = new AuditExportBacklogHealthCheck(
            new PostgreSqlConnectionSettings(fixture.ConnectionString), clock);
        var context = new HealthCheckContext();
        Assert.Equal(HealthStatus.Healthy,
            (await check.CheckHealthAsync(context)).Status);

        await WriteAuditAsync();
        Assert.Equal(HealthStatus.Healthy,
            (await check.CheckHealthAsync(context)).Status);

        clock.UtcNow = clock.UtcNow.AddMinutes(6);
        Assert.Equal(HealthStatus.Degraded,
            (await check.CheckHealthAsync(context)).Status);

        Assert.Equal(1, await CreatePump(new CapturingSink(), clock).ExportNextBatchAsync());
        Assert.Equal(HealthStatus.Healthy,
            (await check.CheckHealthAsync(context)).Status);
    }

    [Fact]
    public async Task Delivery_preserves_event_identity_and_dequeues_only_after_sink_accepts()
    {
        await ClearQueueAsync();
        var correlation = await WriteAuditAsync();
        var clock = new AdjustableClock(DateTimeOffset.UtcNow.AddSeconds(1));
        var sink = new CapturingSink();
        var pump = CreatePump(sink, clock);

        Assert.Equal(1, await pump.ExportNextBatchAsync());
        Assert.Equal(0, await pump.ExportNextBatchAsync());

        var exported = Assert.Single(sink.Events);
        Assert.Equal(correlation, exported.Record.CorrelationId);
        Assert.Equal("Core.Device.Read", exported.Record.Action);
        Assert.Equal("Device", exported.Record.Target?.Type);
        Assert.Equal("device-42", exported.Record.Target?.Id);
        Assert.Equal("Allowed", exported.Record.Context?["Decision"]);
        Assert.NotEqual(Guid.Empty, exported.EventId);
        Assert.True(exported.RecordedAt <= clock.UtcNow);
        Assert.Equal(0L, await QueueCountAsync());
    }

    [Fact]
    public async Task Failed_delivery_is_retried_with_same_event_id_after_backoff()
    {
        await ClearQueueAsync();
        await WriteAuditAsync();
        var clock = new AdjustableClock(DateTimeOffset.UtcNow.AddSeconds(1));
        var sink = new CapturingSink(failFirst: true);
        var pump = CreatePump(sink, clock);

        Assert.Equal(0, await pump.ExportNextBatchAsync());
        Assert.Equal(1L, await QueueCountAsync());
        Assert.Equal(0, await pump.ExportNextBatchAsync());

        clock.UtcNow = clock.UtcNow.AddSeconds(3);
        Assert.Equal(1, await pump.ExportNextBatchAsync());
        Assert.Equal(0L, await QueueCountAsync());
        var attempts = sink.Events.ToArray();
        Assert.Equal(2, attempts.Length);
        Assert.Equal(attempts[0].EventId, attempts[1].EventId);
    }

    [Fact]
    public async Task Unexpired_lease_blocks_delivery_and_expired_lease_is_recovered()
    {
        await ClearQueueAsync();
        await WriteAuditAsync();
        var clock = new AdjustableClock(DateTimeOffset.UtcNow.AddSeconds(1));
        var sink = new CapturingSink();
        var pump = CreatePump(sink, clock);

        await using (var connection = new NpgsqlConnection(fixture.ConnectionString))
        {
            await connection.OpenAsync();
            await using var command = new NpgsqlCommand("""
                UPDATE platform.audit_export_queue
                SET lease_id = @lease_id, leased_until = @leased_until
                """, connection);
            command.Parameters.AddWithValue("lease_id", Guid.NewGuid());
            command.Parameters.AddWithValue("leased_until", clock.UtcNow.AddMinutes(1));
            Assert.Equal(1, await command.ExecuteNonQueryAsync());
        }

        Assert.Equal(0, await pump.ExportNextBatchAsync());
        clock.UtcNow = clock.UtcNow.AddMinutes(2);
        Assert.Equal(1, await pump.ExportNextBatchAsync());
        Assert.Single(sink.Events);
        Assert.Equal(0L, await QueueCountAsync());
    }

    [Fact]
    public async Task Concurrent_pumps_do_not_claim_the_same_live_lease()
    {
        await ClearQueueAsync();
        await WriteAuditAsync();
        var clock = new AdjustableClock(DateTimeOffset.UtcNow.AddSeconds(1));
        var sink = new BlockingSink();
        var first = CreatePump(sink, clock);
        var second = CreatePump(sink, clock);

        var firstDelivery = first.ExportNextBatchAsync();
        await sink.Started.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(0, await second.ExportNextBatchAsync());
        sink.Release.SetResult(true);
        Assert.Equal(1, await firstDelivery);
        Assert.Equal(1, sink.CallCount);
        Assert.Equal(0L, await QueueCountAsync());
    }

    [Fact]
    public async Task Enabled_background_worker_delivers_new_audit_events()
    {
        await ClearQueueAsync();
        var sink = new CapturingSink();
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionStrings:Fleetory"] = fixture.ConnectionString,
                ["Fleetory:AuditExport:Enabled"] = "true"
            })
            .Build();
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<IAuditExportSink>(sink);
        var platform = new Fleetory.Platform.PlatformModule();
        services.AddSingleton<IReadOnlyCollection<IFleetoryModule>>(new IFleetoryModule[] { platform });
        platform.RegisterServices(services, configuration);
        await using var provider = services.BuildServiceProvider(
            new ServiceProviderOptions { ValidateOnBuild = true });
        var worker = Assert.Single(provider.GetServices<IHostedService>().OfType<AuditExportWorker>());

        await worker.StartAsync(CancellationToken.None);
        try
        {
            var correlation = await WriteAuditAsync();
            var deadline = DateTimeOffset.UtcNow.AddSeconds(10);
            while ((sink.Events.IsEmpty || await QueueCountAsync() != 0) &&
                   DateTimeOffset.UtcNow < deadline)
            {
                await Task.Delay(50);
            }

            Assert.True(!sink.Events.IsEmpty && await QueueCountAsync() == 0,
                $"Worker did not drain the queue: sent={sink.Events.Count}, pending={await QueueCountAsync()}.");
            Assert.Equal(correlation, Assert.Single(sink.Events).Record.CorrelationId);
            Assert.Equal(0L, await QueueCountAsync());
        }
        finally
        {
            await worker.StopAsync(CancellationToken.None);
        }
    }

    private PostgreSqlAuditExportPump CreatePump(IAuditExportSink sink, IClock clock) =>
        new(new PostgreSqlConnectionSettings(fixture.ConnectionString), sink, clock,
            NullLogger<PostgreSqlAuditExportPump>.Instance);

    private async Task<CorrelationId> WriteAuditAsync()
    {
        var correlation = CorrelationId.New();
        await using var scope = fixture.Services.CreateAsyncScope();
        await scope.ServiceProvider.GetRequiredService<IAuditWriter>().WriteAsync(new AuditRecord(
            new ActorReference("system:export-test", ActorKind.System),
            "Core.Device.Read",
            new AuditTarget("Device", "device-42"),
            correlation,
            DateTimeOffset.UtcNow,
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["Decision"] = "Allowed"
            }));
        return correlation;
    }

    private async Task ClearQueueAsync()
    {
        await using var connection = new NpgsqlConnection(fixture.ConnectionString);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand("DELETE FROM platform.audit_export_queue", connection);
        await command.ExecuteNonQueryAsync();
    }

    private async Task<long> QueueCountAsync()
    {
        await using var connection = new NpgsqlConnection(fixture.ConnectionString);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand("SELECT COUNT(*) FROM platform.audit_export_queue", connection);
        return Convert.ToInt64(await command.ExecuteScalarAsync());
    }

    private sealed class AdjustableClock(DateTimeOffset utcNow) : IClock
    {
        public DateTimeOffset UtcNow { get; set; } = utcNow;
    }

    private sealed class CapturingSink(bool failFirst = false) : IAuditExportSink
    {
        public ConcurrentQueue<AuditExportEvent> Events { get; } = new();

        private int _callCount;

        public ValueTask PublishAsync(
            AuditExportEvent auditEvent,
            CancellationToken cancellationToken = default)
        {
            Events.Enqueue(auditEvent);
            if (failFirst && Interlocked.Increment(ref _callCount) == 1)
            {
                throw new InvalidOperationException("Simulated sink failure.");
            }

            return ValueTask.CompletedTask;
        }
    }

    private sealed class BlockingSink : IAuditExportSink
    {
        public TaskCompletionSource<bool> Started { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public TaskCompletionSource<bool> Release { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public int CallCount { get; private set; }

        public async ValueTask PublishAsync(
            AuditExportEvent auditEvent,
            CancellationToken cancellationToken = default)
        {
            CallCount++;
            Started.TrySetResult(true);
            await Release.Task.WaitAsync(cancellationToken);
        }
    }

}
