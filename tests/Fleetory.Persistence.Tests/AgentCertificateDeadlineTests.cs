using System.Data.Common;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Fleetory.Core.Contracts;
using Fleetory.Core.Persistence;
using Fleetory.Core.Security;
using Fleetory.Platform.Contracts;
using Fleetory.SharedKernel;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;

namespace Fleetory.Persistence.Tests;

[Collection(PostgreSqlTestCollection.Name)]
public sealed class AgentCertificateDeadlineTests(PostgreSqlTestFixture fixture)
{
    [Theory]
    [InlineData(299, true)]
    [InlineData(300, false)]
    public async Task Enrollment_uses_the_time_after_the_device_lock(int seconds, bool allowed)
    {
        await using var test = new DeadlineFixture(fixture);
        var token = await test.CreateInitialGrantAsync();
        var releasedAt = test.Clock.UtcNow.AddSeconds(seconds);
        var failure = await test.WhileDeviceLockedAsync(
            () => test.Enrollment.EnrollAsync(test.Device, test.Pki.Client, token,
                CorrelationId.New()).AsTask(), releasedAt);

        if (allowed) { Assert.Null(failure); }
        else { Assert.IsType<UnauthorizedAccessException>(failure); }
        var grant = await test.Database.AgentEnrollmentGrants.AsNoTracking()
            .SingleAsync(row => row.DeviceId == test.Device);
        Assert.Equal(allowed ? releasedAt : (DateTimeOffset?)null, grant.ConsumedAt);
        Assert.Equal(allowed ? 1 : 0, await test.Database.AgentCertificates
            .CountAsync(row => row.DeviceId == test.Device));
    }

    [Theory]
    [InlineData(299, true)]
    [InlineData(300, false)]
    public async Task Rotation_intent_cannot_expire_while_a_grant_waits_for_the_device_lock(
        int seconds, bool allowed)
    {
        await using var test = new DeadlineFixture(fixture);
        await test.BindInitialCertificateAsync();
        var intent = await test.Enrollment.CreateRotationIntentAsync(test.Device,
            test.Pki.Client, Fingerprint(test.Pki.UnregisteredClient), CorrelationId.New());
        var releasedAt = test.Clock.UtcNow.AddSeconds(seconds);
        var failure = await test.WhileDeviceLockedAsync(async () =>
        {
            await test.Enrollment.CreateGrantAsync(test.Requester, test.Device, "rotation deadline",
                CorrelationId.New(), Fingerprint(test.Pki.Client), intent);
        }, releasedAt);

        if (allowed) { Assert.Null(failure); }
        else { Assert.IsType<AgentRotationIntentException>(failure); }
        var row = await test.Database.AgentRotationIntents.AsNoTracking()
            .SingleAsync(row => row.IntentId == intent);
        Assert.Equal(allowed ? releasedAt : (DateTimeOffset?)null, row.ClaimedAt);
        var grants = await test.Database.AgentEnrollmentGrants.AsNoTracking()
            .Where(row => row.DeviceId == test.Device && row.ConsumedAt == null).ToListAsync();
        if (allowed) { Assert.Equal(releasedAt.AddMinutes(5), Assert.Single(grants).ExpiresAt); }
        else { Assert.Empty(grants); }
    }

    [Theory]
    [InlineData(899, true)]
    [InlineData(900, false)]
    public async Task Recovery_approval_cannot_outlive_its_request_while_waiting_for_the_device_lock(
        int seconds, bool allowed)
    {
        await using var test = new DeadlineFixture(fixture);
        await test.BindInitialCertificateAsync();
        var replacement = Fingerprint(test.Pki.UnregisteredClient);
        var evidence = new string('A', 64);
        var recovery = await test.Recovery.RequestAsync(test.Requester, test.Device,
            Fingerprint(test.Pki.Client), replacement, evidence, "test-incident", CorrelationId.New());
        var releasedAt = test.Clock.UtcNow.AddSeconds(seconds);
        var failure = await test.WhileDeviceLockedAsync(async () =>
        {
            await test.Recovery.ApproveAsync(test.Approver, test.Device, recovery,
                replacement, evidence, "test-incident", CorrelationId.New());
        }, releasedAt);

        if (allowed) { Assert.Null(failure); }
        else { Assert.IsType<AgentRecoveryConflictException>(failure); }
        var row = await test.Database.AgentCertificateRecoveries.AsNoTracking()
            .SingleAsync(row => row.RecoveryId == recovery);
        Assert.Equal(allowed ? releasedAt : (DateTimeOffset?)null, row.ApprovedAt);
        var certificate = await test.Database.AgentCertificates.AsNoTracking()
            .SingleAsync(row => row.DeviceId == test.Device);
        Assert.Equal(allowed ? releasedAt : (DateTimeOffset?)null, certificate.RevokedAt);
        var grants = await test.Database.AgentEnrollmentGrants.AsNoTracking()
            .Where(row => row.DeviceId == test.Device && row.ConsumedAt == null).ToListAsync();
        if (allowed) { Assert.Equal(releasedAt.AddMinutes(5), Assert.Single(grants).ExpiresAt); }
        else { Assert.Empty(grants); }
    }

    [Theory]
    [InlineData(true, 5)]
    [InlineData(false, 15)]
    public async Task A_new_request_gets_its_full_lifetime_after_the_device_lock(bool rotation, int minutes)
    {
        await using var test = new DeadlineFixture(fixture);
        await test.BindInitialCertificateAsync();
        var replacement = Fingerprint(test.Pki.UnregisteredClient);
        var releasedAt = test.Clock.UtcNow.AddMinutes(1);
        var failure = await test.WhileDeviceLockedAsync(async () =>
        {
            if (rotation)
            {
                await test.Enrollment.CreateRotationIntentAsync(test.Device,
                    test.Pki.Client, replacement, CorrelationId.New());
            }
            else
            {
                await test.Recovery.RequestAsync(test.Requester, test.Device,
                    Fingerprint(test.Pki.Client), replacement, new string('C', 64),
                    "test-created-after-lock", CorrelationId.New());
            }
        }, releasedAt);

        Assert.Null(failure);
        var expiry = rotation
            ? (await test.Database.AgentRotationIntents.AsNoTracking()
                .SingleAsync(row => row.DeviceId == test.Device)).ExpiresAt
            : (await test.Database.AgentCertificateRecoveries.AsNoTracking()
                .SingleAsync(row => row.DeviceId == test.Device)).ExpiresAt;
        Assert.Equal(releasedAt.AddMinutes(minutes), expiry);
    }

    [Fact]
    public async Task A_new_certificate_expiring_during_the_lock_wait_is_not_bound()
    {
        await using var test = new DeadlineFixture(fixture);
        var expiry = new DateTimeOffset(test.Pki.Client.NotAfter.ToUniversalTime());
        test.Clock.UtcNow = expiry.AddMinutes(-2);
        var token = await test.CreateInitialGrantAsync();
        var failure = await test.WhileDeviceLockedAsync(
            () => test.Enrollment.EnrollAsync(test.Device, test.Pki.Client, token,
                CorrelationId.New()).AsTask(), expiry);

        Assert.IsType<UnauthorizedAccessException>(failure);
        Assert.False(await test.Database.AgentCertificates.AnyAsync(row => row.DeviceId == test.Device));
        Assert.Null((await test.Database.AgentEnrollmentGrants.AsNoTracking()
            .SingleAsync(row => row.DeviceId == test.Device)).ConsumedAt);
    }

    [Fact]
    public async Task An_old_certificate_expiring_during_the_lock_wait_cannot_create_a_rotation_intent()
    {
        await using var test = new DeadlineFixture(fixture);
        var expiry = new DateTimeOffset(test.Pki.Client.NotAfter.ToUniversalTime());
        test.Clock.UtcNow = expiry.AddMinutes(-2);
        await test.BindInitialCertificateAsync();
        var failure = await test.WhileDeviceLockedAsync(async () =>
        {
            await test.Enrollment.CreateRotationIntentAsync(test.Device, test.Pki.Client,
                Fingerprint(test.Pki.UnregisteredClient), CorrelationId.New());
        }, expiry);

        Assert.IsType<UnauthorizedAccessException>(failure);
        Assert.False(await test.Database.AgentRotationIntents.AnyAsync(row => row.DeviceId == test.Device));
    }

    [Fact]
    public async Task Recovery_expiry_after_revocation_rolls_back_all_credential_changes()
    {
        var interceptor = new AfterRevocationInterceptor();
        await using var test = new DeadlineFixture(fixture, interceptor);
        await test.BindInitialCertificateAsync();
        var replacement = Fingerprint(test.Pki.UnregisteredClient);
        var intent = await test.Enrollment.CreateRotationIntentAsync(test.Device,
            test.Pki.Client, replacement, CorrelationId.New());
        await test.Enrollment.CreateGrantAsync(test.Requester, test.Device, "pending rotation",
            CorrelationId.New(), Fingerprint(test.Pki.Client), intent);
        var evidence = new string('B', 64);
        var recovery = await test.Recovery.RequestAsync(test.Requester, test.Device,
            Fingerprint(test.Pki.Client), replacement, evidence, "test-rollback", CorrelationId.New());
        var expiry = (await test.Database.AgentCertificateRecoveries.AsNoTracking()
            .SingleAsync(row => row.RecoveryId == recovery)).ExpiresAt;
        interceptor.AfterRevocation = () => test.Clock.UtcNow = expiry;

        await Assert.ThrowsAsync<AgentRecoveryConflictException>(async () =>
            await test.Recovery.ApproveAsync(test.Approver, test.Device, recovery,
                replacement, evidence, "test-rollback", CorrelationId.New()));

        Assert.True(interceptor.RevocationObserved);
        Assert.Null((await test.Database.AgentCertificates.AsNoTracking()
            .SingleAsync(row => row.DeviceId == test.Device)).RevokedAt);
        Assert.Null((await test.Database.AgentCertificateRecoveries.AsNoTracking()
            .SingleAsync(row => row.RecoveryId == recovery)).ApprovedAt);
        Assert.True(await test.Database.AgentRotationIntents.AnyAsync(row => row.IntentId == intent));
        var grants = await test.Database.AgentEnrollmentGrants.AsNoTracking()
            .Where(row => row.DeviceId == test.Device).ToListAsync();
        Assert.Equal(2, grants.Count);
        Assert.Single(grants, row => row.ConsumedAt is null && row.RecoveryRequestId is null);
    }

    private static string Fingerprint(X509Certificate2 certificate) =>
        Convert.ToHexString(SHA256.HashData(certificate.RawData));

    private sealed class MutableClock : IClock
    {
        public DateTimeOffset UtcNow { get; set; } =
            DateTimeOffset.FromUnixTimeMilliseconds(DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
    }

    private sealed class AllowedAuthorization : IAuthorizationService
    {
        public ValueTask<AuthorizationDecision> AuthorizeAsync(AuthorizationRequest request,
            CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(AuthorizationDecision.Allow());
    }

    private sealed class AfterRevocationInterceptor : DbCommandInterceptor
    {
        public Action? AfterRevocation { get; set; }
        public bool RevocationObserved { get; private set; }

        public override ValueTask<int> NonQueryExecutedAsync(DbCommand command,
            CommandExecutedEventData eventData, int result, CancellationToken cancellationToken = default)
        {
            if (result > 0 && command.CommandText.StartsWith("UPDATE", StringComparison.Ordinal) &&
                command.CommandText.Contains("agent_certificates", StringComparison.Ordinal))
            {
                RevocationObserved = true;
                AfterRevocation?.Invoke();
            }
            return ValueTask.FromResult(result);
        }
    }

    private sealed class DeadlineFixture : IAsyncDisposable
    {
        private readonly PostgreSqlTestFixture _fixture;
        private readonly AsyncServiceScope _scope;
        private readonly bool _ownsDatabase;

        public DeadlineFixture(PostgreSqlTestFixture fixture, DbCommandInterceptor? interceptor = null)
        {
            _fixture = fixture;
            _scope = fixture.Services.CreateAsyncScope();
            var services = _scope.ServiceProvider;
            _ownsDatabase = interceptor is not null;
            Database = interceptor is null ? services.GetRequiredService<CoreDbContext>() :
                new CoreDbContext(new DbContextOptionsBuilder<CoreDbContext>(
                    services.GetRequiredService<DbContextOptions<CoreDbContext>>())
                    .AddInterceptors(interceptor).Options);
            Pki = new AgentGatewayTlsTests.TestPki(Device);
            var authorization = new AllowedAuthorization();
            var audit = services.GetRequiredService<IAuditWriter>();
            var verifier = new AgentCertificateBindingVerifier(
                services.GetRequiredService<IAgentCertificateBindingStore>(), Clock);
            Enrollment = new AgentEnrollmentService(authorization, audit, verifier, Database, Clock);
            Recovery = new AgentCertificateRecoveryService(authorization, audit, Database, Clock);
        }

        public DeviceId Device { get; } = new(Guid.NewGuid());
        public MutableClock Clock { get; } = new();
        public ActorReference Requester { get; } = new("person:" + Guid.NewGuid().ToString("N"), ActorKind.Person);
        public ActorReference Approver { get; } = new("person:" + Guid.NewGuid().ToString("N"), ActorKind.Person);
        public AgentGatewayTlsTests.TestPki Pki { get; }
        public CoreDbContext Database { get; }
        public AgentEnrollmentService Enrollment { get; }
        public AgentCertificateRecoveryService Recovery { get; }

        public async Task<string> CreateInitialGrantAsync() =>
            await Enrollment.CreateGrantAsync(Requester, Device, "deadline fixture", CorrelationId.New(),
                initialCertificateSha256: Fingerprint(Pki.Client));

        public async Task BindInitialCertificateAsync() =>
            await Enrollment.EnrollAsync(Device, Pki.Client, await CreateInitialGrantAsync(), CorrelationId.New());

        public async Task<Exception?> WhileDeviceLockedAsync(Func<Task> operation, DateTimeOffset releasedAt)
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            await Database.Database.OpenConnectionAsync(timeout.Token);
            var backend = ((NpgsqlConnection)Database.Database.GetDbConnection()).ProcessID;
            await using var blocker = new NpgsqlConnection(_fixture.ConnectionString);
            await blocker.OpenAsync(timeout.Token);
            await using var transaction = await blocker.BeginTransactionAsync(timeout.Token);
            await using var command = new NpgsqlCommand(
                "SELECT device_id FROM core.devices WHERE device_id = @device FOR UPDATE", blocker, transaction);
            command.Parameters.AddWithValue("device", Device.Value);
            Assert.Equal(Device.Value, await command.ExecuteScalarAsync(timeout.Token));
            var pending = Record.ExceptionAsync(operation);
            try
            {
                await using var probe = new NpgsqlCommand(
                    "SELECT cardinality(pg_blocking_pids(@backend)) > 0", blocker, transaction);
                probe.Parameters.AddWithValue("backend", backend);
                while (await probe.ExecuteScalarAsync(timeout.Token) is not true)
                {
                    await Task.Delay(20, timeout.Token);
                }
                Clock.UtcNow = releasedAt;
            }
            finally
            {
                await transaction.RollbackAsync();
                await pending.WaitAsync(TimeSpan.FromSeconds(10));
            }
            return await pending;
        }

        public async ValueTask DisposeAsync()
        {
            Pki.Dispose();
            if (_ownsDatabase) { await Database.DisposeAsync(); }
            await _scope.DisposeAsync();
        }
    }
}
