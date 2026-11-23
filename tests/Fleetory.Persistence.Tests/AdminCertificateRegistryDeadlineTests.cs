using Fleetory.Platform.Authorization;
using Fleetory.Platform.Persistence;
using Npgsql;

namespace Fleetory.Persistence.Tests;

[Collection(PostgreSqlTestCollection.Name)]
public sealed class AdminCertificateRegistryDeadlineTests(PostgreSqlTestFixture fixture)
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Registration_overlap_uses_current_database_time_after_a_lock_wait(bool expireDuringRead)
    {
        using var lifetime = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var cancellationToken = lifetime.Token;
        var fingerprint = Guid.NewGuid().ToString("N").ToUpperInvariant() +
            Guid.NewGuid().ToString("N").ToUpperInvariant();
        var actor = $"person:{Guid.NewGuid():N}";
        var store = new AdminCertificateAccessStore(new PostgreSqlConnectionSettings(fixture.ConnectionString));
        await using var blocker = new NpgsqlConnection(fixture.ConnectionString);
        await blocker.OpenAsync(cancellationToken);
        await using var seed = new NpgsqlCommand("""
            INSERT INTO platform.admin_certificate_registrations
                (certificate_sha256, actor_subject_id, registered_at, overlap_ends_at,
                 incident_reference, operator_reference)
            VALUES (@fingerprint, @actor, clock_timestamp(), clock_timestamp() + @duration,
                    'registry-deadline-test', 'test-operator')
            RETURNING overlap_ends_at
            """, blocker);
        seed.Parameters.AddWithValue("fingerprint", fingerprint);
        seed.Parameters.AddWithValue("actor", actor);
        seed.Parameters.AddWithValue("duration", TimeSpan.FromSeconds(expireDuringRead ? 10 : 60));
        var expiresAt = (DateTime) (await seed.ExecuteScalarAsync(cancellationToken))!;
        try
        {
            var initial = await store.CheckAsync(fingerprint, actor, true, cancellationToken);
            Assert.Equal(AdminCertificateAccess.Accepted, initial.Status);
            Assert.Equal(new DateTimeOffset(expiresAt), initial.RegistrationExpiresAt);
            await using var transaction = await blocker.BeginTransactionAsync(cancellationToken);
            await using var tableLock = new NpgsqlCommand(
                "LOCK TABLE platform.admin_certificate_registrations IN ACCESS EXCLUSIVE MODE", blocker, transaction);
            await tableLock.ExecuteNonQueryAsync(cancellationToken);
            var pending = store.CheckAsync(fingerprint, actor, true, cancellationToken).AsTask();
            try
            {
                await PostgreSqlLockWait.ForReaderAsync(blocker, transaction,
                    "platform.admin_certificate_registrations", cancellationToken);
                if (expireDuringRead)
                {
                    await using var expired = new NpgsqlCommand("SELECT clock_timestamp() >= @expiry", blocker, transaction);
                    expired.Parameters.AddWithValue("expiry", expiresAt);
                    while (await expired.ExecuteScalarAsync(cancellationToken) is not true)
                    {
                        await Task.Delay(50, cancellationToken);
                    }
                }
            }
            finally
            {
                await transaction.RollbackAsync(CancellationToken.None);
            }

            var result = await pending;
            Assert.Equal(expireDuringRead ? AdminCertificateAccess.Unregistered : AdminCertificateAccess.Accepted,
                result.Status);
            if (!expireDuringRead) { Assert.Equal(initial.RegistrationExpiresAt, result.RegistrationExpiresAt); }
        }
        finally
        {
            await using var cleanup = new NpgsqlCommand("""
                DELETE FROM platform.admin_certificate_registrations
                WHERE certificate_sha256 = @fingerprint AND actor_subject_id = @actor
                """, blocker);
            cleanup.Parameters.AddWithValue("fingerprint", fingerprint);
            cleanup.Parameters.AddWithValue("actor", actor);
            await cleanup.ExecuteNonQueryAsync(CancellationToken.None);
        }
    }
}
