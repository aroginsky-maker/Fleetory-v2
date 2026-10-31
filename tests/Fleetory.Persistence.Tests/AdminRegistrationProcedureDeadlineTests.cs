using System.Data;
using System.Security.Cryptography;
using Npgsql;

namespace Fleetory.Persistence.Tests;

[Collection(PostgreSqlTestCollection.Name)]
public sealed class AdminRegistrationProcedureDeadlineTests(PostgreSqlTestFixture fixture)
{
    [Theory]
    [InlineData("rotate", false, false, true)]
    [InlineData("rotate", true, false, false)]
    [InlineData("recovery", true, false, true)]
    [InlineData("recovery", false, false, false)]
    [InlineData("rotate", true, true, false)]
    [InlineData("rotate", false, true, true)]
    public async Task Operator_registration_evaluates_eligibility_and_stamps_time_after_locks(
        string mode, bool expiresWhileWaiting, bool rowLock, bool expectedSuccess)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        await using var test = new RegistrationCase(fixture.ConnectionString, mode);
        await test.InitializeAsync(expiresWhileWaiting, timeout.Token);
        var (error, releasedAt) = await test.AttemptAsync(expiresWhileWaiting, rowLock, timeout.Token);
        if (expectedSuccess) { Assert.Null(error); }
        else
        {
            var rejected = Assert.IsType<PostgresException>(error);
            Assert.Equal(PostgresErrorCodes.RaiseException, rejected.SqlState);
            Assert.Contains(mode == "rotate" ? "matching active prior" : "already has an active",
                rejected.MessageText, StringComparison.Ordinal);
        }
        await test.VerifyAsync(expectedSuccess, releasedAt, timeout.Token);
    }

    private sealed class RegistrationCase(string connectionString, string mode) : IAsyncDisposable
    {
        private readonly NpgsqlConnection _connection = new(connectionString);
        private readonly Guid _person = Guid.NewGuid();
        private readonly string _old = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        private readonly string _replacement = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        private NpgsqlTransaction? _transaction;
        private DateTime _expiry;
        private NpgsqlTransaction Transaction => _transaction ?? throw new InvalidOperationException("Not initialized.");

        public async Task InitializeAsync(bool expiresWhileWaiting, CancellationToken cancellationToken)
        {
            await _connection.OpenAsync(cancellationToken);
            await using var seed = new NpgsqlCommand("""
                INSERT INTO platform.admin_certificate_registrations
                    (certificate_sha256, actor_subject_id, registered_at, overlap_ends_at,
                     incident_reference, operator_reference)
                VALUES (@fingerprint, @actor, clock_timestamp(), clock_timestamp() + @duration,
                        'operator-deadline-test', 'test-operator')
                RETURNING overlap_ends_at
                """, _connection);
            seed.Parameters.AddWithValue("fingerprint", _old);
            seed.Parameters.AddWithValue("actor", $"person:{_person:N}");
            seed.Parameters.AddWithValue("duration", TimeSpan.FromSeconds(expiresWhileWaiting ? 10 : 60));
            _expiry = (DateTime)(await seed.ExecuteScalarAsync(cancellationToken))!;
            _transaction = await _connection.BeginTransactionAsync(cancellationToken);
            await using var configure = new NpgsqlCommand("""
                SELECT set_config('fleetory.admin_register.mode', @mode, true),
                       set_config('fleetory.admin_register.person_id', @person, true),
                       set_config('fleetory.admin_register.certificate_sha256', @replacement, true),
                       set_config('fleetory.admin_register.previous_certificate_sha256', @previous, true),
                       set_config('fleetory.admin_register.incident_reference', 'operator-deadline-test', true),
                       set_config('fleetory.admin_register.operator_reference', 'test-operator', true)
                """, _connection, Transaction);
            configure.Parameters.AddWithValue("mode", mode);
            configure.Parameters.AddWithValue("person", _person.ToString("D"));
            configure.Parameters.AddWithValue("replacement", _replacement);
            configure.Parameters.AddWithValue("previous", mode == "rotate" ? _old : "");
            await configure.ExecuteNonQueryAsync(cancellationToken);
            await Transaction.SaveAsync("before_registration", cancellationToken);
        }

        public async Task<(Exception? Error, DateTime ReleasedAt)> AttemptAsync(
            bool expiresWhileWaiting, bool rowLock, CancellationToken cancellationToken)
        {
            await using var blocker = new NpgsqlConnection(connectionString);
            await blocker.OpenAsync(cancellationToken);
            await using var blocked = await blocker.BeginTransactionAsync(cancellationToken);
            await using var hold = new NpgsqlCommand(rowLock
                ? "SELECT certificate_sha256 FROM platform.admin_certificate_registrations WHERE certificate_sha256 = @old FOR UPDATE"
                : "SELECT pg_advisory_xact_lock(2067, 3)", blocker, blocked);
            if (rowLock) { hold.Parameters.AddWithValue("old", _old); }
            await hold.ExecuteNonQueryAsync(cancellationToken);
            var sql = await File.ReadAllTextAsync(
                Path.Combine(AppContext.BaseDirectory, "register-admin-certificate.sql"), cancellationToken);
            await using var operation = new NpgsqlCommand(sql, _connection, Transaction);
            var backend = _connection.ProcessID;
            var pending = Record.ExceptionAsync(async () => { await operation.ExecuteNonQueryAsync(cancellationToken); });
            DateTime releasedAt;
            try
            {
                await PostgreSqlLockWait.ForBackendAsync(blocker, blocked, backend,
                    rowLock ? "transactionid" : "advisory", cancellationToken);
                if (expiresWhileWaiting) { await WaitForExpiryAsync(blocker, blocked, cancellationToken); }
                await using var timestamp = new NpgsqlCommand("SELECT clock_timestamp()", blocker, blocked);
                releasedAt = (DateTime)(await timestamp.ExecuteScalarAsync(cancellationToken))!;
            }
            finally { await blocked.RollbackAsync(CancellationToken.None); }
            return (await pending, releasedAt);
        }

        private async Task WaitForExpiryAsync(NpgsqlConnection blocker, NpgsqlTransaction transaction,
            CancellationToken cancellationToken)
        {
            await using var expired = new NpgsqlCommand("SELECT clock_timestamp() >= @expiry", blocker, transaction);
            expired.Parameters.AddWithValue("expiry", _expiry);
            while (await expired.ExecuteScalarAsync(cancellationToken) is not true)
            {
                await Task.Delay(50, cancellationToken);
            }
        }

        public async Task VerifyAsync(bool success, DateTime releasedAt, CancellationToken cancellationToken)
        {
            if (!success) { await Transaction.RollbackAsync("before_registration", cancellationToken); }
            await using var verify = new NpgsqlCommand("""
                SELECT prior.overlap_ends_at, replacement.registered_at,
                       (SELECT count(*) FROM platform.audit_events WHERE target_id = @replacement),
                       (SELECT count(*) FROM platform.audit_events AS event
                        JOIN platform.audit_export_queue AS queue ON queue.audit_event_id = event.event_id
                        WHERE event.target_id = @replacement AND event.action = @action
                          AND event.occurred_at = replacement.registered_at
                          AND event.recorded_at = replacement.registered_at
                          AND queue.enqueued_at = replacement.registered_at
                          AND queue.next_attempt_at = replacement.registered_at)
                FROM platform.admin_certificate_registrations AS prior
                LEFT JOIN platform.admin_certificate_registrations AS replacement
                  ON replacement.certificate_sha256 = @replacement
                WHERE prior.certificate_sha256 = @old
                """, _connection, Transaction);
            verify.Parameters.AddWithValue("replacement", _replacement);
            verify.Parameters.AddWithValue("old", _old);
            verify.Parameters.AddWithValue("action", "admin.certificate." + mode);
            await using var reader = await verify.ExecuteReaderAsync(cancellationToken);
            Assert.True(await reader.ReadAsync(cancellationToken));
            Assert.Equal(!success, reader.IsDBNull(1));
            Assert.Equal(success ? 1L : 0L, reader.GetInt64(2));
            Assert.Equal(success ? 1L : 0L, reader.GetInt64(3));
            var expectedOldExpiry = _expiry;
            if (success)
            {
                var registeredAt = reader.GetDateTime(1);
                Assert.True(registeredAt >= releasedAt, "Registration timestamp precedes lock release.");
                if (mode == "rotate") { expectedOldExpiry = registeredAt.AddHours(1); }
            }
            Assert.Equal(expectedOldExpiry, reader.GetDateTime(0));
        }

        public async ValueTask DisposeAsync()
        {
            try
            {
                if (_transaction is not null) { await _transaction.DisposeAsync(); }
                if (_connection.State == ConnectionState.Open)
                {
                    await using var cleanup = new NpgsqlCommand("""
                        DELETE FROM platform.admin_certificate_registrations
                        WHERE certificate_sha256 = @old AND actor_subject_id = @actor
                        """, _connection);
                    cleanup.Parameters.AddWithValue("old", _old);
                    cleanup.Parameters.AddWithValue("actor", $"person:{_person:N}");
                    await cleanup.ExecuteNonQueryAsync(CancellationToken.None);
                }
            }
            finally { await _connection.DisposeAsync(); }
        }
    }
}
