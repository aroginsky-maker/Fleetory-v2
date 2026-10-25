using System.Security.Cryptography;
using Fleetory.CommandSigning;
using Fleetory.Core.Contracts;
using Npgsql;

namespace Fleetory.Persistence.Tests;

[Collection(PostgreSqlTestCollection.Name)]
public sealed class SigningRequestJournalTests(PostgreSqlTestFixture fixture) : IAsyncLifetime
{
    public async Task InitializeAsync()
    {
        await using var source = NpgsqlDataSource.Create(fixture.ConnectionString);
        await using var command = source.CreateCommand(await File.ReadAllTextAsync(
            Path.Combine(AppContext.BaseDirectory, "provision-signing-journal.sql")));
        await command.ExecuteNonQueryAsync();
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task Reservation_and_result_survive_reopening_and_completion_is_idempotent()
    {
        var request = Request();
        var envelope = Envelope(request);
        await using (var source = NpgsqlDataSource.Create(fixture.ConnectionString))
        {
            var journal = new PostgreSqlSigningRequestJournal(source);
            Assert.True(await journal.TryBeginAsync(request));
            await journal.CompleteAsync(request, envelope);
            await journal.CompleteAsync(request, envelope);
        }
        await using var reopened = NpgsqlDataSource.Create(fixture.ConnectionString);
        Assert.False(await new PostgreSqlSigningRequestJournal(reopened).TryBeginAsync(request));
        await using var read = reopened.CreateCommand("""
            SELECT request.caller_id, request.client_certificate_sha256, request.target_device_id,
                request.command_type, request.accepted_at, result.command_id, result.signing_key_id,
                result.envelope_sha256, result.recorded_at
            FROM signer.signing_requests AS request JOIN signer.signing_results AS result USING (request_id)
            WHERE request_id = $1;
            """);
        read.Parameters.AddWithValue(request.RequestId);
        await using var reader = await read.ExecuteReaderAsync();
        Assert.True(await reader.ReadAsync());
        Assert.Equal(request.CallerId, reader.GetString(0));
        Assert.Equal(request.ClientCertificateSha256.ToUpperInvariant(), reader.GetString(1));
        Assert.Equal(request.TargetDeviceId.Value, reader.GetGuid(2));
        Assert.Equal(AgentCommandTypes.InventoryRefresh, reader.GetString(3));
        Assert.Equal(DateTimeKind.Utc, reader.GetDateTime(4).Kind);
        Assert.Equal(envelope.CommandId, reader.GetGuid(5));
        Assert.Equal(envelope.SigningKeyId, reader.GetString(6));
        Assert.Equal(Convert.ToHexString(SHA256.HashData(
            [.. envelope.GetSigningBytes(), .. envelope.Signature.Span])), reader.GetString(7));
        Assert.True(reader.GetDateTime(8) >= reader.GetDateTime(4));
        Assert.False(await reader.ReadAsync());
    }

    [Fact]
    public async Task Concurrent_connections_reserve_a_request_only_once()
    {
        await using var source = NpgsqlDataSource.Create(fixture.ConnectionString);
        var request = Request();
        var results = await Task.WhenAll(Enumerable.Range(0, 16).Select(_ =>
            new PostgreSqlSigningRequestJournal(source).TryBeginAsync(request)));
        Assert.Equal(1, results.Count(accepted => accepted));
        Assert.False(await new PostgreSqlSigningRequestJournal(source).TryBeginAsync(
            request with { CallerId = "other-caller", TargetDeviceId = new DeviceId(Guid.NewGuid()) }));
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("caller")]
    [InlineData("certificate")]
    [InlineData("device")]
    public async Task Completion_must_match_its_durable_reservation(string mismatch)
    {
        await using var source = NpgsqlDataSource.Create(fixture.ConnectionString);
        var journal = new PostgreSqlSigningRequestJournal(source);
        var request = Request();
        Assert.True(await journal.TryBeginAsync(request));
        var changed = mismatch switch
        {
            "missing" => request with { RequestId = Guid.NewGuid() },
            "caller" => request with { CallerId = "other-caller" },
            "certificate" => request with { ClientCertificateSha256 = new string('B', 64) },
            "device" => request with { TargetDeviceId = new DeviceId(Guid.NewGuid()) },
            _ => throw new InvalidOperationException()
        };
        await Assert.ThrowsAsync<InvalidOperationException>(() => journal.CompleteAsync(changed, Envelope(changed)));
        Assert.Equal(0L, await CountResultsAsync(source, request.RequestId));
    }

    [Theory]
    [InlineData("command")]
    [InlineData("signature")]
    [InlineData("key")]
    public async Task Conflicting_result_cannot_replace_the_committed_command(string changed)
    {
        await using var source = NpgsqlDataSource.Create(fixture.ConnectionString);
        var journal = new PostgreSqlSigningRequestJournal(source);
        var request = Request();
        await journal.TryBeginAsync(request);
        var envelope = Envelope(request);
        await journal.CompleteAsync(request, envelope);
        var conflict = new SignedCommandEnvelope(request.TargetDeviceId,
            changed == "command" ? Guid.NewGuid() : envelope.CommandId, envelope.CommandType, [],
            envelope.IssuedAt, envelope.ExpiresAt, envelope.Nonce,
            changed == "key" ? "other-key-v2" : envelope.SigningKeyId,
            changed == "signature" ? Enumerable.Repeat((byte)1, 64).ToArray() : envelope.Signature.Span);
        await Assert.ThrowsAsync<InvalidOperationException>(() => journal.CompleteAsync(request, conflict));
        Assert.Equal(1L, await CountResultsAsync(source, request.RequestId));
    }

    [Fact]
    public async Task A_command_cannot_be_attached_to_a_second_request()
    {
        await using var source = NpgsqlDataSource.Create(fixture.ConnectionString);
        var journal = new PostgreSqlSigningRequestJournal(source);
        var request = Request();
        var second = request with { RequestId = Guid.NewGuid() };
        await journal.TryBeginAsync(request);
        await journal.TryBeginAsync(second);
        var envelope = Envelope(request);
        await journal.CompleteAsync(request, envelope);
        var failure = await Assert.ThrowsAsync<PostgresException>(() => journal.CompleteAsync(second, envelope));
        Assert.Equal(PostgresErrorCodes.UniqueViolation, failure.SqlState);
        Assert.Equal(0L, await CountResultsAsync(source, second.RequestId));
    }

    [Theory]
    [InlineData("request-id")]
    [InlineData("device-id")]
    [InlineData("caller")]
    [InlineData("fingerprint")]
    public async Task Malformed_request_is_rejected_before_inserting(string kind)
    {
        await using var source = NpgsqlDataSource.Create(fixture.ConnectionString);
        var request = Request();
        request = kind switch
        {
            "request-id" => request with { RequestId = Guid.Empty },
            "device-id" => request with { TargetDeviceId = default },
            "caller" => request with { CallerId = "injected\r\ncaller" },
            "fingerprint" => request with { ClientCertificateSha256 = "invalid" },
            _ => throw new InvalidOperationException()
        };
        await Assert.ThrowsAsync<ArgumentException>(() => new PostgreSqlSigningRequestJournal(source).TryBeginAsync(request));
    }

    [Theory]
    [InlineData("device")]
    [InlineData("type")]
    [InlineData("payload")]
    [InlineData("signature")]
    public async Task Invalid_envelope_never_completes_a_request(string kind)
    {
        await using var source = NpgsqlDataSource.Create(fixture.ConnectionString);
        var request = Request();
        var journal = new PostgreSqlSigningRequestJournal(source);
        await journal.TryBeginAsync(request);
        var envelope = new SignedCommandEnvelope(
            kind == "device" ? new DeviceId(Guid.NewGuid()) : request.TargetDeviceId,
            Guid.NewGuid(), kind == "type" ? "Fleet.Bulk.Reboot" : AgentCommandTypes.InventoryRefresh,
            kind == "payload" ? [1] : [], DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(1),
            "test-nonce", "test-key-v2", kind == "signature" ? [] : new byte[64]);
        await Assert.ThrowsAsync<ArgumentException>(() => journal.CompleteAsync(request, envelope));
        Assert.Equal(0L, await CountResultsAsync(source, request.RequestId));
    }

    [Fact]
    public async Task Narrow_runtime_role_can_append_but_cannot_change_or_delete_audit_rows()
    {
        await using var owner = NpgsqlDataSource.Create(fixture.ConnectionString);
        var role = "signer_test_" + Guid.NewGuid().ToString("N");
        await using var setup = owner.CreateCommand($"""
            CREATE ROLE {role} NOLOGIN;
            GRANT USAGE ON SCHEMA signer TO {role};
            GRANT SELECT, INSERT ON signer.signing_requests, signer.signing_results TO {role};
            """);
        await setup.ExecuteNonQueryAsync();
        try
        {
            var configuration = new NpgsqlConnectionStringBuilder(fixture.ConnectionString)
            {
                Options = $"-c role={role} -c synchronous_commit=off", Pooling = false
            };
            await using var runtime = NpgsqlDataSource.Create(configuration.ConnectionString);
            var journal = new PostgreSqlSigningRequestJournal(runtime);
            var request = Request();
            Assert.True(await journal.TryBeginAsync(request));
            await journal.CompleteAsync(request, Envelope(request));
            foreach (var sql in new[]
            {
                "UPDATE signer.signing_requests SET caller_id = 'changed'",
                "DELETE FROM signer.signing_results",
                "TRUNCATE signer.signing_requests CASCADE"
            })
            {
                await using var forbidden = runtime.CreateCommand(sql);
                var error = await Assert.ThrowsAsync<PostgresException>(() => forbidden.ExecuteNonQueryAsync());
                Assert.Equal(PostgresErrorCodes.InsufficientPrivilege, error.SqlState);
            }
            await using var revoke = owner.CreateCommand($"REVOKE INSERT ON signer.signing_results FROM {role}");
            await revoke.ExecuteNonQueryAsync();
            var unfinished = Request();
            Assert.True(await journal.TryBeginAsync(unfinished));
            await Assert.ThrowsAsync<PostgresException>(() => journal.CompleteAsync(unfinished, Envelope(unfinished)));
            Assert.False(await journal.TryBeginAsync(unfinished));
            Assert.Equal(0L, await CountResultsAsync(owner, unfinished.RequestId));
        }
        finally
        {
            await using var cleanup = owner.CreateCommand($"DROP OWNED BY {role}; DROP ROLE {role};");
            await cleanup.ExecuteNonQueryAsync();
        }
    }

    [Fact]
    public async Task Both_inserts_require_durable_commit_even_when_the_session_default_is_off()
    {
        await using var owner = NpgsqlDataSource.Create(fixture.ConnectionString);
        var function = "require_sync_" + Guid.NewGuid().ToString("N");
        await using var setup = owner.CreateCommand($"""
            CREATE FUNCTION signer.{function}() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
                IF current_setting('synchronous_commit') <> 'on' THEN
                    RAISE EXCEPTION 'Signer journal requires synchronous commit';
                END IF;
                RETURN NEW;
            END;
            $$;
            CREATE TRIGGER {function} BEFORE INSERT ON signer.signing_requests
                FOR EACH ROW EXECUTE FUNCTION signer.{function}();
            CREATE TRIGGER {function} BEFORE INSERT ON signer.signing_results
                FOR EACH ROW EXECUTE FUNCTION signer.{function}();
            """);
        await setup.ExecuteNonQueryAsync();
        try
        {
            var settings = new NpgsqlConnectionStringBuilder(fixture.ConnectionString)
            {
                Options = "-c synchronous_commit=off"
            };
            await using var source = NpgsqlDataSource.Create(settings.ConnectionString);
            await using var session = source.CreateCommand("SHOW synchronous_commit");
            Assert.Equal("off", await session.ExecuteScalarAsync());
            var journal = new PostgreSqlSigningRequestJournal(source);
            var request = Request();
            Assert.True(await journal.TryBeginAsync(request));
            await journal.CompleteAsync(request, Envelope(request));
            Assert.Equal(1L, await CountResultsAsync(owner, request.RequestId));
        }
        finally
        {
            await using var cleanup = owner.CreateCommand($"DROP FUNCTION signer.{function}() CASCADE");
            await cleanup.ExecuteNonQueryAsync();
        }
    }

    private static SigningRequest Request() =>
        new(Guid.NewGuid(), "approval-service", new string('a', 64), new DeviceId(Guid.NewGuid()));

    private static SignedCommandEnvelope Envelope(SigningRequest request) =>
        new(request.TargetDeviceId, Guid.NewGuid(), AgentCommandTypes.InventoryRefresh, [],
            DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(1), "test-nonce", "test-key-v2", new byte[64]);

    private static async Task<long> CountResultsAsync(NpgsqlDataSource source, Guid requestId)
    {
        await using var command = source.CreateCommand("SELECT count(*) FROM signer.signing_results WHERE request_id = $1");
        command.Parameters.AddWithValue(requestId);
        return (long)(await command.ExecuteScalarAsync())!;
    }
}
