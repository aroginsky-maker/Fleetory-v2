using System.Security.Cryptography;
using System.Text.Json;
using Fleetory.CommandSigning;
using Fleetory.Core.Contracts;
using Npgsql;

namespace Fleetory.Persistence.Tests;

[Collection(PostgreSqlTestCollection.Name)]
public sealed class SigningRequestReconciliationTests(PostgreSqlTestFixture fixture) : IAsyncLifetime
{
    private readonly string _readerRole = "signer_reader_" + Guid.NewGuid().ToString("N");
    private readonly string _password = Guid.NewGuid().ToString("N");
    private string _script = "";

    public async Task InitializeAsync()
    {
        _script = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "reconcile-signing-request.sql"));
        await ExecuteOwnerAsync(await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "provision-signing-journal.sql")));
        await ExecuteOwnerAsync($"""
            CREATE ROLE {_readerRole} LOGIN PASSWORD '{_password}';
            GRANT CONNECT ON DATABASE {new NpgsqlConnectionStringBuilder(fixture.ConnectionString).Database} TO {_readerRole};
            GRANT USAGE ON SCHEMA signer TO {_readerRole};
            GRANT SELECT ON signer.signing_requests, signer.signing_results TO {_readerRole};
            """);
    }

    public Task DisposeAsync() => ExecuteOwnerAsync($"DROP OWNED BY {_readerRole}; DROP ROLE {_readerRole};");

    [Theory]
    [InlineData("NotFound")]
    [InlineData("Pending")]
    [InlineData("SigningRecorded")]
    public async Task Inspection_returns_one_consistent_read_only_observation_without_authorizing_retry(string state)
    {
        var request = Request();
        var envelope = Envelope(request);
        await using var owner = NpgsqlDataSource.Create(fixture.ConnectionString);
        var journal = new PostgreSqlSigningRequestJournal(owner);
        if (state != "NotFound") { Assert.True(await journal.TryBeginAsync(request)); }
        if (state == "SigningRecorded") { await journal.CompleteAsync(request, envelope); }
        var before = await CountsAsync(request.RequestId);
        using var observation = JsonDocument.Parse(await InspectAsync(request.RequestId.ToString()));
        var data = observation.RootElement;
        Assert.Equal("fleetory.signing-reconciliation.v1", data.GetProperty("schema").GetString());
        Assert.Equal(request.RequestId, data.GetProperty("requestId").GetGuid());
        Assert.Equal(state, data.GetProperty("status").GetString());
        Assert.Equal(_readerRole, data.GetProperty("databaseOperator").GetString());
        Assert.Equal(new NpgsqlConnectionStringBuilder(fixture.ConnectionString).Database, data.GetProperty("database").GetString());
        Assert.True(data.GetProperty("readOnly").GetBoolean());
        foreach (var flag in new[] { "automaticRetryAllowed", "deliveryVerified", "executionVerified" })
        {
            Assert.False(data.GetProperty(flag).GetBoolean());
        }
        Assert.Equal(TimeSpan.Zero, data.GetProperty("observedAt").GetDateTimeOffset().Offset);
        if (state == "NotFound")
        {
            Assert.Equal(JsonValueKind.Null, data.GetProperty("request").ValueKind);
        }
        else
        {
            var attempt = data.GetProperty("request");
            Assert.Equal(request.CallerId, attempt.GetProperty("callerId").GetString());
            Assert.Equal(request.ClientCertificateSha256.ToUpperInvariant(), attempt.GetProperty("clientCertificateSha256").GetString());
            Assert.Equal(request.TargetDeviceId.Value, attempt.GetProperty("deviceId").GetGuid());
            Assert.Equal(AgentCommandTypes.InventoryRefresh, attempt.GetProperty("commandType").GetString());
            Assert.True(attempt.GetProperty("acceptedAt").GetDateTimeOffset() <= DateTimeOffset.UtcNow);
        }
        if (state == "SigningRecorded")
        {
            var result = data.GetProperty("result");
            Assert.Equal(envelope.CommandId, result.GetProperty("commandId").GetGuid());
            Assert.Equal(envelope.SigningKeyId, result.GetProperty("signingKeyId").GetString());
            Assert.Equal(Convert.ToHexString(SHA256.HashData([.. envelope.GetSigningBytes(), .. envelope.Signature.Span])),
                result.GetProperty("envelopeSha256").GetString());
            Assert.True(result.GetProperty("recordedAt").GetDateTimeOffset() <= DateTimeOffset.UtcNow);
            Assert.False(result.TryGetProperty("signature", out _));
        }
        else { Assert.Equal(JsonValueKind.Null, data.GetProperty("result").ValueKind); }
        Assert.Equal(before, await CountsAsync(request.RequestId));
        using var repeated = JsonDocument.Parse(await InspectAsync(request.RequestId.ToString().ToUpperInvariant()));
        Assert.Equal(state, repeated.RootElement.GetProperty("status").GetString());
        Assert.Equal(before, await CountsAsync(request.RequestId));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("00000000-0000-0000-0000-000000000000")]
    [InlineData("invalid-private-sentinel")]
    [InlineData("00000000000000000000000000000001")]
    [InlineData("'; DROP SCHEMA signer CASCADE; --")]
    public async Task Invalid_input_is_rejected_without_echo_or_journal_changes(string? requestId)
    {
        var error = await Assert.ThrowsAsync<PostgresException>(() => InspectAsync(requestId));
        Assert.Equal(PostgresErrorCodes.RaiseException, error.SqlState);
        Assert.DoesNotContain("private-sentinel", error.ToString());
        Assert.Equal((0L, 0L), await CountsAsync(Guid.NewGuid()));
    }

    [Fact]
    public async Task A_new_observation_sees_a_later_completion_without_changing_the_request()
    {
        var request = Request();
        await using var owner = NpgsqlDataSource.Create(fixture.ConnectionString);
        var journal = new PostgreSqlSigningRequestJournal(owner);
        Assert.True(await journal.TryBeginAsync(request));
        using var pending = JsonDocument.Parse(await InspectAsync(request.RequestId.ToString()));
        Assert.Equal("Pending", pending.RootElement.GetProperty("status").GetString());
        await journal.CompleteAsync(request, Envelope(request));
        using var completed = JsonDocument.Parse(await InspectAsync(request.RequestId.ToString()));
        Assert.Equal("SigningRecorded", completed.RootElement.GetProperty("status").GetString());
        Assert.Equal(pending.RootElement.GetProperty("request").GetRawText(), completed.RootElement.GetProperty("request").GetRawText());
        Assert.Equal((1L, 1L), await CountsAsync(request.RequestId));
    }

    [Fact]
    public async Task Inspection_cannot_commit_writes_from_an_existing_transaction()
    {
        var requestId = Guid.NewGuid();
        var error = await Assert.ThrowsAsync<PostgresException>(() => InspectAsync(requestId.ToString(), joinWriteTransaction: true));
        Assert.Equal(PostgresErrorCodes.RaiseException, error.SqlState);
        Assert.Contains("read-only transaction", error.MessageText);
        Assert.Equal((0L, 0L), await CountsAsync(requestId));
    }

    [Fact]
    public async Task Inspection_refuses_role_switched_credentials()
    {
        var error = await Assert.ThrowsAsync<PostgresException>(() => InspectAsync(Guid.NewGuid().ToString(), switchedRole: true));
        Assert.Equal(PostgresErrorCodes.RaiseException, error.SqlState);
    }

    [Theory]
    [InlineData("signing_requests")]
    [InlineData("signing_results")]
    public async Task Missing_read_permissions_fail_instead_of_reporting_not_found(string table)
    {
        await ExecuteOwnerAsync($"REVOKE SELECT ON signer.{table} FROM {_readerRole}");
        var error = await Assert.ThrowsAsync<PostgresException>(() => InspectAsync(Guid.NewGuid().ToString()));
        Assert.Equal(PostgresErrorCodes.InsufficientPrivilege, error.SqlState);
    }

    [Theory]
    [InlineData("INSERT INTO signer.signing_requests DEFAULT VALUES")]
    [InlineData("UPDATE signer.signing_requests SET caller_id = 'changed'")]
    [InlineData("DELETE FROM signer.signing_results")]
    [InlineData("TRUNCATE signer.signing_results")]
    public async Task Reader_credentials_cannot_mutate_the_journal(string sql)
    {
        await using var reader = ReaderSource();
        await using var command = reader.CreateCommand(sql);
        var error = await Assert.ThrowsAsync<PostgresException>(() => command.ExecuteNonQueryAsync());
        Assert.Equal(PostgresErrorCodes.InsufficientPrivilege, error.SqlState);
    }

    [Fact]
    public async Task A_blocked_read_has_a_bounded_lock_deadline_and_can_be_retried_as_an_observation()
    {
        await using var owner = NpgsqlDataSource.Create(fixture.ConnectionString);
        await using var connection = await owner.OpenConnectionAsync();
        await using (var transaction = await connection.BeginTransactionAsync())
        {
            await using var locked = new NpgsqlCommand("LOCK TABLE signer.signing_requests IN ACCESS EXCLUSIVE MODE", connection, transaction);
            await locked.ExecuteNonQueryAsync();
            var error = await Assert.ThrowsAsync<PostgresException>(() => InspectAsync(Guid.NewGuid().ToString()));
            Assert.Equal(PostgresErrorCodes.LockNotAvailable, error.SqlState);
        }
        using var observation = JsonDocument.Parse(await InspectAsync(Guid.NewGuid().ToString()));
        Assert.Equal("NotFound", observation.RootElement.GetProperty("status").GetString());
    }

    private async Task<string> InspectAsync(string? requestId, bool joinWriteTransaction = false, bool switchedRole = false)
    {
        await using var source = joinWriteTransaction || switchedRole ? NpgsqlDataSource.Create(fixture.ConnectionString) : ReaderSource();
        await using var connection = await source.OpenConnectionAsync();
        if (switchedRole)
        {
            await using var role = new NpgsqlCommand($"SET ROLE {_readerRole}", connection);
            await role.ExecuteNonQueryAsync();
        }
        if (requestId is not null)
        {
            await using var setting = new NpgsqlCommand("SELECT set_config('fleetory.signer_reconcile.request_id', $1, false)", connection);
            setting.Parameters.AddWithValue(requestId);
            await setting.ExecuteNonQueryAsync();
        }
        await using var transaction = joinWriteTransaction ? await connection.BeginTransactionAsync() : null;
        if (transaction is not null)
        {
            await using var pending = new NpgsqlCommand("""
                INSERT INTO signer.signing_requests
                    (request_id, caller_id, client_certificate_sha256, target_device_id)
                VALUES ($1, 'preexisting-write', $2, $3);
                """, connection, transaction);
            pending.Parameters.AddWithValue(Guid.Parse(requestId!));
            pending.Parameters.AddWithValue(new string('A', 64));
            pending.Parameters.AddWithValue(Guid.NewGuid());
            await pending.ExecuteNonQueryAsync();
        }
        await using var command = new NpgsqlCommand(_script, connection, transaction);
        await using var reader = await command.ExecuteReaderAsync();
        while (reader.FieldCount == 0 && await reader.NextResultAsync()) { }
        Assert.True(await reader.ReadAsync());
        var json = reader.GetString(0);
        Assert.False(await reader.ReadAsync());
        while (await reader.NextResultAsync()) { Assert.False(await reader.ReadAsync()); }
        return json;
    }

    private NpgsqlDataSource ReaderSource() => NpgsqlDataSource.Create(
        new NpgsqlConnectionStringBuilder(fixture.ConnectionString)
        {
            Username = _readerRole, Password = _password, Pooling = false, Timeout = 5, CommandTimeout = 15
        }.ConnectionString);

    private async Task ExecuteOwnerAsync(string sql)
    {
        await using var source = NpgsqlDataSource.Create(fixture.ConnectionString);
        await using var command = source.CreateCommand(sql);
        await command.ExecuteNonQueryAsync();
    }

    private async Task<(long Requests, long Results)> CountsAsync(Guid requestId)
    {
        await using var source = NpgsqlDataSource.Create(fixture.ConnectionString);
        await using var command = source.CreateCommand("""
            SELECT (SELECT count(*) FROM signer.signing_requests WHERE request_id = $1),
                   (SELECT count(*) FROM signer.signing_results WHERE request_id = $1);
            """);
        command.Parameters.AddWithValue(requestId);
        await using var reader = await command.ExecuteReaderAsync();
        Assert.True(await reader.ReadAsync());
        return (reader.GetInt64(0), reader.GetInt64(1));
    }

    private static SigningRequest Request() => new(Guid.NewGuid(), "approval-service", new string('a', 64), new DeviceId(Guid.NewGuid()));

    private static SignedCommandEnvelope Envelope(SigningRequest request) => new(request.TargetDeviceId,
        Guid.NewGuid(), AgentCommandTypes.InventoryRefresh, [], DateTimeOffset.UtcNow,
        DateTimeOffset.UtcNow.AddMinutes(1), "inspection-test", "test-key-v2", new byte[64]);
}
