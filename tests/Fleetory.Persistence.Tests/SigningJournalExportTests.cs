using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using DotNet.Testcontainers.Configurations;
using Npgsql;
using Testcontainers.PostgreSql;

namespace Fleetory.Persistence.Tests;

[Collection(PostgreSqlTestCollection.Name)]
public sealed class SigningJournalExportTests(PostgreSqlTestFixture fixture) : IAsyncLifetime
{
    private readonly string _role = "signer_export_" + Guid.NewGuid().ToString("N");
    private readonly string _password = Guid.NewGuid().ToString("N");
    private string _script = "";

    public async Task InitializeAsync()
    {
        _script = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "export-signing-journal.sql"));
        await OwnerAsync("DROP SCHEMA IF EXISTS signer CASCADE");
        await OwnerAsync(await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "provision-signing-journal.sql")));
        await OwnerAsync($"""
            CREATE ROLE {_role} LOGIN PASSWORD '{_password}';
            GRANT CONNECT ON DATABASE {new NpgsqlConnectionStringBuilder(fixture.ConnectionString).Database} TO {_role};
            GRANT USAGE ON SCHEMA signer TO {_role};
            GRANT SELECT ON ALL TABLES IN SCHEMA signer TO {_role};
            """);
    }

    public Task DisposeAsync() => OwnerAsync($"DROP OWNED BY {_role}; DROP ROLE {_role};");

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Snapshot_is_complete_read_only_and_explicitly_excludes_delivery_and_custody_claims(bool populated)
    {
        if (populated) { await SeedAsync(2); }
        using var snapshot = JsonDocument.Parse(await ExportAsync());
        var data = snapshot.RootElement;
        Assert.Equal("fleetory.signer-journal-snapshot.v1", data.GetProperty("schema").GetString());
        Assert.Equal(_role, data.GetProperty("databaseOperator").GetString());
        Assert.Equal(new NpgsqlConnectionStringBuilder(fixture.ConnectionString).Database, data.GetProperty("database").GetString());
        Assert.True(data.GetProperty("readOnly").GetBoolean());
        Assert.True(data.GetProperty("snapshotComplete").GetBoolean());
        Assert.False(data.GetProperty("deliveryVerified").GetBoolean());
        Assert.False(data.GetProperty("executionVerified").GetBoolean());
        Assert.False(data.GetProperty("independentCustodyVerified").GetBoolean());
        Assert.Equal(TimeSpan.Zero, data.GetProperty("observedAt").GetDateTimeOffset().Offset);
        foreach (var name in new[] { "requests", "results", "rejections", "revocations" })
        {
            Assert.Equal(populated ? 2 : 0, data.GetProperty(name).GetArrayLength());
        }
        if (populated)
        {
            var requests = data.GetProperty("requests").EnumerateArray().ToArray();
            var result = data.GetProperty("results")[0];
            Assert.Equal(requests[0].GetProperty("request_id").GetGuid(), result.GetProperty("request_id").GetGuid());
            Assert.Equal("Inventory.Refresh", requests[0].GetProperty("command_type").GetString());
            Assert.Equal(new string('A', 64), result.GetProperty("envelope_sha256").GetString());
            Assert.Equal("Unavailable", data.GetProperty("rejections")[0].GetProperty("reason").GetString());
            Assert.Equal(new string('i', 128), data.GetProperty("revocations")[0].GetProperty("incident_reference").GetString());
            Assert.NotEqual(Guid.Empty, data.GetProperty("revocations")[0].GetProperty("event_id").GetGuid());
        }
        Assert.DoesNotContain(_password, data.GetRawText());
        Assert.DoesNotContain("PRIVATE KEY", data.GetRawText());
        using var repeated = JsonDocument.Parse(await ExportAsync());
        foreach (var name in new[] { "requests", "results", "rejections", "revocations" })
        {
            Assert.Equal(data.GetProperty(name).GetRawText(), repeated.RootElement.GetProperty(name).GetRawText());
        }
    }

    [Fact]
    public async Task A_later_observation_sees_later_rows_without_modifying_the_journal()
    {
        using var empty = JsonDocument.Parse(await ExportAsync());
        Assert.Equal(0, empty.RootElement.GetProperty("requests").GetArrayLength());
        await SeedAsync(1);
        using var populated = JsonDocument.Parse(await ExportAsync());
        Assert.Equal(1, populated.RootElement.GetProperty("requests").GetArrayLength());
    }

    [Fact]
    public async Task Columns_added_later_are_not_automatically_exported()
    {
        await SeedAsync(1);
        await OwnerAsync("ALTER TABLE signer.signing_requests ADD COLUMN future_secret text DEFAULT 'private-export-sentinel'");
        var json = await ExportAsync();
        Assert.DoesNotContain("future_secret", json);
        Assert.DoesNotContain("private-export-sentinel", json);
    }

    [Fact]
    public async Task Concurrent_commits_cannot_change_the_snapshot_after_its_row_limit_check()
    {
        var key = BitConverter.ToInt64(Guid.NewGuid().ToByteArray());
        await using var owner = NpgsqlDataSource.Create(fixture.ConnectionString);
        await using var held = await owner.OpenConnectionAsync();
        await using var acquire = new NpgsqlCommand("SELECT pg_advisory_lock($1)", held);
        acquire.Parameters.AddWithValue(key);
        await acquire.ExecuteNonQueryAsync();
        _script = _script.Replace("payload := jsonb_build_object(",
            $"PERFORM pg_advisory_xact_lock({key});\n    payload := jsonb_build_object(", StringComparison.Ordinal);
        var exporting = ExportAsync();
        await using var waiting = owner.CreateCommand("SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE usename = $1 AND wait_event = 'advisory')");
        waiting.Parameters.AddWithValue(_role);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        while (await waiting.ExecuteScalarAsync(deadline.Token) is not true) { await Task.Delay(10, deadline.Token); }
        await SeedAsync(1);
        await using var release = new NpgsqlCommand("SELECT pg_advisory_unlock($1)", held);
        release.Parameters.AddWithValue(key);
        await release.ExecuteNonQueryAsync();
        using var snapshot = JsonDocument.Parse(await exporting);
        Assert.Equal(0, snapshot.RootElement.GetProperty("requests").GetArrayLength());
        using var later = JsonDocument.Parse(await ExportAsync());
        Assert.Equal(1, later.RootElement.GetProperty("requests").GetArrayLength());
    }

    [Fact]
    public async Task Export_cannot_commit_a_preexisting_write_transaction()
    {
        await Assert.ThrowsAsync<PostgresException>(() => ExportAsync(joinWriteTransaction: true));
        using var after = JsonDocument.Parse(await ExportAsync());
        Assert.Equal(0, after.RootElement.GetProperty("requests").GetArrayLength());
    }

    [Theory]
    [InlineData("signing_requests")]
    [InlineData("signing_results")]
    [InlineData("signing_rejections")]
    [InlineData("client_certificate_revocations")]
    public async Task Missing_read_rights_fail_instead_of_returning_an_incomplete_snapshot(string table)
    {
        await OwnerAsync($"REVOKE SELECT ON signer.{table} FROM {_role}");
        var error = await Assert.ThrowsAsync<PostgresException>(() => ExportAsync());
        Assert.Equal(PostgresErrorCodes.InsufficientPrivilege, error.SqlState);
    }

    [Theory]
    [InlineData("INSERT INTO signer.signing_requests DEFAULT VALUES")]
    [InlineData("UPDATE signer.signing_results SET signing_key_id = 'changed'")]
    [InlineData("DELETE FROM signer.signing_rejections")]
    [InlineData("TRUNCATE signer.client_certificate_revocations")]
    public async Task Export_login_cannot_change_journal_data(string sql)
    {
        await using var source = ReaderSource();
        await using var command = source.CreateCommand(sql);
        var error = await Assert.ThrowsAsync<PostgresException>(() => command.ExecuteNonQueryAsync());
        Assert.Equal(PostgresErrorCodes.InsufficientPrivilege, error.SqlState);
    }

    [Fact]
    public async Task A_row_limit_failure_returns_no_truncated_snapshot()
    {
        await OwnerAsync("""
            INSERT INTO signer.signing_rejections (event_id, client_certificate_sha256, reason)
            SELECT gen_random_uuid(), repeat('A', 64), 'Unavailable' FROM generate_series(1, 5001);
            """);
        var error = await Assert.ThrowsAsync<PostgresException>(() => ExportAsync());
        Assert.Equal(PostgresErrorCodes.RaiseException, error.SqlState);
        Assert.Contains("5000-row", error.MessageText);
    }

    [Fact]
    public async Task An_oversized_but_row_bounded_snapshot_is_rejected_before_output()
    {
        await SeedAsync(5000);
        var error = await Assert.ThrowsAsync<PostgresException>(() => ExportAsync());
        Assert.Equal(PostgresErrorCodes.RaiseException, error.SqlState);
        Assert.Contains("8 MiB", error.MessageText);
    }

    [Fact]
    public async Task Role_switching_is_refused()
    {
        var error = await Assert.ThrowsAsync<PostgresException>(() => ExportAsync(switchedRole: true));
        Assert.Equal(PostgresErrorCodes.RaiseException, error.SqlState);
    }

    [Fact]
    public async Task A_blocked_table_fails_within_the_lock_deadline()
    {
        await using var owner = NpgsqlDataSource.Create(fixture.ConnectionString);
        await using var connection = await owner.OpenConnectionAsync();
        await using var transaction = await connection.BeginTransactionAsync();
        await using var locked = new NpgsqlCommand("LOCK TABLE signer.signing_results IN ACCESS EXCLUSIVE MODE", connection, transaction);
        await locked.ExecuteNonQueryAsync();
        var elapsed = Stopwatch.StartNew();
        var error = await Assert.ThrowsAsync<PostgresException>(() => ExportAsync());
        Assert.Equal(PostgresErrorCodes.LockNotAvailable, error.SqlState);
        Assert.True(elapsed.Elapsed < TimeSpan.FromSeconds(10));
    }

    [Theory]
    [InlineData("LATIN1")]
    [InlineData("WIN1251")]
    public async Task Native_psql_emits_one_utf8_json_observation_despite_a_legacy_client_encoding(string initialEncoding)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(1));
        await using var database = new PostgreSqlBuilder(PostgreSqlTestFixture.PostgreSqlImage)
            .WithDatabase("signer_encoding_test").WithUsername("encoding_owner").WithPassword(Guid.NewGuid().ToString("N"))
            .WithEnvironment("PGCLIENTENCODING", initialEncoding)
            .WithResourceMapping(await File.ReadAllBytesAsync(Path.Combine(AppContext.BaseDirectory, "export-signing-journal.sql"), deadline.Token),
                "/proof/export-signing-journal.sql", 999, 999, UnixFileModes.UserRead)
            .Build();
        await database.StartAsync(deadline.Token);
        await using var owner = NpgsqlDataSource.Create(database.GetConnectionString());
        await using (var schema = owner.CreateCommand(await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "provision-signing-journal.sql"))))
        {
            await schema.ExecuteNonQueryAsync(deadline.Token);
        }
        await using (var provision = owner.CreateCommand("""
            CREATE ROLE evidence_reader LOGIN;
            GRANT CONNECT ON DATABASE signer_encoding_test TO evidence_reader;
            GRANT USAGE ON SCHEMA signer TO evidence_reader;
            GRANT SELECT ON ALL TABLES IN SCHEMA signer TO evidence_reader;
            """))
        {
            await provision.ExecuteNonQueryAsync(deadline.Token);
        }
        await using (var incident = owner.CreateCommand("""
            INSERT INTO signer.client_certificate_revocations
                (certificate_sha256, incident_reference, operator_reference, approver_reference, evidence_sha256)
            VALUES (repeat('A', 64), $1, 'operator', 'approver', repeat('B', 64));
            """))
        {
            incident.Parameters.AddWithValue("ИНЦИДЕНТ-漢字-é");
            await incident.ExecuteNonQueryAsync(deadline.Token);
        }
        // Local socket trust belongs only to this disposable test container, not to the production service profile.
        var export = await database.ExecAsync(["psql", "-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1",
            "--no-password", "--username=evidence_reader", "--dbname=signer_encoding_test", "--file=/proof/export-signing-journal.sql"], deadline.Token);
        Assert.True(export.ExitCode == 0, export.Stderr);
        using var snapshot = JsonDocument.Parse(export.Stdout);
        Assert.Equal("fleetory.signer-journal-snapshot.v1", snapshot.RootElement.GetProperty("schema").GetString());
        Assert.Equal("evidence_reader", snapshot.RootElement.GetProperty("databaseOperator").GetString());
        Assert.Equal("ИНЦИДЕНТ-漢字-é", snapshot.RootElement.GetProperty("revocations")[0].GetProperty("incident_reference").GetString());
        Assert.False(snapshot.RootElement.GetProperty("independentCustodyVerified").GetBoolean());
        await VerifyRetainedSnapshotAsync(export.Stdout, deadline.Token);
    }

    private static async Task VerifyRetainedSnapshotAsync(string json, CancellationToken cancellationToken)
    {
        var path = Path.Combine(Path.GetTempPath(), "fleetory-signer-evidence-" + Guid.NewGuid().ToString("N") + ".json");
        var bytes = Encoding.UTF8.GetBytes(json);
        var digest = Convert.ToHexString(SHA256.HashData(bytes));
        try
        {
            await using (var output = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                await output.WriteAsync(bytes, cancellationToken);
            }
            var start = new ProcessStartInfo("pwsh")
            {
                UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true
            };
            foreach (var argument in new[] { "-NoProfile", "-File", Path.Combine(AppContext.BaseDirectory, "verify-signing-journal-snapshot.ps1"),
                "-SnapshotPath", path, "-ExpectedSha256", digest }) { start.ArgumentList.Add(argument); }
            using var process = Process.Start(start)!;
            var stdout = process.StandardOutput.ReadToEndAsync(cancellationToken);
            var stderr = process.StandardError.ReadToEndAsync(cancellationToken);
            try { await process.WaitForExitAsync(cancellationToken); }
            catch (OperationCanceledException) { process.Kill(entireProcessTree: true); throw; }
            Assert.True(process.ExitCode == 0, await stderr);
            using var verification = JsonDocument.Parse(await stdout);
            Assert.Equal(digest, verification.RootElement.GetProperty("snapshotSha256").GetString());
            Assert.True(verification.RootElement.GetProperty("approvedDigestMatched").GetBoolean());
            Assert.Equal(1, verification.RootElement.GetProperty("rowCounts").GetProperty("revocations").GetInt32());
            Assert.False(verification.RootElement.GetProperty("independentCustodyVerified").GetBoolean());
            Assert.Equal(bytes, await File.ReadAllBytesAsync(path, cancellationToken));
        }
        finally { File.Delete(path); }
    }

    private async Task<string> ExportAsync(bool switchedRole = false, bool joinWriteTransaction = false)
    {
        await using var source = switchedRole || joinWriteTransaction ? NpgsqlDataSource.Create(fixture.ConnectionString) : ReaderSource();
        await using var connection = await source.OpenConnectionAsync();
        if (switchedRole)
        {
            await using var change = new NpgsqlCommand($"SET ROLE {_role}", connection);
            await change.ExecuteNonQueryAsync();
        }
        await using var transaction = joinWriteTransaction ? await connection.BeginTransactionAsync() : null;
        if (transaction is not null)
        {
            await using var pending = new NpgsqlCommand("""
                INSERT INTO signer.signing_requests (request_id, caller_id, client_certificate_sha256, target_device_id)
                VALUES (gen_random_uuid(), 'preexisting-write', repeat('A', 64), gen_random_uuid());
                """, connection, transaction);
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

    private async Task SeedAsync(int count) => await OwnerAsync($"""
        INSERT INTO signer.signing_requests (request_id, caller_id, client_certificate_sha256, target_device_id)
        SELECT gen_random_uuid(), repeat('c', 96), repeat('A', 64), gen_random_uuid() FROM generate_series(1, {count});
        INSERT INTO signer.signing_results (request_id, command_id, signing_key_id, envelope_sha256)
        SELECT request_id, gen_random_uuid(), repeat('k', 128), repeat('A', 64) FROM signer.signing_requests;
        INSERT INTO signer.signing_rejections (event_id, client_certificate_sha256, reason, request_id, target_device_id)
        SELECT gen_random_uuid(), repeat('A', 64), 'Unavailable', request_id, target_device_id FROM signer.signing_requests;
        INSERT INTO signer.client_certificate_revocations (certificate_sha256, incident_reference, operator_reference, approver_reference, evidence_sha256)
        SELECT upper(repeat(md5(i::text), 2)), repeat('i', 128), repeat('o', 128), repeat('a', 128), repeat('A', 64)
        FROM generate_series(1, {count}) AS i;
        """);

    private NpgsqlDataSource ReaderSource() => NpgsqlDataSource.Create(
        new NpgsqlConnectionStringBuilder(fixture.ConnectionString)
        {
            Username = _role, Password = _password, Pooling = false, Timeout = 5, CommandTimeout = 15
        }.ConnectionString);

    private async Task OwnerAsync(string sql)
    {
        await using var source = NpgsqlDataSource.Create(fixture.ConnectionString);
        await using var command = source.CreateCommand(sql);
        await command.ExecuteNonQueryAsync();
    }
}
