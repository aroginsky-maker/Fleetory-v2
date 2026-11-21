using Fleetory.Agent.Security;
using Fleetory.Core.Contracts;
using Microsoft.Data.Sqlite;

namespace Fleetory.Core.Tests;

public sealed class AgentReplaySchemaTests
{
    private static readonly DeviceId Device = new(Guid.Parse("dd6d68ac-3f4f-4efc-ad41-ccf48dc2c28d"));
    private static readonly DateTimeOffset Expires = new(2026, 11, 1, 0, 0, 0, TimeSpan.Zero);

    [Theory]
    [InlineData("none")]
    [InlineData("command")]
    [InlineData("nonce")]
    [InlineData("partial")]
    public async Task Missing_or_partial_uniqueness_fails_before_writing(string schema)
    {
        using var fixture = new ReplayFixture(schema);
        var before = fixture.Snapshot();

        var error = await Assert.ThrowsAsync<SqliteException>(async () =>
            await fixture.Store.TryConsumeAsync(Device, Guid.NewGuid(), "schema-test-nonce-1", Expires));

        Assert.Equal(1, error.SqliteErrorCode);
        Assert.Equal(before, fixture.Snapshot());
    }

    [Fact]
    public async Task A_constraint_removed_after_construction_is_rechecked_without_resetting_history()
    {
        using var fixture = new ReplayFixture("indexed");
        var id = Guid.NewGuid();
        Assert.True(await fixture.Store.TryConsumeAsync(Device, id, "retained-nonce-1", Expires));
        fixture.Execute("DROP INDEX replay_nonce;");
        var before = fixture.Snapshot();

        await Assert.ThrowsAsync<SqliteException>(async () =>
            await fixture.Store.TryConsumeAsync(Device, Guid.NewGuid(), "fresh-nonce-123456", Expires));
        Assert.Equal(before, fixture.Snapshot());
        await Assert.ThrowsAsync<SqliteException>(async () =>
            await fixture.RecreateStore().TryConsumeAsync(Device, Guid.NewGuid(), "fresh-nonce-123456", Expires));
        Assert.Equal(before, fixture.Snapshot());

        fixture.Execute("CREATE UNIQUE INDEX replay_nonce ON consumed_commands(device_id, nonce);");
        Assert.False(await fixture.Store.TryConsumeAsync(Device, Guid.NewGuid(), "retained-nonce-1", Expires));
        Assert.True(await fixture.Store.TryConsumeAsync(Device, Guid.NewGuid(), "fresh-nonce-123456", Expires));
    }

    [Theory]
    [InlineData("delete")]
    [InlineData("rewrite")]
    [InlineData("suppress")]
    public async Task A_trigger_added_after_construction_cannot_change_history(string action)
    {
        using var fixture = new ReplayFixture("canonical");
        var id = Guid.NewGuid();
        Assert.True(await fixture.Store.TryConsumeAsync(Device, id, "retained-nonce-1", Expires));
        fixture.Execute(action switch
        {
            "delete" => """
                CREATE TRIGGER unsafe_replay AFTER INSERT ON CONSUMED_COMMANDS
                BEGIN DELETE FROM consumed_commands; END;
                """,
            "rewrite" => """
                CREATE TRIGGER unsafe_replay AFTER INSERT ON consumed_commands
                BEGIN UPDATE consumed_commands SET expires_at_utc_ticks = 0; END;
                """,
            _ => """
                CREATE TRIGGER unsafe_replay BEFORE INSERT ON consumed_commands
                BEGIN SELECT RAISE(IGNORE); END;
                """
        });
        var before = fixture.Snapshot();

        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await fixture.Store.TryConsumeAsync(Device, Guid.NewGuid(), "fresh-nonce-123456", Expires));
        Assert.Equal(before, fixture.Snapshot());

        fixture.Execute("DROP TRIGGER unsafe_replay;");
        Assert.True(await fixture.Store.TryConsumeAsync(Device, Guid.NewGuid(), "fresh-nonce-123456", Expires));
        Assert.False(await fixture.Store.TryConsumeAsync(Device, id, "other-nonce-123456", Expires));
    }

    [Fact]
    public async Task An_unexpected_unique_ignore_policy_is_not_reported_as_a_replay()
    {
        using var fixture = new ReplayFixture("unexpected-unique");
        Assert.True(await fixture.Store.TryConsumeAsync(Device, Guid.NewGuid(), "retained-nonce-1", Expires));
        var before = fixture.Snapshot();

        var error = await Assert.ThrowsAsync<SqliteException>(async () =>
            await fixture.Store.TryConsumeAsync(Device, Guid.NewGuid(), "fresh-nonce-123456", Expires));

        Assert.Equal(19, error.SqliteErrorCode);
        Assert.Equal(before, fixture.Snapshot());
    }

    [Fact]
    public async Task An_unexpected_check_failure_is_a_storage_error_not_a_replay()
    {
        using var fixture = new ReplayFixture("check");
        var before = fixture.Snapshot();

        var error = await Assert.ThrowsAsync<SqliteException>(async () =>
            await fixture.Store.TryConsumeAsync(Device, Guid.NewGuid(), "schema-test-nonce-1", Expires));

        Assert.Equal(19, error.SqliteErrorCode);
        Assert.Equal(before, fixture.Snapshot());
    }

    [Theory]
    [InlineData("canonical")]
    [InlineData("indexed")]
    public async Task Supported_indexes_preserve_both_replay_keys_and_device_scope(string schema)
    {
        using var fixture = new ReplayFixture(schema);
        var id = Guid.NewGuid();
        Assert.True(await fixture.Store.TryConsumeAsync(Device, id, "retained-nonce-1", Expires));
        var before = fixture.Snapshot();

        Assert.False(await fixture.Store.TryConsumeAsync(Device, id, "other-nonce-123456", Expires));
        Assert.False(await fixture.RecreateStore().TryConsumeAsync(Device, Guid.NewGuid(), "retained-nonce-1", Expires));
        Assert.Equal(before, fixture.Snapshot());
        Assert.True(await fixture.Store.TryConsumeAsync(new DeviceId(Guid.NewGuid()), id, "retained-nonce-1", Expires));
    }

    [Fact]
    public async Task An_unrelated_tables_trigger_does_not_block_replay_consumption()
    {
        using var fixture = new ReplayFixture("canonical");
        fixture.Execute("""
            CREATE TABLE unrelated(value INTEGER);
            CREATE TRIGGER unrelated_trigger AFTER INSERT ON unrelated
            BEGIN UPDATE unrelated SET value = value + 1; END;
            """);

        Assert.True(await fixture.Store.TryConsumeAsync(Device, Guid.NewGuid(), "schema-test-nonce-1", Expires));
    }

    private sealed class ReplayFixture : IDisposable
    {
        private readonly string _directory = AgentStorageTestDirectory.Create();
        private readonly string _path;
        private readonly string _connectionString;
        public SqliteCommandReplayStore Store { get; }

        public ReplayFixture(string schema)
        {
            _path = Path.Combine(_directory, "replay.db");
            _connectionString = new SqliteConnectionStringBuilder { DataSource = _path, Pooling = false }.ToString();
            if (schema != "canonical")
            {
                var constraints = schema switch
                {
                    "none" => "",
                    "nonce" => ", UNIQUE(device_id, nonce)",
                    "unexpected-unique" => ", PRIMARY KEY(device_id, command_id), UNIQUE(device_id, nonce), UNIQUE(expires_at_utc_ticks) ON CONFLICT IGNORE",
                    "check" => ", PRIMARY KEY(device_id, command_id), UNIQUE(device_id, nonce), CHECK(expires_at_utc_ticks < 0)",
                    _ => ", PRIMARY KEY(device_id, command_id)"
                };
                Execute($"""
                    CREATE TABLE consumed_commands(
                        device_id TEXT NOT NULL, command_id TEXT NOT NULL,
                        nonce TEXT NOT NULL, expires_at_utc_ticks INTEGER NOT NULL {constraints});
                    """);
                if (schema is "partial" or "indexed")
                {
                    Execute(schema == "partial" ?
                        "CREATE UNIQUE INDEX replay_nonce ON consumed_commands(device_id, nonce) WHERE nonce LIKE 'only-%';" :
                        "CREATE UNIQUE INDEX replay_nonce ON consumed_commands(device_id, nonce);");
                }
            }
            Store = RecreateStore();
        }

        public SqliteCommandReplayStore RecreateStore() => new(_path);

        public void Execute(string sql)
        {
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = sql;
            command.ExecuteNonQuery();
        }

        public string Snapshot()
        {
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = """
                SELECT type || ':' || name || ':' || COALESCE(sql, '') FROM sqlite_schema
                WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name;
                SELECT device_id || ':' || command_id || ':' || nonce || ':' || expires_at_utc_ticks
                FROM consumed_commands ORDER BY device_id, command_id;
                """;
            using var reader = command.ExecuteReader();
            var rows = new List<string>();
            do { while (reader.Read()) { rows.Add(reader.GetString(0)); } } while (reader.NextResult());
            return string.Join('\n', rows);
        }

        public void Dispose()
        {
            var target = Path.GetFullPath(_directory);
            if (!target.StartsWith(Path.GetFullPath(Path.GetTempPath()), StringComparison.OrdinalIgnoreCase) ||
                !Path.GetFileName(target).StartsWith("fleetory-agent-replay-", StringComparison.Ordinal))
            {
                throw new InvalidOperationException("Replay test cleanup escaped its temporary directory.");
            }
            Directory.Delete(target, recursive: true);
        }
    }
}
