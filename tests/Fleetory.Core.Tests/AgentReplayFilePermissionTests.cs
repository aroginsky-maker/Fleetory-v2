using Fleetory.Agent.Security;
using Fleetory.Core.Contracts;
using Microsoft.Data.Sqlite;

namespace Fleetory.Core.Tests;

public sealed class AgentReplayFilePermissionTests
{
    [Theory]
    [InlineData("", UnixFileMode.GroupWrite)]
    [InlineData("", UnixFileMode.OtherWrite)]
    [InlineData("-wal", UnixFileMode.GroupWrite)]
    [InlineData("-wal", UnixFileMode.OtherWrite)]
    [InlineData("-shm", UnixFileMode.GroupWrite)]
    [InlineData("-shm", UnixFileMode.OtherWrite)]
    public async Task Unix_writable_replay_files_are_refused_without_changing_history(
        string suffix, UnixFileMode exposedWrite)
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        var directory = AgentStorageTestDirectory.Create();
        try
        {
            var path = Path.Combine(directory, "replay.db");
            var device = new DeviceId(Guid.NewGuid());
            var retainedId = Guid.NewGuid();
            var attemptedId = Guid.NewGuid();
            var expires = DateTimeOffset.UtcNow.AddMinutes(1);
            var store = new SqliteCommandReplayStore(path);

            // A real open connection retains SQLite's WAL and shared-memory files.
            await using var keeper = new SqliteConnection(
                new SqliteConnectionStringBuilder { DataSource = path, Pooling = false }.ToString());
            await keeper.OpenAsync();
            await using var read = keeper.CreateCommand();
            read.CommandText = "SELECT count(*) FROM consumed_commands;";
            Assert.Equal(0L, await read.ExecuteScalarAsync());
            Assert.True(await store.TryConsumeAsync(device, retainedId, "retained-nonce-123", expires));

            var file = path + suffix;
            Assert.True(File.Exists(file));
            var originalMode = File.GetUnixFileMode(file);
            var unsafeMode = originalMode | exposedWrite;
            File.SetUnixFileMode(file, unsafeMode);
            var before = new[] { path, path + "-wal", path + "-shm" }
                .Select(File.ReadAllBytes).ToArray();

            Assert.Throws<InvalidOperationException>(() => new SqliteCommandReplayStore(path));
            await Assert.ThrowsAsync<InvalidOperationException>(async () =>
                await store.TryConsumeAsync(device, attemptedId, "attempted-nonce-123", expires));
            Assert.Equal(unsafeMode, File.GetUnixFileMode(file));
            var after = new[] { path, path + "-wal", path + "-shm" }
                .Select(File.ReadAllBytes).ToArray();
            for (var i = 0; i < before.Length; i++)
            {
                Assert.Equal(before[i], after[i]);
            }

            File.SetUnixFileMode(file, originalMode);
            var restarted = new SqliteCommandReplayStore(path);
            Assert.False(await restarted.TryConsumeAsync(device, retainedId, "other-nonce-123456", expires));
            Assert.False(await restarted.TryConsumeAsync(device, Guid.NewGuid(), "retained-nonce-123", expires));
            Assert.True(await restarted.TryConsumeAsync(device, attemptedId, "attempted-nonce-123", expires));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }
}
