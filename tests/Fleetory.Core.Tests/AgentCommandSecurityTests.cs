using Fleetory.Agent.Security;
using Fleetory.Core.Contracts;
using System.Security.Cryptography;
using Fleetory.AgentTestSupport;

namespace Fleetory.Core.Tests;

public sealed class AgentCommandSecurityTests
{
    private static readonly DeviceId Device = new(Guid.Parse("c60c38d9-adfd-4c48-9cb2-f34c783f895b"));

    [Fact]
    public async Task Replay_entries_survive_store_recreation_and_reject_either_reused_identifier()
    {
        var directory = CreateTemporaryDirectory();
        try
        {
            var path = Path.Combine(directory, "replay.db");
            var commandId = Guid.NewGuid();
            var expiry = DateTimeOffset.UtcNow.AddMinutes(1);
            var first = new SqliteCommandReplayStore(path);
            Assert.True(await first.TryConsumeAsync(Device, commandId, "nonce-first-123456", expiry));

            var restarted = new SqliteCommandReplayStore(path);
            Assert.False(await restarted.TryConsumeAsync(Device, commandId, "nonce-second-12345", expiry));
            Assert.False(await restarted.TryConsumeAsync(Device, Guid.NewGuid(), "nonce-first-123456", expiry));
            Assert.True(await restarted.TryConsumeAsync(
                new DeviceId(Guid.NewGuid()), commandId, "nonce-first-123456", expiry));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task Concurrent_consumers_accept_one_command_only()
    {
        var directory = CreateTemporaryDirectory();
        try
        {
            var store = new SqliteCommandReplayStore(Path.Combine(directory, "replay.db"));
            var commandId = Guid.NewGuid();
            var attempts = Enumerable.Range(0, 12).Select(_ => Task.Run(async () =>
                await store.TryConsumeAsync(Device, commandId, "same-nonce-12345678", DateTimeOffset.UtcNow.AddMinutes(1))));

            var results = await Task.WhenAll(attempts);
            Assert.Single(results, accepted => accepted);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void Missing_storage_directory_fails_closed()
    {
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"), "replay.db");
        Assert.Throws<ArgumentException>(() => new SqliteCommandReplayStore(path));
    }

    [Fact]
    public async Task Replay_storage_rejects_invalid_identity_and_untrusted_directory()
    {
        var directory = CreateTemporaryDirectory();
        try
        {
            var store = new SqliteCommandReplayStore(Path.Combine(directory, "replay.db"));
            await Assert.ThrowsAsync<ArgumentException>(async () =>
                await store.TryConsumeAsync(Device, Guid.Empty, "valid-nonce-123456", DateTimeOffset.UtcNow));

            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(directory,
                    UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute |
                    UnixFileMode.OtherRead);
                await Assert.ThrowsAsync<InvalidOperationException>(async () =>
                    await store.TryConsumeAsync(Device, Guid.NewGuid(), "fresh-nonce-123456", DateTimeOffset.UtcNow));
                Assert.Throws<InvalidOperationException>(() =>
                    new SqliteCommandReplayStore(Path.Combine(directory, "other.db")));
            }
            else
            {
                WindowsAgentAclTestHelper.GrantEveryoneWrite(directory, directory: true);
                await Assert.ThrowsAsync<InvalidOperationException>(async () =>
                    await store.TryConsumeAsync(Device, Guid.NewGuid(), "fresh-nonce-123456", DateTimeOffset.UtcNow));
                Assert.Throws<InvalidOperationException>(() =>
                    new SqliteCommandReplayStore(Path.Combine(directory, "other.db")));
            }
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task Windows_replay_storage_rejects_exposed_existing_database()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var directory = CreateTemporaryDirectory();
        try
        {
            var path = Path.Combine(directory, "replay.db");
            var store = new SqliteCommandReplayStore(path);
            WindowsAgentAclTestHelper.GrantEveryoneWrite(path, directory: false);
            Assert.Throws<InvalidOperationException>(() => new SqliteCommandReplayStore(path));
            await Assert.ThrowsAsync<InvalidOperationException>(async () =>
                await store.TryConsumeAsync(Device, Guid.NewGuid(), "new-nonce-12345678", DateTimeOffset.UtcNow));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task Local_policy_denies_other_targets_payloads_and_unsupported_commands()
    {
        var policy = new AgentCommandExecutionPolicy(Device);

        Assert.True(await policy.IsAllowedAsync(Device, "Inventory.Refresh", ReadOnlyMemory<byte>.Empty));
        Assert.False(await policy.IsAllowedAsync(Device, "Inventory.Refresh", "{}"u8.ToArray()));
        Assert.False(await policy.IsAllowedAsync(new DeviceId(Guid.NewGuid()), "Inventory.Refresh", ReadOnlyMemory<byte>.Empty));
        Assert.False(await policy.IsAllowedAsync(Device, "Shell.Execute", ReadOnlyMemory<byte>.Empty));
    }

    [Fact]
    public async Task Trust_directory_scopes_keys_to_device_and_reflects_revocation()
    {
        var directory = CreateTemporaryDirectory();
        try
        {
            using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var key = signer.ExportSubjectPublicKeyInfo();
            var path = Path.Combine(directory, $"{Device.Value:N}-key-1.spki");
            await File.WriteAllBytesAsync(path, key);
            var trust = new DirectoryCommandVerificationKeys(Device, directory);

            Assert.Equal(key, (await trust.FindPublicKeyAsync(Device, "key-1"))?.ToArray());
            Assert.Null(await trust.FindPublicKeyAsync(new DeviceId(Guid.NewGuid()), "key-1"));
            Assert.Null(await trust.FindPublicKeyAsync(Device, "../key-1"));

            File.Delete(path);
            Assert.Null(await trust.FindPublicKeyAsync(Device, "key-1"));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task Trust_directory_rejects_oversize_and_writable_key_files()
    {
        var directory = CreateTemporaryDirectory();
        try
        {
            var path = Path.Combine(directory, $"{Device.Value:N}-key-1.spki");
            var trust = new DirectoryCommandVerificationKeys(Device, directory);
            await File.WriteAllBytesAsync(path, new byte[1025]);
            await Assert.ThrowsAsync<InvalidOperationException>(async () =>
                await trust.FindPublicKeyAsync(Device, "key-1"));

            if (!OperatingSystem.IsWindows())
            {
                await File.WriteAllBytesAsync(path, [1, 2, 3]);
                File.SetUnixFileMode(path,
                    UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.OtherWrite);
                await Assert.ThrowsAsync<InvalidOperationException>(async () =>
                    await trust.FindPublicKeyAsync(Device, "key-1"));
            }
            else
            {
                await File.WriteAllBytesAsync(path, [1, 2, 3]);
                WindowsAgentAclTestHelper.GrantEveryoneWrite(path, directory: false);
                await Assert.ThrowsAsync<InvalidOperationException>(async () =>
                    await trust.FindPublicKeyAsync(Device, "key-1"));
            }
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task Windows_trust_directory_rejects_broad_access()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var directory = CreateTemporaryDirectory();
        try
        {
            var trust = new DirectoryCommandVerificationKeys(Device, directory);
            WindowsAgentAclTestHelper.GrantEveryoneWrite(directory, directory: true);
            Assert.Throws<InvalidOperationException>(() =>
                new DirectoryCommandVerificationKeys(Device, directory));
            await Assert.ThrowsAsync<InvalidOperationException>(async () =>
                await trust.FindPublicKeyAsync(Device, "key-1"));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    private static string CreateTemporaryDirectory()
    {
        var directory = Path.Combine(Path.GetTempPath(), "fleetory-agent-replay-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        if (OperatingSystem.IsWindows())
        {
            WindowsAgentAclTestHelper.ProtectDirectory(directory);
        }
        else
        {
            File.SetUnixFileMode(directory,
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }
        return directory;
    }
}
