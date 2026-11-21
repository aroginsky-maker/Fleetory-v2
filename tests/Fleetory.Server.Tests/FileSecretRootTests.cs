using System.Diagnostics;
using Fleetory.Security.Infrastructure;

namespace Fleetory.Server.Tests;

public sealed class FileSecretRootTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Uncached_read_rejects_a_root_replaced_by_a_link(bool warmCache)
    {
        using var files = new SecretRoot();
        SecretRoot.Write(files.Secrets, "cached", "original");
        SecretRoot.Write(files.Alternate, "fresh", "replacement");
        SecretRoot.Write(files.Alternate, "cached", "replacement");
        var provider = new FileSecretProvider(files.Secrets);
        if (warmCache) { Assert.Equal("original", provider.GetRequiredSecret("cached")); }

        await files.ReplaceRootAsync();
        var error = Assert.Throws<InvalidOperationException>(() => provider.GetRequiredSecret("fresh"));
        Assert.DoesNotContain("replacement", error.ToString(), StringComparison.Ordinal);
        if (warmCache) { Assert.Equal("original", provider.GetRequiredSecret("cached")); }
    }

    [Theory]
    [InlineData(UnixFileMode.GroupWrite)]
    [InlineData(UnixFileMode.OtherWrite)]
    public void Uncached_read_rechecks_unix_directory_write_permissions(UnixFileMode unsafeMode)
    {
        if (OperatingSystem.IsWindows()) { return; }
        using var files = new SecretRoot();
        SecretRoot.Write(files.Secrets, "cached", "original");
        SecretRoot.Write(files.Secrets, "fresh", "fresh-private-value");
        var provider = new FileSecretProvider(files.Secrets);
        Assert.Equal("original", provider.GetRequiredSecret("cached"));
        var original = File.GetUnixFileMode(files.Secrets);
        File.SetUnixFileMode(files.Secrets, original | unsafeMode);
        try
        {
            var error = Assert.Throws<InvalidOperationException>(() => provider.GetRequiredSecret("fresh"));
            Assert.DoesNotContain("fresh-private-value", error.ToString(), StringComparison.Ordinal);
            Assert.Equal("original", provider.GetRequiredSecret("cached"));
        }
        finally { File.SetUnixFileMode(files.Secrets, original); }
    }

    [Fact]
    public void Protected_unchanged_root_allows_a_later_uncached_secret()
    {
        using var files = new SecretRoot();
        SecretRoot.Write(files.Secrets, "cached", "original");
        var provider = new FileSecretProvider(files.Secrets);
        Assert.Equal("original", provider.GetRequiredSecret("cached"));
        SecretRoot.Write(files.Secrets, "fresh", "later-value");
        Assert.Equal("later-value", provider.GetRequiredSecret("fresh"));
    }

    private sealed class SecretRoot : IDisposable
    {
        private readonly string _root = Path.Combine(Path.GetTempPath(), "fleetory-secret-root-" + Guid.NewGuid().ToString("N"));
        public string Secrets => Path.Combine(_root, "secrets");
        public string Alternate => Path.Combine(_root, "alternate");
        private string Archive => Path.Combine(_root, "archive");

        public SecretRoot()
        {
            Directory.CreateDirectory(Secrets);
            Directory.CreateDirectory(Alternate);
        }

        public static void Write(string directory, string name, string value)
        {
            var path = Path.Combine(directory, name);
            File.WriteAllText(path, value);
            if (!OperatingSystem.IsWindows()) { File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite); }
        }

        public async Task ReplaceRootAsync()
        {
            Assert.Equal(_root, Path.GetDirectoryName(Path.GetFullPath(Secrets)));
            Assert.Equal(_root, Path.GetDirectoryName(Path.GetFullPath(Archive)));
            Directory.Move(Secrets, Archive);
            if (OperatingSystem.IsWindows())
            {
                var start = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "cmd.exe"))
                {
                    UseShellExecute = false, CreateNoWindow = true,
                    RedirectStandardOutput = true, RedirectStandardError = true
                };
                foreach (var argument in new[] { "/d", "/c", "mklink", "/J", Secrets, Alternate })
                {
                    start.ArgumentList.Add(argument);
                }
                using var process = Process.Start(start) ?? throw new InvalidOperationException("Junction fixture did not start.");
                using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                await process.WaitForExitAsync(deadline.Token);
                Assert.Equal(0, process.ExitCode);
            }
            else { Directory.CreateSymbolicLink(Secrets, Alternate); }
            Assert.NotEqual((FileAttributes)0, File.GetAttributes(Secrets) & FileAttributes.ReparsePoint);
        }

        public void Dispose()
        {
            foreach (var directory in new[] { Secrets, Archive, Alternate })
            {
                if (!Directory.Exists(directory)) { continue; }
                if ((File.GetAttributes(directory) & FileAttributes.ReparsePoint) == 0)
                {
                    foreach (var file in Directory.GetFiles(directory)) { File.Delete(file); }
                }
                Directory.Delete(directory);
            }
            Directory.Delete(_root);
        }
    }
}
