using Fleetory.Platform.Contracts.Secrets;
using Fleetory.Platform.Persistence;
using Fleetory.Platform.Secrets;
using Fleetory.Server;
using Fleetory.Core.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Fleetory.Server.Tests;

public sealed class SecretProviderTests
{
    private const string TestConnectionString =
        "Host=127.0.0.1;Port=1;Database=fleetory_test_secrets;Username=fleetory;Timeout=1";

    [Fact]
    public void Production_requires_a_secret_directory()
    {
        var exception = Assert.Throws<InvalidOperationException>(() =>
            FleetoryApplication.Build([
                "--environment=Production",
                $"--ConnectionStrings:Fleetory={TestConnectionString}"
            ]));

        Assert.Contains("Fleetory:Secrets:Directory", exception.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(TestConnectionString, exception.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void Agent_gateway_requires_secret_mount_and_distinct_valid_ports()
    {
        var missingSecrets = Assert.Throws<InvalidOperationException>(() =>
            FleetoryApplication.Build([
                "--environment=Development",
                $"--ConnectionStrings:Fleetory={TestConnectionString}",
                "--Fleetory:AgentGateway:Enabled=true"
            ]));
        Assert.Contains("Secrets:Directory", missingSecrets.Message, StringComparison.Ordinal);

        using var directory = new TestSecretDirectory();
        directory.Write(FleetorySecretNames.PostgreSqlConnectionString, TestConnectionString);
        var samePort = Assert.Throws<InvalidOperationException>(() =>
            FleetoryApplication.Build([
                "--environment=Development",
                $"--Fleetory:Secrets:Directory={directory.Path}",
                "--Fleetory:AgentGateway:Enabled=true",
                "--Fleetory:Web:Port=4433",
                "--Fleetory:AgentGateway:Port=4433"
            ]));
        Assert.Contains("ports must differ", samePort.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("0.0.0.0")]
    [InlineData("::")]
    [InlineData("::ffff:0.0.0.0")]
    public void Admin_gateway_rejects_wildcard_bind_addresses(string bindAddress)
    {
        using var directory = new TestSecretDirectory();
        directory.Write(FleetorySecretNames.PostgreSqlConnectionString, TestConnectionString);

        var exception = Assert.Throws<InvalidOperationException>(() =>
            FleetoryApplication.Build([
                "--environment=Development",
                $"--Fleetory:Secrets:Directory={directory.Path}",
                "--Fleetory:AdminGateway:Enabled=true",
                "--Fleetory:Web:Port=4433",
                "--Fleetory:AdminGateway:Port=4434",
                $"--Fleetory:AdminGateway:BindAddress={bindAddress}"
            ]));

        Assert.Contains("must be a specific IP address", exception.Message,
            StringComparison.Ordinal);
    }

    [Fact]
    public void Production_uses_the_file_secret_provider()
    {
        using var directory = new TestSecretDirectory();
        directory.Write(FleetorySecretNames.PostgreSqlConnectionString, TestConnectionString);

        using var app = FleetoryApplication.Build([
            "--environment=Production",
            $"--Fleetory:Secrets:Directory={directory.Path}"
        ]);

        var provider = app.Services.GetRequiredService<ISecretProvider>();
        Assert.IsType<FileSecretProvider>(provider);
        Assert.Equal(TestConnectionString,
            provider.GetRequiredSecret(FleetorySecretNames.PostgreSqlConnectionString));

        using var scope = app.Services.CreateScope();
        Assert.Equal(TestConnectionString,
            scope.ServiceProvider.GetRequiredService<PlatformDbContext>().Database.GetConnectionString());
        Assert.Equal(TestConnectionString,
            scope.ServiceProvider.GetRequiredService<CoreDbContext>().Database.GetConnectionString());
    }

    [Fact]
    public void Direct_configuration_is_rejected_when_a_secret_directory_is_set()
    {
        using var directory = new TestSecretDirectory();
        directory.Write(FleetorySecretNames.PostgreSqlConnectionString, TestConnectionString);

        var exception = Assert.Throws<InvalidOperationException>(() =>
            FleetoryApplication.Build([
                "--environment=Production",
                $"--Fleetory:Secrets:Directory={directory.Path}",
                $"--ConnectionStrings:Fleetory={TestConnectionString}"
            ]));

        Assert.Contains("either", exception.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(TestConnectionString, exception.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void OpenBao_rejects_mixed_secret_sources_and_missing_connection_configuration()
    {
        var mixedSources = Assert.Throws<InvalidOperationException>(() =>
            FleetoryApplication.Build([
                "--environment=Development",
                "--Fleetory:Secrets:Provider=OpenBao",
                $"--ConnectionStrings:Fleetory={TestConnectionString}"
            ]));
        Assert.Contains("cannot be combined", mixedSources.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(TestConnectionString, mixedSources.ToString(), StringComparison.Ordinal);

        var missingConfiguration = Assert.Throws<InvalidOperationException>(() =>
            FleetoryApplication.Build([
                "--environment=Development",
                "--Fleetory:Secrets:Provider=OpenBao"
            ]));
        Assert.Contains("TokenDirectory and Address", missingConfiguration.Message,
            StringComparison.Ordinal);
    }

    [Fact]
    public void Unknown_secret_provider_is_rejected_before_server_startup()
    {
        var exception = Assert.Throws<InvalidOperationException>(() =>
            FleetoryApplication.Build([
                "--environment=Development",
                "--Fleetory:Secrets:Provider=Unknown"
            ]));
        Assert.Contains("Unknown Fleetory:Secrets:Provider", exception.Message,
            StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("Fleetory:AdminGateway:RateLimitPerMinute", 0)]
    [InlineData("Fleetory:AdminGateway:RateLimitPerMinute", 301)]
    [InlineData("Fleetory:AgentGateway:RotationIntentRateLimitPerMinute", 0)]
    [InlineData("Fleetory:AgentGateway:RotationIntentRateLimitPerMinute", 301)]
    [InlineData("Fleetory:AgentGateway:EnrollmentRateLimitPerMinute", 0)]
    [InlineData("Fleetory:AgentGateway:EnrollmentRateLimitPerMinute", 301)]
    public void Gateway_rate_limits_refuse_values_outside_supported_range(
        string setting, int perMinute)
    {
        var exception = Assert.Throws<InvalidOperationException>(() =>
            FleetoryApplication.Build([
                "--environment=Development",
                $"--ConnectionStrings:Fleetory={TestConnectionString}",
                $"--{setting}={perMinute}"
            ]));
        Assert.Contains("must be between 1 and 300", exception.Message,
            StringComparison.Ordinal);
    }

    [Fact]
    public void Missing_or_invalid_secret_prevents_startup_without_echoing_its_value()
    {
        using var directory = new TestSecretDirectory();
        Assert.Throws<InvalidOperationException>(() => FleetoryApplication.Build([
            "--environment=Production",
            $"--Fleetory:Secrets:Directory={directory.Path}"
        ]));

        directory.Write(FleetorySecretNames.PostgreSqlConnectionString, "this is not a connection string");
        var exception = Assert.Throws<InvalidOperationException>(() => FleetoryApplication.Build([
            "--environment=Production",
            $"--Fleetory:Secrets:Directory={directory.Path}"
        ]));
        Assert.DoesNotContain("this is not a connection string", exception.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void Secret_names_are_restricted_and_file_contents_are_cached()
    {
        using var directory = new TestSecretDirectory();
        directory.Write(FleetorySecretNames.PostgreSqlConnectionString, TestConnectionString + "\n");
        var provider = new FileSecretProvider(directory.Path);

        Assert.Throws<ArgumentException>(() => provider.GetRequiredSecret("../outside"));
        Assert.Throws<ArgumentException>(() => provider.GetRequiredSecret("UPPERCASE"));
        Assert.Equal(TestConnectionString,
            provider.GetRequiredSecret(FleetorySecretNames.PostgreSqlConnectionString));

        directory.Write(FleetorySecretNames.PostgreSqlConnectionString, "changed");
        Assert.Equal(TestConnectionString,
            provider.GetRequiredSecret(FleetorySecretNames.PostgreSqlConnectionString));
    }

    [Fact]
    public void Oversized_secret_is_rejected()
    {
        using var directory = new TestSecretDirectory();
        directory.Write(FleetorySecretNames.PostgreSqlConnectionString, new string('a', 16 * 1024 + 1));

        var provider = new FileSecretProvider(directory.Path);
        var exception = Assert.Throws<InvalidOperationException>(() =>
            provider.GetRequiredSecret(FleetorySecretNames.PostgreSqlConnectionString));
        Assert.Contains("too large", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Invalid_utf8_and_broad_unix_permissions_are_rejected()
    {
        using var directory = new TestSecretDirectory();
        var path = directory.Write(FleetorySecretNames.PostgreSqlConnectionString, TestConnectionString);
        var provider = new FileSecretProvider(directory.Path);

        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.GroupRead);
            var permissionsException = Assert.Throws<InvalidOperationException>(() =>
                provider.GetRequiredSecret(FleetorySecretNames.PostgreSqlConnectionString));
            Assert.Contains("permissions", permissionsException.Message, StringComparison.Ordinal);
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }

        File.WriteAllBytes(path, [0xff]);
        provider = new FileSecretProvider(directory.Path);
        Assert.Throws<InvalidOperationException>(() =>
            provider.GetRequiredSecret(FleetorySecretNames.PostgreSqlConnectionString));
    }

    private sealed class TestSecretDirectory : IDisposable
    {
        public string Path { get; } = System.IO.Path.Combine(
            System.IO.Path.GetTempPath(), "fleetory-secret-test-" + Guid.NewGuid().ToString("N"));

        public TestSecretDirectory() => Directory.CreateDirectory(Path);

        public string Write(string name, string value)
        {
            var path = System.IO.Path.Combine(Path, name);
            File.WriteAllText(path, value);
            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }

            return path;
        }

        public void Dispose()
        {
            foreach (var file in Directory.GetFiles(Path))
            {
                File.Delete(file);
            }

            Directory.Delete(Path);
        }
    }
}
