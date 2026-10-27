using System.Diagnostics;
using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using DotNet.Testcontainers.Builders;
using DotNet.Testcontainers.Configurations;
using DotNet.Testcontainers.Containers;
using Docker.DotNet.Models;
using Fleetory.CommandSigner.Host;
using Fleetory.Core.Contracts;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Npgsql;
using Testcontainers.PostgreSql;
using TestPki = Fleetory.Persistence.Tests.AgentGatewayTlsTests.TestPki;

namespace Fleetory.Persistence.Tests;

[Collection(PostgreSqlTestCollection.Name)]
public sealed class SignerProcessIsolationTests
{
    [Fact]
    public async Task Published_signer_runs_in_a_separate_restricted_process_and_preserves_its_security_boundary()
    {
        var repo = FindRepository();
        var packageName = "isolation-" + Guid.NewGuid().ToString("N");
        var context = Path.Combine(repo, "artifacts", "command-signer-container", packageName);
        try
        {
            await PublishAsync(repo, packageName);
            Assert.False(File.Exists(Path.Combine(context, "publish", "Fleetory.Server.dll")));
            var image = "fleetory-signer-proof:" + packageName;
            using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(4));
            await RunProcessAsync("docker", repo, ["build", "--quiet", "--tag", image, context], TimeSpan.FromMinutes(2));
            await using var network = new NetworkBuilder().Build();
            await network.CreateAsync(deadline.Token);
            using var pki = new TestPki(new Uri("urn:fleetory:approval-service:proof"));
            using var databaseKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            using var databaseCertificate = pki.IssueServerCertificate(databaseKey, "signer-db");
            await using var database = new PostgreSqlBuilder(PostgreSqlTestFixture.PostgreSqlImage)
                .WithDatabase("signer_isolation_test").WithUsername("deployment_owner").WithPassword(Guid.NewGuid().ToString("N"))
                .WithNetwork(network).WithNetworkAliases("signer-db")
                .WithResourceMapping(Bytes(databaseCertificate.ExportCertificatePem()), "/tls/server.pem", 999, 999, UnixFileModes.UserRead)
                .WithResourceMapping(Bytes(databaseKey.ExportPkcs8PrivateKeyPem()), "/tls/server.key", 999, 999, UnixFileModes.UserRead)
                .WithCommand("-c", "fsync=on", "-c", "ssl=on", "-c", "ssl_cert_file=/tls/server.pem", "-c", "ssl_key_file=/tls/server.key")
                .Build();
            await database.StartAsync(deadline.Token);
            var ownerSettings = new NpgsqlConnectionStringBuilder(database.GetConnectionString()) { SslMode = SslMode.Disable };
            await using var owner = NpgsqlDataSource.Create(ownerSettings.ConnectionString);
            var runtimePassword = Guid.NewGuid().ToString("N");
            var probePassword = Guid.NewGuid().ToString("N");
            await ProvisionAsync(owner, runtimePassword, probePassword);
            using var signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            using var transitTlsKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            using var transitCertificate = pki.IssueServerCertificate(transitTlsKey, "host.docker.internal");
            var token = "proof-" + Guid.NewGuid().ToString("N");
            var transitCalls = 0;
            var builder = WebApplication.CreateSlimBuilder();
            builder.Configuration["AllowedHosts"] = "host.docker.internal";
            builder.Logging.ClearProviders();
            builder.WebHost.ConfigureKestrel(options => options.Listen(IPAddress.Any, 0,
                listen => listen.UseHttps(transitCertificate)));
            await using var transit = builder.Build();
            transit.MapPost("/v1/transit/sign/proof-key/sha2-256", async (Microsoft.AspNetCore.Http.HttpContext http) =>
            {
                Assert.Equal(token, http.Request.Headers["X-Vault-Token"]);
                Interlocked.Increment(ref transitCalls);
                using var body = await JsonDocument.ParseAsync(http.Request.Body);
                var input = Convert.FromBase64String(body.RootElement.GetProperty("input").GetString()!);
                var signature = signingKey.SignData(input, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
                return Microsoft.AspNetCore.Http.Results.Json(new { data = new { signature = "vault:v2:" + Convert.ToBase64String(signature) } });
            });
            await transit.StartAsync(deadline.Token);
            var transitPort = new Uri(transit.Services.GetRequiredService<IServer>().Features
                .Get<IServerAddressesFeature>()!.Addresses.Single()).Port;
            var device = new DeviceId(Guid.NewGuid());
            var runtime = new NpgsqlConnectionStringBuilder
            {
                Host = "signer-db", Database = "signer_isolation_test", Username = "signer_runtime", Password = runtimePassword,
                SslMode = SslMode.VerifyFull, RootCertificate = "/run/fleetory-signer/infrastructure-ca", Pooling = false
            };
            var secrets = new Dictionary<string, string>
            {
                ["signer-postgresql"] = runtime.ConnectionString,
                ["signer-server-ca"] = pki.Root.ExportCertificatePem(),
                ["signer-server-cert"] = pki.ServerChainPem,
                ["signer-server-key"] = pki.ServerKey.ExportPkcs8PrivateKeyPem(),
                ["signer-transit-token"] = token,
                ["signer-transit-public-key"] = Convert.ToBase64String(signingKey.ExportSubjectPublicKeyInfo()),
                ["infrastructure-ca"] = pki.Root.ExportCertificatePem(),
                ["signer-policy"] = JsonSerializer.Serialize(new
                {
                    rootsPem = pki.Root.ExportCertificatePem(), callers = new[] { new
                    {
                        callerId = "approval-proof", certificateSha256 = pki.Client.GetCertHashString(HashAlgorithmName.SHA256),
                        deviceIds = new[] { device.Value }, notBefore = DateTimeOffset.UtcNow.AddMinutes(-1),
                        expiresAt = DateTimeOffset.UtcNow.AddMinutes(10)
                    } }
                })
            };
            var signerBuilder = Restricted(image).WithNetwork(network)
                .WithPortBinding(9443, true)
                .WithCreateParameterModifier(parameters =>
                {
                    foreach (var binding in parameters.HostConfig!.PortBindings["9443/tcp"]) { binding.HostIP = "127.0.0.1"; }
                })
                .WithEnvironment("SSL_CERT_FILE", "/run/fleetory-signer/infrastructure-ca")
                .WithCommand("--Signer:SecretsDirectory=/run/fleetory-signer", "--Signer:Port=9443",
                    $"--Signer:TransitAddress=https://host.docker.internal:{transitPort}/", "--Signer:TransitKey=proof-key", "--Signer:TransitKeyVersion=2")
                .WithWaitStrategy(Wait.ForUnixContainer().UntilInternalTcpPortIsAvailable(9443));
            if (!OperatingSystem.IsWindows()) { signerBuilder = signerBuilder.WithExtraHost("host.docker.internal", "host-gateway"); }
            await using var secretVolume = new VolumeBuilder().Build();
            await secretVolume.CreateAsync(deadline.Token);
            var initializerBuilder = new ContainerBuilder(image).WithEntrypoint("/bin/sh")
                .WithCommand("-c", "sleep 120").WithVolumeMount(secretVolume, "/secrets")
                .WithCreateParameterModifier(parameters => parameters.User = "0");
            foreach (var secret in secrets)
            {
                initializerBuilder = initializerBuilder.WithResourceMapping(Bytes(secret.Value),
                    "/secrets/" + secret.Key, 1654, 1654, UnixFileModes.UserRead);
            }
            await using var initializer = initializerBuilder.Build();
            await initializer.StartAsync(deadline.Token);
            Assert.Equal(0, (await initializer.ExecAsync(["chmod", "0555", "/secrets"])).ExitCode);
            await initializer.StopAsync(deadline.Token);
            signerBuilder = signerBuilder.WithVolumeMount(secretVolume, "/run/fleetory-signer", AccessMode.ReadOnly);
            await using var signer = signerBuilder.Build();
            await signer.StartAsync(deadline.Token);
            await AssertRestrictedAsync(signer);
            await using var probe = Restricted(image).WithEntrypoint("/bin/sh")
                .WithCommand("-c", "test ! -e /run/fleetory-signer/signer-transit-token && test ! -e /run/fleetory-signer/signer-server-key && test ! -S /var/run/docker.sock && sleep 30").Build();
            await probe.StartAsync(deadline.Token);
            Assert.Equal(0, (await probe.ExecAsync(["/bin/sh", "-c", "test ! -e /run/fleetory-signer/signer-transit-token && test ! -e /app/Fleetory.Server.dll"])).ExitCode);
            var probeSettings = new NpgsqlConnectionStringBuilder(ownerSettings.ConnectionString)
            {
                Username = "server_probe", Password = probePassword
            };
            await using (var probeSource = NpgsqlDataSource.Create(probeSettings.ConnectionString))
            await using (var denied = probeSource.CreateCommand("SELECT * FROM signer.signing_requests"))
            {
                var error = await Assert.ThrowsAsync<PostgresException>(() => denied.ExecuteScalarAsync());
                Assert.Equal(PostgresErrorCodes.InsufficientPrivilege, error.SqlState);
            }
            var url = $"https://127.0.0.1:{signer.GetMappedPublicPort(9443)}";
            var requestId = Guid.NewGuid();
            using (var client = pki.CreateClient(pki.Client))
            using (var response = await client.PostAsJsonAsync(url + "/signing/inventory-refresh", new { requestId, deviceId = device.Value }))
            {
                Assert.Equal(HttpStatusCode.OK, response.StatusCode);
                var result = (await response.Content.ReadFromJsonAsync<SigningHostApplication.SigningResponse>())!;
                Assert.Equal(requestId, result.RequestId);
                Assert.Equal(device.Value, result.DeviceId);
                Assert.Equal(AgentCommandTypes.InventoryRefresh, result.CommandType);
                var envelope = new SignedCommandEnvelope(device, result.CommandId, result.CommandType, [], result.IssuedAt,
                    result.ExpiresAt, result.Nonce, result.SigningKeyId, Convert.FromBase64String(result.Signature), result.FormatVersion);
                Assert.True(signingKey.VerifyData(envelope.GetSigningBytes(), envelope.Signature.Span,
                    HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
            }
            await signer.StopAsync(deadline.Token);
            await signer.StartAsync(deadline.Token);
            url = $"https://127.0.0.1:{signer.GetMappedPublicPort(9443)}";
            using (var client = pki.CreateClient(pki.Client))
            using (var duplicate = await client.PostAsJsonAsync(url + "/signing/inventory-refresh", new { requestId, deviceId = device.Value }))
            {
                Assert.Equal(HttpStatusCode.Conflict, duplicate.StatusCode);
            }
            using (var unregistered = pki.CreateClient(pki.UnregisteredClient))
            {
                await Assert.ThrowsAsync<HttpRequestException>(() => unregistered.GetAsync(url + "/health/live"));
            }
            Assert.Equal(1, Volatile.Read(ref transitCalls));
            var logs = await signer.GetLogsAsync();
            Assert.Contains("fleetory.signer-tls-failure.v1", logs.Stdout);
            Assert.DoesNotContain(token, logs.Stdout + logs.Stderr);
            Assert.DoesNotContain(runtimePassword, logs.Stdout + logs.Stderr);
            Assert.DoesNotContain("PRIVATE KEY", logs.Stdout + logs.Stderr);
        }
        finally
        {
            await RunProcessAsync("docker", repo, ["image", "rm", "fleetory-signer-proof:" + packageName], TimeSpan.FromSeconds(30), requireSuccess: false);
            foreach (var folder in new[] { "command-signer-container", "command-signer-publish" })
            {
                var root = Path.GetFullPath(Path.Combine(repo, "artifacts", folder)) + Path.DirectorySeparatorChar;
                var target = Path.GetFullPath(Path.Combine(root, packageName));
                if (!target.StartsWith(root, StringComparison.OrdinalIgnoreCase)) { throw new InvalidOperationException("Unsafe package cleanup path."); }
                if (Directory.Exists(target)) { Directory.Delete(target, true); }
            }
        }
    }

    private static ContainerBuilder Restricted(string image) => new ContainerBuilder(image)
        .WithCreateParameterModifier(parameters =>
        {
            parameters.HostConfig ??= new HostConfig();
            parameters.HostConfig.ReadonlyRootfs = true;
            parameters.HostConfig.CapDrop = ["ALL"];
            parameters.HostConfig.SecurityOpt = ["no-new-privileges:true"];
            parameters.HostConfig.PidsLimit = 64;
            parameters.HostConfig.Memory = 256 * 1024 * 1024;
        });

    private static async Task AssertRestrictedAsync(IContainer container)
    {
        var check = await container.ExecAsync(["/bin/sh", "-c", """
            test "$(id -u)" = 1654 &&
            grep -q '^NoNewPrivs:[[:space:]]*1' /proc/self/status &&
            grep -q '^CapEff:[[:space:]]*0000000000000000' /proc/self/status &&
            test ! -S /var/run/docker.sock && test ! -e /app/Fleetory.Server.dll &&
            grep ' /run/fleetory-signer ' /proc/mounts | grep -q ' ro[, ]' &&
            if touch /tmp/write-probe 2>/dev/null; then exit 1; fi
            """]);
        Assert.Equal(0, check.ExitCode);
    }

    private static async Task ProvisionAsync(NpgsqlDataSource owner, string runtimePassword, string probePassword)
    {
        await using var schema = owner.CreateCommand(await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "provision-signing-journal.sql")));
        await schema.ExecuteNonQueryAsync();
        // Passwords are generated hex test values, never supplied input or production credentials.
        await using var roles = owner.CreateCommand($"""
            CREATE ROLE signer_runtime LOGIN PASSWORD '{runtimePassword}';
            CREATE ROLE server_probe LOGIN PASSWORD '{probePassword}';
            GRANT CONNECT ON DATABASE signer_isolation_test TO signer_runtime, server_probe;
            GRANT USAGE ON SCHEMA signer TO signer_runtime;
            GRANT SELECT, INSERT ON signer.signing_requests, signer.signing_results, signer.signing_rejections TO signer_runtime;
            GRANT SELECT ON signer.client_certificate_revocations TO signer_runtime;
            """);
        await roles.ExecuteNonQueryAsync();
    }

    private static async Task PublishAsync(string repo, string name)
    {
        await RunProcessAsync("pwsh", repo,
            ["-NoProfile", "-File", Path.Combine(repo, "eng", "package-command-signer.ps1"), "-Name", name], TimeSpan.FromMinutes(1));
    }

    private static async Task RunProcessAsync(string executable, string directory, string[] arguments, TimeSpan timeout, bool requireSuccess = true)
    {
        var start = new ProcessStartInfo(executable) { WorkingDirectory = directory, UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var argument in arguments) { start.ArgumentList.Add(argument); }
        using var process = Process.Start(start)!;
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        using var deadline = new CancellationTokenSource(timeout);
        try { await process.WaitForExitAsync(deadline.Token); }
        catch (OperationCanceledException) { process.Kill(entireProcessTree: true); throw; }
        var output = (await stdout) + (await stderr);
        if (requireSuccess) { Assert.True(process.ExitCode == 0, output); }
    }

    private static string FindRepository()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "Fleetory.sln"))) { directory = directory.Parent; }
        return directory?.FullName ?? throw new InvalidOperationException("Fleetory repository was not found.");
    }

    private static byte[] Bytes(string value) => Encoding.UTF8.GetBytes(value);
}
