using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Fleetory.CommandSigner.Host;
using Fleetory.Core.Contracts;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Npgsql;
using TestPki = Fleetory.Persistence.Tests.AgentGatewayTlsTests.TestPki;
using TestSecrets = Fleetory.Persistence.Tests.AgentGatewayTlsTests.TestSecretDirectory;

namespace Fleetory.Persistence.Tests;

[Collection(PostgreSqlTestCollection.Name)]
public sealed partial class SigningHostTlsTests(PostgreSqlTestFixture fixture)
{
    [Fact]
    public async Task Real_mtls_signing_journals_once_and_returns_a_valid_signature()
    {
        await using var lab = await HostLab.CreateAsync(fixture);
        var requestId = Guid.NewGuid();
        using var client = lab.Pki.CreateClient(lab.Pki.Client);
        using var response = await client.PostAsJsonAsync(lab.Url + "/signing/inventory-refresh",
            new { requestId, deviceId = lab.Device.Value });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        var result = (await response.Content.ReadFromJsonAsync<SigningHostApplication.SigningResponse>())!;
        var envelope = new SignedCommandEnvelope(new DeviceId(result.DeviceId), result.CommandId,
            result.CommandType, [], result.IssuedAt, result.ExpiresAt, result.Nonce, result.SigningKeyId,
            Convert.FromBase64String(result.Signature), result.FormatVersion);
        Assert.Equal(requestId, result.RequestId);
        Assert.True(lab.Key.VerifyData(envelope.GetSigningBytes(), envelope.Signature.Span,
            HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
        using var repeated = await client.PostAsJsonAsync(lab.Url + "/signing/inventory-refresh",
            new { requestId, deviceId = lab.Device.Value });
        Assert.Equal(HttpStatusCode.Conflict, repeated.StatusCode);
        Assert.Equal(1, lab.TransitCalls);
        Assert.Equal(1L, await lab.CountAsync("signing_requests"));
        Assert.Equal(1L, await lab.CountAsync("signing_results"));
        Assert.Equal(1L, await lab.CountAsync("signing_rejections"));
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("unregistered")]
    [InlineData("foreign")]
    public async Task Clients_without_the_registered_key_cannot_reach_http_signing(string kind)
    {
        await using var lab = await HostLab.CreateAsync(fixture);
        using var foreign = new TestPki(new DeviceId(Guid.NewGuid()));
        using var client = lab.Pki.CreateClient(kind switch
        {
            "missing" => null, "unregistered" => lab.Pki.UnregisteredClient, _ => foreign.Client
        });
        client.DefaultRequestHeaders.Add("X-ARR-ClientCert", Convert.ToBase64String(lab.Pki.Client.RawData));
        await Assert.ThrowsAsync<HttpRequestException>(() => client.PostAsJsonAsync(
            lab.Url + "/signing/inventory-refresh", new { requestId = Guid.NewGuid(), deviceId = lab.Device.Value }));
        Assert.Equal(0, lab.TransitCalls);
        Assert.Equal(0L, await lab.CountAsync("signing_requests"));
    }

    [Theory]
    [InlineData("scope", HttpStatusCode.Forbidden)]
    [InlineData("unknown-field", HttpStatusCode.BadRequest)]
    [InlineData("duplicate-field", HttpStatusCode.BadRequest)]
    [InlineData("empty", HttpStatusCode.BadRequest)]
    [InlineData("oversized", HttpStatusCode.BadRequest)]
    [InlineData("unsupported-command", HttpStatusCode.NotFound)]
    [InlineData("unsupported-dotted-command", HttpStatusCode.NotFound)]
    public async Task Rejected_http_requests_are_audited_without_transit_access(string kind, HttpStatusCode expected)
    {
        await using var lab = await HostLab.CreateAsync(fixture);
        using var client = lab.Pki.CreateClient(lab.Pki.Client);
        var id = Guid.NewGuid();
        var json = kind switch
        {
            "scope" => JsonSerializer.Serialize(new { requestId = id, deviceId = Guid.NewGuid() }),
            "unknown-field" => JsonSerializer.Serialize(new { requestId = id, deviceId = lab.Device.Value, callerId = "admin" }),
            "duplicate-field" => $"{{\"requestId\":\"{id}\",\"requestId\":\"{Guid.NewGuid()}\",\"deviceId\":\"{lab.Device.Value}\"}}",
            "empty" => "{}",
            "oversized" => new string('x', 2048),
            _ => JsonSerializer.Serialize(new { requestId = id, deviceId = lab.Device.Value })
        };
        var path = kind switch
        {
            "unsupported-command" => "/signing/bulk-reboot",
            "unsupported-dotted-command" => "/signing/Fleet.Bulk.Reboot",
            _ => "/signing/inventory-refresh"
        };
        using var response = await client.PostAsync(lab.Url + path, new StringContent(json, Encoding.UTF8, "application/json"));
        Assert.Equal(expected, response.StatusCode);
        Assert.True(Guid.TryParseExact(response.Headers.GetValues("X-Fleetory-Audit-Id").Single(), "N", out _));
        Assert.Equal(0, lab.TransitCalls);
        Assert.Equal(0L, await lab.CountAsync("signing_requests"));
        Assert.Equal(1L, await lab.CountAsync("signing_rejections"));
    }

    [Fact]
    public async Task Global_rate_limit_is_audited_before_another_signature()
    {
        await using var lab = await HostLab.CreateAsync(fixture, rate: 1);
        using var client = lab.Pki.CreateClient(lab.Pki.Client);
        using var first = await client.PostAsJsonAsync(lab.Url + "/signing/inventory-refresh",
            new { requestId = Guid.NewGuid(), deviceId = lab.Device.Value });
        using var second = await client.PostAsJsonAsync(lab.Url + "/signing/inventory-refresh",
            new { requestId = Guid.NewGuid(), deviceId = lab.Device.Value });
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        Assert.Equal(HttpStatusCode.TooManyRequests, second.StatusCode);
        Assert.Equal(1, lab.TransitCalls);
        Assert.Equal(1L, await lab.CountAsync("signing_rejections"));
    }

    [Fact]
    public async Task Missing_result_permission_withholds_envelope_and_readiness_degrades()
    {
        await using var lab = await HostLab.CreateAsync(fixture);
        await lab.ExecuteOwnerAsync($"REVOKE INSERT ON signer.signing_results FROM {lab.Role}");
        using var client = lab.Pki.CreateClient(lab.Pki.Client);
        using var ready = await client.GetAsync(lab.Url + "/health/ready");
        Assert.Equal(HttpStatusCode.ServiceUnavailable, ready.StatusCode);
        using var response = await client.PostAsJsonAsync(lab.Url + "/signing/inventory-refresh",
            new { requestId = Guid.NewGuid(), deviceId = lab.Device.Value });
        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Equal(1L, await lab.CountAsync("signing_requests"));
        Assert.Equal(0L, await lab.CountAsync("signing_results"));
        Assert.Equal(1L, await lab.CountAsync("signing_rejections"));
        Assert.DoesNotContain("Password", await response.Content.ReadAsStringAsync(), StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("owner")]
    [InlineData("replication")]
    [InlineData("membership")]
    public async Task Startup_rejects_privileged_database_credentials(string kind)
    {
        await using var lab = await HostLab.CreateAsync(fixture);
        if (kind == "owner") { lab.Secrets.Write("signer-postgresql", fixture.ConnectionString); }
        else if (kind == "replication") { await lab.ExecuteOwnerAsync($"ALTER ROLE {lab.Role} REPLICATION"); }
        else { await lab.ExecuteOwnerAsync($"GRANT pg_read_all_data TO {lab.Role}"); }
        await using var unsafeApp = SigningHostApplication.Build(lab.Arguments());
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => unsafeApp.StartAsync());
        Assert.Contains("runtime permissions", error.Message);
        Assert.DoesNotContain(fixture.ConnectionString, error.ToString());
    }

    [Fact]
    public async Task Concurrency_limit_rejects_a_fifth_inflight_signature()
    {
        await using var lab = await HostLab.CreateAsync(fixture);
        lab.TransitRelease = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var client = lab.Pki.CreateClient(lab.Pki.Client);
        var calls = Enumerable.Range(0, 4).Select(_ => client.PostAsJsonAsync(lab.Url + "/signing/inventory-refresh",
            new { requestId = Guid.NewGuid(), deviceId = lab.Device.Value })).ToArray();
        try
        {
            await lab.FourTransitCalls.Task.WaitAsync(TimeSpan.FromSeconds(10));
            using var refused = await client.PostAsJsonAsync(lab.Url + "/signing/inventory-refresh",
                new { requestId = Guid.NewGuid(), deviceId = lab.Device.Value });
            Assert.Equal(HttpStatusCode.TooManyRequests, refused.StatusCode);
            Assert.Equal(4, lab.TransitCalls);
        }
        finally { lab.TransitRelease.TrySetResult(); }
        var responses = await Task.WhenAll(calls);
        foreach (var response in responses)
        {
            using (response) { Assert.Equal(HttpStatusCode.OK, response.StatusCode); }
        }
    }

    [Fact]
    public async Task Failed_rejection_audit_returns_unavailable_without_signing()
    {
        await using var lab = await HostLab.CreateAsync(fixture);
        await lab.ExecuteOwnerAsync($"REVOKE INSERT ON signer.signing_rejections FROM {lab.Role}");
        using var client = lab.Pki.CreateClient(lab.Pki.Client);
        using var response = await client.PostAsJsonAsync(lab.Url + "/signing/inventory-refresh", new { });
        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Equal(0, lab.TransitCalls);
        Assert.Equal(0L, await lab.CountAsync("signing_requests"));
        Assert.Equal(0L, await lab.CountAsync("signing_rejections"));
    }

    [Fact]
    public async Task Transit_failure_is_audited_and_keeps_the_request_pending()
    {
        await using var lab = await HostLab.CreateAsync(fixture);
        lab.TransitUnavailable = true;
        using var client = lab.Pki.CreateClient(lab.Pki.Client);
        using var response = await client.PostAsJsonAsync(lab.Url + "/signing/inventory-refresh",
            new { requestId = Guid.NewGuid(), deviceId = lab.Device.Value });
        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Equal(1L, await lab.CountAsync("signing_requests"));
        Assert.Equal(0L, await lab.CountAsync("signing_results"));
        Assert.Equal(1L, await lab.CountAsync("signing_rejections"));
    }

    [Theory]
    [InlineData("json")]
    [InlineData("null-caller")]
    [InlineData("private-key")]
    [InlineData("remote-database")]
    [InlineData("session-options")]
    public async Task Invalid_policy_and_database_settings_fail_without_secret_disclosure(string kind)
    {
        await using var lab = await HostLab.CreateAsync(fixture);
        switch (kind)
        {
            case "json": lab.Secrets.Write("signer-policy", "{broken"); break;
            case "null-caller": lab.Secrets.Write("signer-policy", "{\"rootsPem\":\"\",\"callers\":[null]}"); break;
            case "private-key": lab.Secrets.Write("signer-policy", "PRIVATE KEY disposable-private-sentinel"); break;
            case "remote-database": lab.Secrets.Write("signer-postgresql", "Host=remote.example;Username=signer;Password=disposable-private-sentinel"); break;
            case "session-options": lab.Secrets.Write("signer-postgresql", "Host=127.0.0.1;Options=-c role=untrusted"); break;
        }
        var error = Assert.Throws<InvalidOperationException>(() => SigningHostApplication.Build(lab.Arguments()));
        Assert.DoesNotContain("disposable-private-sentinel", error.ToString());
    }

    [Fact]
    public async Task Production_refuses_lab_http_transit_even_when_the_flag_is_supplied()
    {
        await using var lab = await HostLab.CreateAsync(fixture);
        Assert.Throws<ArgumentException>(() => SigningHostApplication.Build(
            [.. lab.Arguments(), "--environment=Production", "--Signer:Port=9443"]));
    }

    [Theory]
    [InlineData("--Signer:BindAddress=0.0.0.0")]
    [InlineData("--Signer:RequestsPerMinute=1000")]
    [InlineData("--Kestrel:Endpoints:Injected:Url=http://0.0.0.0:9999")]
    public async Task Unsafe_host_configuration_fails_before_listening(string argument)
    {
        await using var lab = await HostLab.CreateAsync(fixture);
        Assert.Throws<InvalidOperationException>(() => SigningHostApplication.Build([.. lab.Arguments(), argument]));
    }

    private sealed class HostLab : IAsyncDisposable
    {
        private readonly PostgreSqlTestFixture _fixture;
        private readonly string _password = Guid.NewGuid().ToString("N");
        private WebApplication? _transit;
        private WebApplication? _host;
        private string _transitUrl = "";
        private bool _operatorProvisioned;
        public DeviceId Device { get; } = new(Guid.NewGuid());
        public TestPki Pki { get; }
        public TestSecrets Secrets { get; } = new();
        public ECDsa Key { get; } = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        public string Role { get; } = "signer_host_" + Guid.NewGuid().ToString("N");
        public string OperatorRole => Role + "_operator";
        private int _transitCalls;
        public int TransitCalls => Volatile.Read(ref _transitCalls);
        public bool TransitUnavailable { get; set; }
        public TaskCompletionSource? TransitRelease { get; set; }
        public TaskCompletionSource FourTransitCalls { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource FirstTransitCall { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public string Url => Address(_host!);

        private HostLab(PostgreSqlTestFixture fixture)
        {
            _fixture = fixture;
            Pki = new TestPki(Device);
        }

        public static async Task<HostLab> CreateAsync(PostgreSqlTestFixture fixture, int rate = 30, bool replacement = false)
        {
            var lab = new HostLab(fixture);
            try { await lab.StartAsync(rate, replacement); return lab; }
            catch { await lab.DisposeAsync(); throw; }
        }

        private async Task StartAsync(int rate, bool replacement)
        {
            await ExecuteOwnerAsync(await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "provision-signing-journal.sql")));
            await ExecuteOwnerAsync($"""
                CREATE ROLE {Role} LOGIN PASSWORD '{_password}';
                GRANT CONNECT ON DATABASE {new NpgsqlConnectionStringBuilder(_fixture.ConnectionString).Database} TO {Role};
                GRANT USAGE ON SCHEMA signer TO {Role};
                GRANT SELECT, INSERT ON signer.signing_requests, signer.signing_results, signer.signing_rejections TO {Role};
                GRANT SELECT ON signer.client_certificate_revocations TO {Role};
                """);
            var settings = new NpgsqlConnectionStringBuilder(_fixture.ConnectionString)
            {
                Username = Role, Password = _password, Pooling = false
            };
            Secrets.Write("signer-postgresql", settings.ConnectionString);
            Secrets.Write("signer-server-ca", Pki.Root.ExportCertificatePem());
            Secrets.Write("signer-server-cert", Pki.ServerChainPem);
            Secrets.Write("signer-server-key", Pki.ServerKey.ExportPkcs8PrivateKeyPem());
            Secrets.Write("signer-transit-token", "disposable-host-token");
            Secrets.Write("signer-transit-public-key", Convert.ToBase64String(Key.ExportSubjectPublicKeyInfo()));
            Secrets.Write("signer-policy", JsonSerializer.Serialize(new
            {
                rootsPem = Pki.Root.ExportCertificatePem(), intermediatesPem = "",
                callers = (replacement ? new[] { Pki.Client, Pki.UnregisteredClient } : new[] { Pki.Client }).Select(certificate => new
                {
                    callerId = "approval-service", certificateSha256 = certificate.GetCertHashString(HashAlgorithmName.SHA256),
                    deviceIds = new[] { Device.Value }, notBefore = DateTimeOffset.UtcNow.AddMinutes(-1),
                    expiresAt = DateTimeOffset.UtcNow.AddMinutes(10)
                }).ToArray()
            }));
            var builder = WebApplication.CreateSlimBuilder();
            builder.Logging.ClearProviders();
            builder.WebHost.ConfigureKestrel(options => options.Listen(IPAddress.Loopback, 0));
            _transit = builder.Build();
            _transit.MapPost("/v1/transit/sign/test-key/sha2-256", async (Microsoft.AspNetCore.Http.HttpContext context) =>
            {
                Assert.Equal("disposable-host-token", context.Request.Headers["X-Vault-Token"]);
                if (Interlocked.Increment(ref _transitCalls) == 4) { FourTransitCalls.TrySetResult(); }
                FirstTransitCall.TrySetResult();
                if (TransitUnavailable) { return Microsoft.AspNetCore.Http.Results.StatusCode(503); }
                if (TransitRelease is not null) { await TransitRelease.Task.WaitAsync(context.RequestAborted); }
                using var body = await JsonDocument.ParseAsync(context.Request.Body);
                var bytes = Convert.FromBase64String(body.RootElement.GetProperty("input").GetString()!);
                byte[] signature;
                lock (Key) { signature = Key.SignData(bytes, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation); }
                return Microsoft.AspNetCore.Http.Results.Json(new { data = new { signature = "vault:v2:" + Convert.ToBase64String(signature) } });
            });
            await _transit.StartAsync();
            _transitUrl = Address(_transit);
            _host = SigningHostApplication.Build([.. Arguments(), $"--Signer:RequestsPerMinute={rate}"]);
            await _host.StartAsync();
        }

        public string[] Arguments() => ["--environment=Development", $"--Signer:SecretsDirectory={Secrets.Path}",
            "--Signer:Port=0", "--Signer:AllowLoopbackHttpTransit=true", $"--Signer:TransitAddress={_transitUrl}/",
            "--Signer:TransitKey=test-key", "--Signer:TransitKeyVersion=2"];

        public async Task ExecuteOwnerAsync(string sql)
        {
            await using var source = NpgsqlDataSource.Create(_fixture.ConnectionString);
            await using var command = source.CreateCommand(sql);
            await command.ExecuteNonQueryAsync();
        }

        public async Task ExecuteRuntimeAsync(string sql)
        {
            var settings = new NpgsqlConnectionStringBuilder(_fixture.ConnectionString)
            {
                Username = Role, Password = _password, Pooling = false
            };
            await using var source = NpgsqlDataSource.Create(settings.ConnectionString);
            await using var command = source.CreateCommand(sql);
            await command.ExecuteNonQueryAsync();
        }

        public async Task RevokeAsync(string? invalid = null)
        {
            if (!_operatorProvisioned)
            {
                await ExecuteOwnerAsync($"""
                    CREATE ROLE {OperatorRole} LOGIN PASSWORD '{_password}-operator';
                    GRANT CONNECT ON DATABASE {new NpgsqlConnectionStringBuilder(_fixture.ConnectionString).Database} TO {OperatorRole};
                    GRANT USAGE ON SCHEMA signer TO {OperatorRole};
                    GRANT SELECT ON signer.client_certificate_revocations TO {OperatorRole};
                    GRANT INSERT (certificate_sha256, incident_reference, operator_reference,
                                  approver_reference, evidence_sha256)
                        ON signer.client_certificate_revocations TO {OperatorRole};
                    """);
                _operatorProvisioned = true;
            }
            var fingerprint = Pki.Client.GetCertHashString(HashAlgorithmName.SHA256);
            var values = new[] { fingerprint, "INC-signer-test", "operator", "approver", new string('A', 64) };
            switch (invalid)
            {
                case "fingerprint": values[0] = "invalid"; break;
                case "evidence": values[4] = "invalid"; break;
                case "incident": values[1] = " "; break;
                case "operator": values[2] = ""; break;
                case "approver": values[3] = ""; break;
                case "same-actor": values[3] = " OPERATOR "; break;
                case "oversized": values[1] = new string('x', 129); break;
                case "control": values[1] = "INC\nforged"; break;
            }
            await using var source = CreateOperatorSource();
            await using var connection = await source.OpenConnectionAsync();
            await using var transaction = await connection.BeginTransactionAsync();
            await using var configure = new NpgsqlCommand("""
                SELECT set_config('synchronous_commit', 'off', true),
                       set_config('fleetory.signer_revoke.certificate_sha256', $1, true),
                       set_config('fleetory.signer_revoke.incident_reference', $2, true),
                       set_config('fleetory.signer_revoke.operator_reference', $3, true),
                       set_config('fleetory.signer_revoke.approver_reference', $4, true),
                       set_config('fleetory.signer_revoke.evidence_sha256', $5, true);
                """, connection, transaction);
            foreach (var value in values) { configure.Parameters.AddWithValue(value); }
            await configure.ExecuteNonQueryAsync();
            await using var revoke = new NpgsqlCommand(await File.ReadAllTextAsync(
                Path.Combine(AppContext.BaseDirectory, "revoke-signing-client.sql")), connection, transaction);
            await revoke.ExecuteNonQueryAsync();
            await using var sync = new NpgsqlCommand("SHOW synchronous_commit", connection, transaction);
            Assert.Equal("on", await sync.ExecuteScalarAsync());
            await transaction.CommitAsync();
        }

        public async Task ExecuteOperatorAsync(string sql)
        {
            await using var source = CreateOperatorSource();
            await using var command = source.CreateCommand(sql);
            await command.ExecuteNonQueryAsync();
        }

        private NpgsqlDataSource CreateOperatorSource() => NpgsqlDataSource.Create(
            new NpgsqlConnectionStringBuilder(_fixture.ConnectionString)
            {
                Username = OperatorRole, Password = _password + "-operator", Pooling = false
            }.ConnectionString);

        public async Task<long> CountAsync(string table)
        {
            // The table name is a test-owned constant, never an HTTP input.
            await using var source = NpgsqlDataSource.Create(_fixture.ConnectionString);
            await using var command = source.CreateCommand($"SELECT count(*) FROM signer.{table} WHERE " +
                (table == "signing_rejections" ? "client_certificate_sha256 = $1" :
                table == "signing_requests" ? "target_device_id = $1" :
                "request_id IN (SELECT request_id FROM signer.signing_requests WHERE target_device_id = $1)"));
            command.Parameters.AddWithValue(table == "signing_rejections" ?
                (object)Pki.Client.GetCertHashString(HashAlgorithmName.SHA256) : Device.Value);
            return (long)(await command.ExecuteScalarAsync())!;
        }

        private static string Address(WebApplication app) => app.Services.GetRequiredService<IServer>()
            .Features.Get<IServerAddressesFeature>()!.Addresses.Single();

        public async ValueTask DisposeAsync()
        {
            if (_host is not null) { await _host.DisposeAsync(); }
            if (_transit is not null) { await _transit.DisposeAsync(); }
            if (_operatorProvisioned) { await ExecuteOwnerAsync($"DROP OWNED BY {OperatorRole}; DROP ROLE {OperatorRole};"); }
            await ExecuteOwnerAsync($"DROP OWNED BY {Role}; DROP ROLE IF EXISTS {Role};");
            Key.Dispose(); Pki.Dispose(); Secrets.Dispose();
        }
    }
}
