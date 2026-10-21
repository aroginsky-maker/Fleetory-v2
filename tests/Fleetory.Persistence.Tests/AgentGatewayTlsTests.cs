using System.Data.Common;
using System.Net;
using System.Net.Http.Json;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Fleetory.Core.Contracts;
using Fleetory.Core.Persistence;
using Fleetory.Core.Security;
using Fleetory.Platform.Contracts;
using Fleetory.Server;
using Fleetory.SharedKernel;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;

namespace Fleetory.Persistence.Tests;

[Collection(PostgreSqlTestCollection.Name)]
public sealed class AgentGatewayTlsTests(PostgreSqlTestFixture fixture)
{
    private static readonly string[] ReadPermissions = ["Core.Device.Read"];
    private static readonly string[] WritePermissions = ["Core.Device.Write"];
    private static readonly string[] DuplicateReadPermissions =
        ["Core.Device.Read", "Core.Device.Read"];

    [Fact]
    public async Task Gateway_accepts_pinned_root_with_intermediate_server_chain()
    {
        using var pki = new TestPki(new DeviceId(Guid.NewGuid()),
            useIntermediate: true, omitLeafBasicConstraints: true);
        using var secrets = new TestSecretDirectory();
        secrets.Write("fleetory-postgresql", fixture.ConnectionString);
        secrets.Write("agent-gateway-root-ca", pki.Root.ExportCertificatePem());
        secrets.Write("agent-gateway-server-cert", pki.ServerChainPem);
        secrets.Write("agent-gateway-server-key", pki.ServerKey.ExportPkcs8PrivateKeyPem());

        var webPort = GetFreePort();
        var agentPort = GetFreePort();
        while (webPort == agentPort) { agentPort = GetFreePort(); }

        await using var app = FleetoryApplication.Build([
            "--environment=Development",
            $"--Fleetory:Secrets:Directory={secrets.Path}",
            "--Fleetory:AgentGateway:Enabled=true",
            $"--Fleetory:Web:Port={webPort}",
            $"--Fleetory:AgentGateway:Port={agentPort}"
        ]);
        await app.StartAsync();
        try
        {
            using var client = pki.CreateClient(pki.Client);
            using var response = await client.GetAsync($"https://127.0.0.1:{agentPort}/agent/identity");
            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        }
        finally
        {
            await app.StopAsync();
        }
    }

    [Fact]
    public async Task Agent_ca_rotation_accepts_both_roots_only_during_the_overlap()
    {
        var deviceId = new DeviceId(Guid.NewGuid());
        using var oldPki = new TestPki(deviceId);
        using var newPki = new TestPki(deviceId);
        using var foreignPki = new TestPki(deviceId);
        using var secrets = new TestSecretDirectory();
        secrets.Write("fleetory-postgresql", fixture.ConnectionString);
        secrets.Write("agent-gateway-root-ca",
            oldPki.Root.ExportCertificatePem() + "\n" + newPki.Root.ExportCertificatePem());
        secrets.Write("agent-gateway-server-cert", newPki.Server.ExportCertificatePem());
        secrets.Write("agent-gateway-server-key", newPki.ServerKey.ExportPkcs8PrivateKeyPem());

        await using (var scope = fixture.Services.CreateAsyncScope())
        {
            var database = scope.ServiceProvider.GetRequiredService<CoreDbContext>();
            database.Devices.Add(DeviceRecord.Create(deviceId, "CA rotation device", DateTimeOffset.UtcNow));
            foreach (var certificate in new[] { oldPki.Client, newPki.Client })
            {
                database.AgentCertificates.Add(AgentCertificateRecord.Create(deviceId,
                    CertificateSha256(certificate), certificate.NotBefore.ToUniversalTime(),
                    certificate.NotAfter.ToUniversalTime()));
            }
            await database.SaveChangesAsync();
        }

        var webPort = GetFreePort();
        var agentPort = GetFreePort();
        while (webPort == agentPort) { agentPort = GetFreePort(); }
        string[] settings = [
            "--environment=Development",
            $"--Fleetory:Secrets:Directory={secrets.Path}",
            "--Fleetory:AgentGateway:Enabled=true",
            $"--Fleetory:Web:Port={webPort}",
            $"--Fleetory:AgentGateway:Port={agentPort}"
        ];
        var identityUrl = $"https://127.0.0.1:{agentPort}/agent/identity";

        await using (var overlap = FleetoryApplication.Build(settings))
        {
            await overlap.StartAsync();
            try
            {
                using var oldClient = newPki.CreateClient(oldPki.Client);
                using var newClient = newPki.CreateClient(newPki.Client);
                using var foreignClient = newPki.CreateClient(foreignPki.Client);
                using var oldResponse = await oldClient.GetAsync(identityUrl);
                using var newResponse = await newClient.GetAsync(identityUrl);
                Assert.Equal(HttpStatusCode.NoContent, oldResponse.StatusCode);
                Assert.Equal(HttpStatusCode.NoContent, newResponse.StatusCode);
                await Assert.ThrowsAsync<HttpRequestException>(async () =>
                    await foreignClient.GetAsync(identityUrl));
            }
            finally { await overlap.StopAsync(); }
        }

        secrets.Write("agent-gateway-root-ca", newPki.Root.ExportCertificatePem());
        await using var retired = FleetoryApplication.Build(settings);
        await retired.StartAsync();
        try
        {
            using var newClient = newPki.CreateClient(newPki.Client);
            using var oldClient = newPki.CreateClient(oldPki.Client);
            using var newResponse = await newClient.GetAsync(identityUrl);
            Assert.Equal(HttpStatusCode.NoContent, newResponse.StatusCode);
            await Assert.ThrowsAsync<HttpRequestException>(async () =>
                await oldClient.GetAsync(identityUrl));
        }
        finally { await retired.StopAsync(); }
    }

    [Fact]
    public void Gateway_rejects_wrong_key_root_and_malformed_certificate_chain()
    {
        using var pki = new TestPki(new DeviceId(Guid.NewGuid()));
        using var foreignPki = new TestPki(new DeviceId(Guid.NewGuid()));
        using var secrets = new TestSecretDirectory();
        secrets.Write("fleetory-postgresql", fixture.ConnectionString);
        var rootPem = pki.Root.ExportCertificatePem();
        var serverPem = pki.Server.ExportCertificatePem();
        var serverKeyPem = pki.ServerKey.ExportPkcs8PrivateKeyPem();

        void AssertRejected(string root, string chain, string key)
        {
            secrets.Write("agent-gateway-root-ca", root);
            secrets.Write("agent-gateway-server-cert", chain);
            secrets.Write("agent-gateway-server-key", key);
            var exception = Assert.Throws<InvalidOperationException>(() =>
                FleetoryApplication.Build([
                    "--environment=Development",
                    $"--Fleetory:Secrets:Directory={secrets.Path}",
                    "--Fleetory:AgentGateway:Enabled=true",
                    "--Fleetory:Web:Port=45121",
                    "--Fleetory:AgentGateway:Port=45122"
                ]));
            Assert.Contains("Gateway TLS material is invalid", exception.Message,
                StringComparison.Ordinal);
            Assert.DoesNotContain(key, exception.ToString(), StringComparison.Ordinal);
        }

        AssertRejected(rootPem, serverPem, foreignPki.ServerKey.ExportPkcs8PrivateKeyPem());
        AssertRejected(foreignPki.Root.ExportCertificatePem(), serverPem, serverKeyPem);
        AssertRejected(rootPem, serverPem + pki.Client.ExportCertificatePem(), serverKeyPem);
        AssertRejected(rootPem, string.Concat(Enumerable.Repeat(serverPem, 5)), serverKeyPem);
        AssertRejected("not a certificate", serverPem, serverKeyPem);
        AssertRejected(rootPem + "\n" + rootPem, serverPem, serverKeyPem);
        AssertRejected(rootPem + "\n" + foreignPki.Root.ExportCertificatePem() + "\n" + rootPem,
            serverPem, serverKeyPem);
    }

    [Fact]
    public async Task Admin_gateway_limits_requests_before_repeated_authorization_work()
    {
        using var adminPki = new TestPki(
            new Uri($"urn:fleetory:admin:{Guid.NewGuid():D}"),
            new Uri($"urn:fleetory:admin:{Guid.NewGuid():D}"));
        using var secrets = new TestSecretDirectory();
        secrets.Write("fleetory-postgresql", fixture.ConnectionString);
        secrets.Write("admin-gateway-root-ca", adminPki.Root.ExportCertificatePem());
        secrets.Write("admin-gateway-server-cert", adminPki.Server.ExportCertificatePem());
        secrets.Write("admin-gateway-server-key", adminPki.ServerKey.ExportPkcs8PrivateKeyPem());

        var webPort = GetFreePort();
        var adminPort = GetFreePort();
        while (webPort == adminPort)
        {
            adminPort = GetFreePort();
        }

        await using var app = FleetoryApplication.Build([
            "--environment=Development",
            $"--Fleetory:Secrets:Directory={secrets.Path}",
            "--Fleetory:AdminGateway:Enabled=true",
            "--Fleetory:AdminGateway:RateLimitPerMinute=3",
            $"--Fleetory:Web:Port={webPort}",
            $"--Fleetory:AdminGateway:Port={adminPort}"
        ]);
        await app.StartAsync();
        try
        {
            using var admin = adminPki.CreateClient(adminPki.Client);
            using var otherAdmin = adminPki.CreateClient(adminPki.UnregisteredClient);
            using var web = new HttpClient();
            var url = $"https://127.0.0.1:{adminPort}/admin/devices/{Guid.NewGuid():D}/enrollment-grants";
            var enrollmentRequest = new
            {
                displayName = "denied",
                initialCertificateSha256 = new string('A', 64)
            };
            for (var attempt = 0; attempt < 4; attempt++)
            {
                using var webAttempt = await web.PostAsJsonAsync(
                    $"http://127.0.0.1:{webPort}/admin/devices/{Guid.NewGuid():D}/enrollment-grants",
                    new { displayName = "denied" });
                Assert.Equal(HttpStatusCode.NotFound, webAttempt.StatusCode);
            }

            for (var attempt = 0; attempt < 3; attempt++)
            {
                using var denied = await admin.PostAsJsonAsync(url, enrollmentRequest);
                Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);
            }

            using var limited = await admin.PostAsJsonAsync(url, enrollmentRequest);
            Assert.Equal(HttpStatusCode.TooManyRequests, limited.StatusCode);
            using var otherAllowed = await otherAdmin.PostAsJsonAsync(url,
                enrollmentRequest);
            Assert.Equal(HttpStatusCode.Forbidden, otherAllowed.StatusCode);
        }
        finally
        {
            await app.StopAsync();
        }
    }

    [Fact]
    public async Task Admin_gateway_with_oidc_rejects_certificate_without_mfa_token()
    {
        var adminId = Guid.NewGuid();
        using var adminPki = new TestPki(new Uri($"urn:fleetory:admin:{adminId:D}"));
        using var secrets = new TestSecretDirectory();
        secrets.Write("fleetory-postgresql", fixture.ConnectionString);
        secrets.Write("admin-gateway-root-ca", adminPki.Root.ExportCertificatePem());
        secrets.Write("admin-gateway-server-cert", adminPki.Server.ExportCertificatePem());
        secrets.Write("admin-gateway-server-key", adminPki.ServerKey.ExportPkcs8PrivateKeyPem());

        var webPort = GetFreePort();
        var adminPort = GetFreePort();
        while (webPort == adminPort) { adminPort = GetFreePort(); }

        await using var app = FleetoryApplication.Build([
            "--environment=Development",
            $"--Fleetory:Secrets:Directory={secrets.Path}",
            "--Fleetory:AdminGateway:Enabled=true",
            "--Fleetory:AdminGateway:Oidc:Enabled=true",
            "--Fleetory:AdminGateway:Oidc:Authority=http://127.0.0.1:1/realms/fleetory",
            "--Fleetory:AdminGateway:Oidc:Audience=fleetory-admin-api",
            "--Fleetory:AdminGateway:Oidc:ClientId=fleetory-admin-lab",
            $"--Fleetory:Web:Port={webPort}",
            $"--Fleetory:AdminGateway:Port={adminPort}"
        ]);
        await app.StartAsync();
        try
        {
            using var admin = adminPki.CreateClient(adminPki.Client);
            using var denied = await admin.PostAsJsonAsync(
                $"https://127.0.0.1:{adminPort}/admin/devices/{Guid.NewGuid():D}/enrollment-grants",
                new { displayName = "denied" });
            Assert.Equal(HttpStatusCode.Unauthorized, denied.StatusCode);
            var correlationId = Assert.Single(denied.Headers.GetValues("X-Correlation-ID"));
            await using var connection = new NpgsqlConnection(fixture.ConnectionString);
            await connection.OpenAsync();
            await using var audit = new NpgsqlCommand("""
                SELECT count(*) FROM platform.audit_events
                WHERE action = 'admin.oidc.denied'
                  AND actor_subject_id = @actor AND correlation_id = @correlation
                """, connection);
            audit.Parameters.AddWithValue("actor", $"person:{adminId:N}");
            audit.Parameters.AddWithValue("correlation", correlationId);
            Assert.Equal(1L, await audit.ExecuteScalarAsync());
        }
        finally
        {
            await app.StopAsync();
        }
    }

    [Fact]
    public async Task Enrollment_requires_durable_audit_before_grant_or_binding_changes()
    {
        var deviceId = new DeviceId(Guid.NewGuid());
        var adminId = Guid.NewGuid();
        var actor = new ActorReference($"person:{adminId:N}", ActorKind.Person);
        using var pki = new TestPki(deviceId);
        await GrantAdminPermissionAsync(adminId, AgentEnrollmentService.Permission);

        await using var scope = fixture.Services.CreateAsyncScope();
        var services = scope.ServiceProvider;
        var database = services.GetRequiredService<CoreDbContext>();
        var unavailableAudit = new AgentEnrollmentService(
            services.GetRequiredService<IAuthorizationService>(),
            new FailingAuditWriter(),
            services.GetRequiredService<IAgentCertificateBindingVerifier>(),
            database,
            services.GetRequiredService<IClock>());
        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await unavailableAudit.CreateGrantAsync(
                actor, deviceId, "audit test device", CorrelationId.New(),
                initialCertificateSha256: CertificateSha256(pki.Client)));
        Assert.False(await database.Devices.AnyAsync(row => row.DeviceId == deviceId));
        Assert.False(await database.AgentEnrollmentGrants.AnyAsync(row => row.DeviceId == deviceId));

        var completionAuditFailure = new AgentEnrollmentService(
            services.GetRequiredService<IAuthorizationService>(),
            new FailingTransactionalAuditWriter(services.GetRequiredService<IAuditWriter>()),
            services.GetRequiredService<IAgentCertificateBindingVerifier>(),
            database,
            services.GetRequiredService<IClock>());
        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await completionAuditFailure.CreateGrantAsync(
                actor, deviceId, "audit test device", CorrelationId.New(),
                initialCertificateSha256: CertificateSha256(pki.Client)));
        database.ChangeTracker.Clear();
        Assert.False(await database.Devices.AnyAsync(row => row.DeviceId == deviceId));
        Assert.False(await database.AgentEnrollmentGrants.AnyAsync(row => row.DeviceId == deviceId));

        var service = services.GetRequiredService<AgentEnrollmentService>();
        var token = await service.CreateGrantAsync(
            actor, deviceId, "audit test device", CorrelationId.New(),
            initialCertificateSha256: CertificateSha256(pki.Client));
        var tokenHash = Convert.ToHexString(SHA256.HashData(
            System.Text.Encoding.ASCII.GetBytes(token)));
        await database.AgentEnrollmentGrants
            .Where(row => row.TokenSha256 == tokenHash)
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(row => row.ReplacementCertificateSha256, (string?)null));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(async () =>
            await service.EnrollAsync(deviceId, pki.Client, token, CorrelationId.New()));
        Assert.True(await database.AgentEnrollmentGrants.AsNoTracking().AnyAsync(
            row => row.TokenSha256 == tokenHash && row.ConsumedAt == null));
        await database.AgentEnrollmentGrants
            .Where(row => row.TokenSha256 == tokenHash)
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(row => row.ReplacementCertificateSha256,
                    CertificateSha256(pki.Client)));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(async () =>
            await service.EnrollAsync(new DeviceId(Guid.NewGuid()), pki.Client,
                token, CorrelationId.New()));
        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await unavailableAudit.EnrollAsync(deviceId, pki.Client,
                token, CorrelationId.New()));
        Assert.False(await database.AgentCertificates.AnyAsync(row => row.DeviceId == deviceId));
        Assert.True(await database.AgentEnrollmentGrants.AnyAsync(
            row => row.DeviceId == deviceId && row.ConsumedAt == null));

        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await completionAuditFailure.EnrollAsync(deviceId, pki.Client,
                token, CorrelationId.New()));
        database.ChangeTracker.Clear();
        Assert.False(await database.AgentCertificates.AnyAsync(row => row.DeviceId == deviceId));
        Assert.True(await database.AgentEnrollmentGrants.AnyAsync(
            row => row.DeviceId == deviceId && row.ConsumedAt == null));

        await service.EnrollAsync(deviceId, pki.Client, token, CorrelationId.New());
        Assert.True(await database.AgentCertificates.AnyAsync(row => row.DeviceId == deviceId));

        var replacementFingerprint = Convert.ToHexString(
            SHA256.HashData(pki.UnregisteredClient.RawData));
        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await unavailableAudit.CreateRotationIntentAsync(deviceId, pki.Client,
                replacementFingerprint, CorrelationId.New()));
        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await completionAuditFailure.CreateRotationIntentAsync(deviceId, pki.Client,
                replacementFingerprint, CorrelationId.New()));
        database.ChangeTracker.Clear();
        Assert.False(await database.AgentRotationIntents.AnyAsync(
            row => row.DeviceId == deviceId));
    }

    [Fact]
    public async Task Stale_initial_grant_cannot_bind_a_second_certificate_without_explicit_rotation()
    {
        var deviceId = new DeviceId(Guid.NewGuid());
        var adminId = Guid.NewGuid();
        var actor = new ActorReference($"person:{adminId:N}", ActorKind.Person);
        using var pki = new TestPki(deviceId);
        await GrantAdminPermissionAsync(adminId, AgentEnrollmentService.Permission);

        await using var scope = fixture.Services.CreateAsyncScope();
        var services = scope.ServiceProvider;
        var service = services.GetRequiredService<AgentEnrollmentService>();
        var database = services.GetRequiredService<CoreDbContext>();
        var firstToken = await service.CreateGrantAsync(
            actor, deviceId, "collision device", CorrelationId.New(),
            initialCertificateSha256: CertificateSha256(pki.Client));
        var staleToken = await service.CreateGrantAsync(
            actor, deviceId, "collision device", CorrelationId.New(),
            initialCertificateSha256: CertificateSha256(pki.UnregisteredClient));

        await service.EnrollAsync(deviceId, pki.Client, firstToken, CorrelationId.New());
        var rejectedCorrelation = CorrelationId.New();
        await Assert.ThrowsAsync<UnauthorizedAccessException>(async () =>
            await service.EnrollAsync(deviceId, pki.UnregisteredClient,
                staleToken, rejectedCorrelation));
        Assert.Equal(1, await database.AgentCertificates.CountAsync(row => row.DeviceId == deviceId));
        var staleHash = Convert.ToHexString(SHA256.HashData(
            System.Text.Encoding.ASCII.GetBytes(staleToken)));
        Assert.True(await database.AgentEnrollmentGrants.AsNoTracking().AnyAsync(
            row => row.TokenSha256 == staleHash && row.ConsumedAt == null));

        Assert.Equal(1, await CountAuditActionAsync(
            rejectedCorrelation, "core.agent_enrollment.denied_collision"));

        var grantCollisionCorrelation = CorrelationId.New();
        await Assert.ThrowsAsync<AgentEnrollmentConflictException>(async () =>
            await service.CreateGrantAsync(actor, deviceId, "collision device",
                grantCollisionCorrelation,
                initialCertificateSha256: CertificateSha256(pki.Client)));
        await Assert.ThrowsAsync<AgentEnrollmentConflictException>(async () =>
            await service.CreateGrantAsync(actor, deviceId, "collision device", CorrelationId.New(),
                expectedCertificateSha256: new string('A', 64)));

        Assert.Equal(1, await CountAuditActionAsync(
            grantCollisionCorrelation, "core.agent_enrollment.grant_collision"));

        var fingerprint = Convert.ToHexString(SHA256.HashData(pki.Client.RawData));
        var deniedRotationCorrelation = CorrelationId.New();
        await Assert.ThrowsAsync<UnauthorizedAccessException>(async () =>
            await service.CreateGrantAsync(actor, deviceId, "collision device",
                deniedRotationCorrelation, expectedCertificateSha256: fingerprint));
        Assert.Equal(1, await CountAuditActionAsync(
            deniedRotationCorrelation, "core.agent_enrollment.grant_rotation_denied"));
        Assert.Equal(2, await database.AgentEnrollmentGrants.CountAsync(
            row => row.DeviceId == deviceId));

        await GrantAdminPermissionAsync(adminId, AgentEnrollmentService.RotationPermission);
        var missingIntentCorrelation = CorrelationId.New();
        await Assert.ThrowsAsync<AgentRotationIntentException>(async () =>
            await service.CreateGrantAsync(actor, deviceId, "collision device",
                missingIntentCorrelation, expectedCertificateSha256: fingerprint));
        Assert.Equal(1, await CountAuditActionAsync(missingIntentCorrelation,
            "core.agent_enrollment.grant_rotation_intent_denied"));

        var replacementFingerprint = Convert.ToHexString(
            SHA256.HashData(pki.UnregisteredClient.RawData));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(async () =>
            await service.CreateRotationIntentAsync(deviceId, pki.UnregisteredClient,
                replacementFingerprint, CorrelationId.New()));
        var expiredIntentId = await service.CreateRotationIntentAsync(
            deviceId, pki.Client, replacementFingerprint, CorrelationId.New());
        await database.AgentRotationIntents
            .Where(row => row.IntentId == expiredIntentId)
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(row => row.ExpiresAt, DateTimeOffset.UtcNow.AddMinutes(-1)));
        await Assert.ThrowsAsync<AgentRotationIntentException>(async () =>
            await service.CreateGrantAsync(actor, deviceId, "collision device",
                CorrelationId.New(), expectedCertificateSha256: fingerprint,
                rotationIntentId: expiredIntentId));
        var intentId = await service.CreateRotationIntentAsync(
            deviceId, pki.Client, replacementFingerprint, CorrelationId.New());
        var failedGrantService = new AgentEnrollmentService(
            services.GetRequiredService<IAuthorizationService>(),
            new FailingTransactionalAuditWriter(services.GetRequiredService<IAuditWriter>()),
            services.GetRequiredService<IAgentCertificateBindingVerifier>(), database,
            services.GetRequiredService<IClock>());
        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await failedGrantService.CreateGrantAsync(actor, deviceId, "collision device",
                CorrelationId.New(), expectedCertificateSha256: fingerprint,
                rotationIntentId: intentId));
        database.ChangeTracker.Clear();
        Assert.True(await database.AgentRotationIntents.AsNoTracking().AnyAsync(
            row => row.IntentId == intentId && row.ClaimedAt == null));
        var rotationToken = await service.CreateGrantAsync(
            actor, deviceId, "collision device", CorrelationId.New(),
            expectedCertificateSha256: fingerprint, rotationIntentId: intentId);
        await Assert.ThrowsAsync<AgentRotationIntentException>(async () =>
            await service.CreateGrantAsync(actor, deviceId, "collision device",
                CorrelationId.New(), expectedCertificateSha256: fingerprint,
                rotationIntentId: intentId));
        var mismatchCorrelation = CorrelationId.New();
        await Assert.ThrowsAsync<UnauthorizedAccessException>(async () =>
            await service.EnrollAsync(deviceId, pki.Client,
                rotationToken, mismatchCorrelation));
        Assert.Equal(1, await CountAuditActionAsync(mismatchCorrelation,
            "core.agent_enrollment.denied_replacement_mismatch"));
        await service.EnrollAsync(deviceId, pki.UnregisteredClient,
            rotationToken, CorrelationId.New());
        Assert.Equal(2, await database.AgentCertificates.CountAsync(row => row.DeviceId == deviceId));

        var pendingIntentId = await service.CreateRotationIntentAsync(
            deviceId, pki.Client, replacementFingerprint, CorrelationId.New());
        var pendingToken = await service.CreateGrantAsync(
            actor, deviceId, "collision device", CorrelationId.New(),
            expectedCertificateSha256: fingerprint, rotationIntentId: pendingIntentId);
        var revokedIntentId = await service.CreateRotationIntentAsync(
            deviceId, pki.Client, replacementFingerprint, CorrelationId.New());
        await GrantAdminPermissionAsync(adminId, AgentCertificateRevocationService.Permission);
        await services.GetRequiredService<AgentCertificateRevocationService>()
            .RevokeAsync(actor, deviceId, fingerprint, CorrelationId.New());
        await Assert.ThrowsAsync<UnauthorizedAccessException>(async () =>
            await service.EnrollAsync(deviceId, pki.UnregisteredClient,
                pendingToken, CorrelationId.New()));
        await Assert.ThrowsAsync<AgentEnrollmentConflictException>(async () =>
            await service.CreateGrantAsync(actor, deviceId, "collision device",
                CorrelationId.New(), expectedCertificateSha256: fingerprint,
                rotationIntentId: revokedIntentId));
    }

    [Fact]
    public async Task Lost_key_recovery_requires_separate_approver_and_rolls_back_on_audit_failure()
    {
        var deviceId = new DeviceId(Guid.NewGuid());
        var requesterId = Guid.NewGuid();
        var approverId = Guid.NewGuid();
        var requester = new ActorReference($"person:{requesterId:N}", ActorKind.Person);
        var approver = new ActorReference($"person:{approverId:N}", ActorKind.Person);
        using var pki = new TestPki(deviceId);
        var oldFingerprint = Convert.ToHexString(SHA256.HashData(pki.Client.RawData));
        var newFingerprint = Convert.ToHexString(SHA256.HashData(pki.UnregisteredClient.RawData));
        var evidenceHash = new string('B', 64);
        const string incident = "INC-2026-10-18-01";
        await GrantAdminPermissionAsync(requesterId, AgentEnrollmentService.Permission);

        await using var scope = fixture.Services.CreateAsyncScope();
        var services = scope.ServiceProvider;
        var database = services.GetRequiredService<CoreDbContext>();
        var enrollment = services.GetRequiredService<AgentEnrollmentService>();
        var recovery = services.GetRequiredService<AgentCertificateRecoveryService>();
        var initialToken = await enrollment.CreateGrantAsync(
            requester, deviceId, "recovery device", CorrelationId.New(),
            initialCertificateSha256: oldFingerprint);
        await enrollment.EnrollAsync(deviceId, pki.Client, initialToken, CorrelationId.New());

        var deniedCorrelation = CorrelationId.New();
        await Assert.ThrowsAsync<UnauthorizedAccessException>(async () =>
            await recovery.RequestAsync(requester, deviceId, oldFingerprint,
                newFingerprint, evidenceHash, incident, deniedCorrelation));
        Assert.Equal(1, await CountAuditActionAsync(deniedCorrelation,
            "core.agent_certificate.recovery_denied"));

        await GrantAdminPermissionAsync(requesterId,
            AgentCertificateRecoveryService.RequestPermission);
        var failedRequestRecovery = new AgentCertificateRecoveryService(
            services.GetRequiredService<IAuthorizationService>(),
            new FailingTransactionalAuditWriter(services.GetRequiredService<IAuditWriter>()),
            database, services.GetRequiredService<IClock>());
        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await failedRequestRecovery.RequestAsync(requester, deviceId,
                oldFingerprint, newFingerprint, evidenceHash, incident,
                CorrelationId.New()));
        database.ChangeTracker.Clear();
        Assert.False(await database.AgentCertificateRecoveries.AsNoTracking().AnyAsync(
            row => row.DeviceId == deviceId));

        var expiredRecoveryId = await recovery.RequestAsync(requester, deviceId,
            oldFingerprint, newFingerprint, evidenceHash, incident,
            CorrelationId.New());
        await database.AgentCertificateRecoveries
            .Where(row => row.RecoveryId == expiredRecoveryId)
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(row => row.ExpiresAt, DateTimeOffset.UtcNow.AddMinutes(-1)));
        var recoveryId = await recovery.RequestAsync(requester, deviceId,
            oldFingerprint, newFingerprint, evidenceHash, incident,
            CorrelationId.New());
        await Assert.ThrowsAsync<AgentRecoveryConflictException>(async () =>
            await recovery.RequestAsync(requester, deviceId, oldFingerprint,
                newFingerprint, evidenceHash, incident, CorrelationId.New()));

        await GrantAdminPermissionAsync(requesterId,
            AgentCertificateRecoveryService.ApprovePermission);
        var sameActorCorrelation = CorrelationId.New();
        await Assert.ThrowsAsync<UnauthorizedAccessException>(async () =>
            await recovery.ApproveAsync(requester, deviceId, recoveryId,
                newFingerprint, evidenceHash, incident, sameActorCorrelation));
        Assert.Equal(1, await CountAuditActionAsync(sameActorCorrelation,
            "core.agent_certificate.recovery_approval_denied"));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(async () =>
            await recovery.ApproveAsync(approver, deviceId, recoveryId,
                newFingerprint, evidenceHash, incident, CorrelationId.New()));

        await GrantAdminPermissionAsync(approverId,
            AgentCertificateRecoveryService.ApprovePermission);
        await Assert.ThrowsAsync<AgentRecoveryConflictException>(async () =>
            await recovery.ApproveAsync(approver, deviceId, expiredRecoveryId,
                newFingerprint, evidenceHash, incident, CorrelationId.New()));
        await Assert.ThrowsAsync<AgentRecoveryConflictException>(async () =>
            await recovery.ApproveAsync(approver, deviceId, recoveryId,
                newFingerprint, new string('C', 64), incident,
                CorrelationId.New()));

        var failedAuditRecovery = new AgentCertificateRecoveryService(
            services.GetRequiredService<IAuthorizationService>(),
            new FailingTransactionalAuditWriter(services.GetRequiredService<IAuditWriter>()),
            database, services.GetRequiredService<IClock>());
        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await failedAuditRecovery.ApproveAsync(approver, deviceId, recoveryId,
                newFingerprint, evidenceHash, incident, CorrelationId.New()));
        database.ChangeTracker.Clear();
        Assert.True(await database.AgentCertificates.AsNoTracking().AnyAsync(
            row => row.DeviceId == deviceId && row.CertificateSha256 == oldFingerprint &&
                row.RevokedAt == null));
        Assert.True(await database.AgentCertificateRecoveries.AsNoTracking().AnyAsync(
            row => row.RecoveryId == recoveryId && row.ApprovedAt == null));
        Assert.False(await database.AgentEnrollmentGrants.AsNoTracking().AnyAsync(
            row => row.RecoveryRequestId == recoveryId));

        var token = await recovery.ApproveAsync(approver, deviceId, recoveryId,
            newFingerprint, evidenceHash, incident, CorrelationId.New());
        await Assert.ThrowsAsync<AgentRecoveryConflictException>(async () =>
            await recovery.RequestAsync(requester, deviceId, oldFingerprint,
                newFingerprint, evidenceHash, incident, CorrelationId.New()));
        Assert.True(await database.AgentCertificates.AsNoTracking().AnyAsync(
            row => row.DeviceId == deviceId && row.CertificateSha256 == oldFingerprint &&
                row.RevokedAt != null));
        Assert.True(await database.AgentCertificateRecoveries.AsNoTracking().AnyAsync(
            row => row.RecoveryId == recoveryId &&
                row.ApproverSubjectId == approver.SubjectId));
        await Assert.ThrowsAsync<AgentRecoveryConflictException>(async () =>
            await recovery.ApproveAsync(approver, deviceId, recoveryId,
                newFingerprint, evidenceHash, incident, CorrelationId.New()));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(async () =>
            await enrollment.EnrollAsync(deviceId, pki.Client,
                token, CorrelationId.New()));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(async () =>
            await enrollment.EnrollAsync(deviceId, pki.RecoveryClient,
                token, CorrelationId.New()));
        Assert.True(await database.AgentEnrollmentGrants.AsNoTracking().AnyAsync(
            row => row.RecoveryRequestId == recoveryId && row.ConsumedAt == null));
        await enrollment.EnrollAsync(deviceId, pki.UnregisteredClient,
            token, CorrelationId.New());
        Assert.Equal(2, await database.AgentCertificates.CountAsync(
            row => row.DeviceId == deviceId));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(async () =>
            await enrollment.EnrollAsync(deviceId, pki.UnregisteredClient,
                token, CorrelationId.New()));
    }

    [Fact]
    public async Task Concurrent_initial_grants_cannot_bind_two_certificates_to_one_device()
    {
        var deviceId = new DeviceId(Guid.NewGuid());
        var adminId = Guid.NewGuid();
        using var pki = new TestPki(deviceId);
        await GrantAdminPermissionAsync(adminId, AgentEnrollmentService.Permission);
        var actor = new ActorReference($"person:{adminId:N}", ActorKind.Person);
        string firstToken;
        string secondToken;
        await using (var scope = fixture.Services.CreateAsyncScope())
        {
            var service = scope.ServiceProvider.GetRequiredService<AgentEnrollmentService>();
            firstToken = await service.CreateGrantAsync(actor, deviceId,
                "parallel identity", CorrelationId.New(),
                initialCertificateSha256: CertificateSha256(pki.Client));
            secondToken = await service.CreateGrantAsync(actor, deviceId,
                "parallel identity", CorrelationId.New(),
                initialCertificateSha256: CertificateSha256(pki.UnregisteredClient));
        }

        async Task<bool> TryEnrollAsync(X509Certificate2 certificate, string grantToken)
        {
            await using var scope = fixture.Services.CreateAsyncScope();
            try
            {
                await scope.ServiceProvider.GetRequiredService<AgentEnrollmentService>()
                    .EnrollAsync(deviceId, certificate, grantToken, CorrelationId.New());
                return true;
            }
            catch (UnauthorizedAccessException)
            {
                return false;
            }
        }

        var results = await Task.WhenAll(
            TryEnrollAsync(pki.Client, firstToken),
            TryEnrollAsync(pki.UnregisteredClient, secondToken));
        Assert.Equal(1, results.Count(success => success));
        await using var verificationScope = fixture.Services.CreateAsyncScope();
        var database = verificationScope.ServiceProvider.GetRequiredService<CoreDbContext>();
        Assert.Equal(1, await database.AgentCertificates.CountAsync(row => row.DeviceId == deviceId));
        Assert.Equal(1, await database.AgentEnrollmentGrants.CountAsync(
            row => row.DeviceId == deviceId && row.ConsumedAt != null));
    }

    [Fact]
    public async Task Concurrent_redemption_of_one_grant_binds_only_one_certificate()
    {
        var deviceId = new DeviceId(Guid.NewGuid());
        var adminId = Guid.NewGuid();
        using var pki = new TestPki(deviceId);
        await GrantAdminPermissionAsync(adminId, AgentEnrollmentService.Permission);
        string token;
        await using (var scope = fixture.Services.CreateAsyncScope())
        {
            token = await scope.ServiceProvider.GetRequiredService<AgentEnrollmentService>()
                .CreateGrantAsync(new ActorReference($"person:{adminId:N}", ActorKind.Person),
                    deviceId, "concurrent device", CorrelationId.New(),
                    initialCertificateSha256: CertificateSha256(pki.Client));
        }

        async Task<bool> TryEnrollAsync(X509Certificate2 certificate)
        {
            await using var scope = fixture.Services.CreateAsyncScope();
            try
            {
                await scope.ServiceProvider.GetRequiredService<AgentEnrollmentService>()
                    .EnrollAsync(deviceId, certificate, token, CorrelationId.New());
                return true;
            }
            catch (UnauthorizedAccessException)
            {
                return false;
            }
        }

        var results = await Task.WhenAll(
            TryEnrollAsync(pki.Client), TryEnrollAsync(pki.UnregisteredClient));
        Assert.Equal(1, results.Count(success => success));
        await using var verificationScope = fixture.Services.CreateAsyncScope();
        var database = verificationScope.ServiceProvider.GetRequiredService<CoreDbContext>();
        Assert.Equal(1, await database.AgentCertificates.CountAsync(row => row.DeviceId == deviceId));
    }

    [Fact]
    public async Task One_time_admin_grant_enrolls_only_the_agent_presenting_its_certificate()
    {
        var deviceId = new DeviceId(Guid.NewGuid());
        var adminId = Guid.NewGuid();
        var recoveryApproverId = Guid.NewGuid();
        using var agentPki = new TestPki(deviceId);
        using var adminPki = new TestPki(
            new Uri($"urn:fleetory:admin:{adminId:D}"),
            new Uri($"urn:fleetory:admin:{recoveryApproverId:D}"));
        using var secrets = new TestSecretDirectory();
        secrets.Write("fleetory-postgresql", fixture.ConnectionString);
        secrets.Write("agent-gateway-root-ca", agentPki.Root.ExportCertificatePem());
        secrets.Write("agent-gateway-server-cert", agentPki.Server.ExportCertificatePem());
        secrets.Write("agent-gateway-server-key", agentPki.ServerKey.ExportPkcs8PrivateKeyPem());
        secrets.Write("admin-gateway-root-ca", adminPki.Root.ExportCertificatePem());
        secrets.Write("admin-gateway-server-cert", adminPki.Server.ExportCertificatePem());
        secrets.Write("admin-gateway-server-key", adminPki.ServerKey.ExportPkcs8PrivateKeyPem());

        var ports = Enumerable.Range(0, 3).Select(_ => GetFreePort()).ToArray();
        while (ports.Distinct().Count() != ports.Length)
        {
            ports = Enumerable.Range(0, 3).Select(_ => GetFreePort()).ToArray();
        }

        await using var app = FleetoryApplication.Build([
            "--environment=Development",
            $"--Fleetory:Secrets:Directory={secrets.Path}",
            "--Fleetory:AgentGateway:Enabled=true",
            "--Fleetory:AgentGateway:RotationIntentRateLimitPerMinute=2",
            "--Fleetory:AgentGateway:EnrollmentRateLimitPerMinute=3",
            "--Fleetory:AdminGateway:Enabled=true",
            $"--Fleetory:Web:Port={ports[0]}",
            $"--Fleetory:AgentGateway:Port={ports[1]}",
            $"--Fleetory:AdminGateway:Port={ports[2]}"
        ]);
        await app.StartAsync();
        try
        {
            using var agent = agentPki.CreateClient(agentPki.Client);
            using var admin = adminPki.CreateClient(adminPki.Client);
            using var recoveryApprover = adminPki.CreateClient(adminPki.UnregisteredClient);
            using var web = new HttpClient();
            var agentBase = $"https://127.0.0.1:{ports[1]}";
            var grantUrl = $"https://127.0.0.1:{ports[2]}/admin/devices/{deviceId.Value:D}/enrollment-grants";
            var initialFingerprint = CertificateSha256(agentPki.Client);

            using var before = await agent.GetAsync($"{agentBase}/agent/identity");
            Assert.Equal(HttpStatusCode.Forbidden, before.StatusCode);
            using var noGrant = await agent.PostAsJsonAsync(
                $"{agentBase}/agent/enroll", new { token = new string('A', 64) });
            Assert.Equal(HttpStatusCode.Forbidden, noGrant.StatusCode);
            using var denied = await admin.PostAsJsonAsync(grantUrl, new
            {
                displayName = "enrolled device",
                initialCertificateSha256 = initialFingerprint
            });
            Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);

            await GrantAdminPermissionAsync(adminId, AgentEnrollmentService.Permission);
            using var invalidBody = await admin.PostAsync(grantUrl,
                new StringContent("not json"));
            Assert.Equal(HttpStatusCode.BadRequest, invalidBody.StatusCode);
            using var oversized = await admin.PostAsJsonAsync(grantUrl,
                new { displayName = new string('x', 2048) });
            Assert.Equal(HttpStatusCode.BadRequest, oversized.StatusCode);
            using var missingFingerprint = await admin.PostAsJsonAsync(grantUrl,
                new { displayName = "enrolled device" });
            Assert.Equal(HttpStatusCode.BadRequest, missingFingerprint.StatusCode);
            using var grant = await admin.PostAsJsonAsync(grantUrl, new
            {
                displayName = "enrolled device",
                initialCertificateSha256 = initialFingerprint
            });
            Assert.Equal(HttpStatusCode.OK, grant.StatusCode);
            Assert.Equal("no-store", grant.Headers.CacheControl?.ToString());
            var response = await grant.Content.ReadFromJsonAsync<System.Text.Json.JsonElement>();
            var token = response.GetProperty("token").GetString();
            Assert.NotNull(token);
            Assert.Equal(64, token.Length);

            for (var attempt = 0; attempt < 4; attempt++)
            {
                using var webAttempt = await web.PostAsJsonAsync(
                    $"http://127.0.0.1:{ports[0]}/agent/enroll", new { token });
                Assert.Equal(HttpStatusCode.NotFound, webAttempt.StatusCode);
            }
            using var malformedIdentity = agentPki.CreateClient(agentPki.MalformedIdentityClient);
            using var malformed = await malformedIdentity.PostAsJsonAsync(
                $"{agentBase}/agent/enroll", new { token });
            Assert.Equal(HttpStatusCode.Forbidden, malformed.StatusCode);
            using var wrongInitialCertificate = agentPki.CreateClient(agentPki.UnregisteredClient);
            using var wrongInitial = await wrongInitialCertificate.PostAsJsonAsync(
                $"{agentBase}/agent/enroll", new { token });
            Assert.Equal(HttpStatusCode.Forbidden, wrongInitial.StatusCode);
            using var enrolled = await agent.PostAsJsonAsync($"{agentBase}/agent/enroll", new { token });
            Assert.Equal(HttpStatusCode.NoContent, enrolled.StatusCode);
            using var identity = await agent.GetAsync($"{agentBase}/agent/identity");
            Assert.Equal(HttpStatusCode.NoContent, identity.StatusCode);
            using var replay = await agent.PostAsJsonAsync($"{agentBase}/agent/enroll", new { token });
            Assert.Equal(HttpStatusCode.Forbidden, replay.StatusCode);
            using var limitedEnrollment = await agent.PostAsJsonAsync(
                $"{agentBase}/agent/enroll", new { token });
            Assert.Equal(HttpStatusCode.TooManyRequests, limitedEnrollment.StatusCode);
            using var identityAfterLimit = await agent.GetAsync($"{agentBase}/agent/identity");
            Assert.Equal(HttpStatusCode.NoContent, identityAfterLimit.StatusCode);

            var currentFingerprint = Convert.ToHexString(SHA256.HashData(agentPki.Client.RawData));
            using var collision = await admin.PostAsJsonAsync(grantUrl, new
            {
                displayName = "ignored for existing device",
                initialCertificateSha256 = initialFingerprint
            });
            Assert.Equal(HttpStatusCode.Conflict, collision.StatusCode);
            using var wrongBinding = await admin.PostAsJsonAsync(
                grantUrl, new
                {
                    displayName = "ignored for existing device",
                    expectedCertificateSha256 = new string('A', 64)
                });
            Assert.Equal(HttpStatusCode.Conflict, wrongBinding.StatusCode);

            using var candidate = agentPki.CreateClient(agentPki.UnregisteredClient);
            var replacementFingerprint = Convert.ToHexString(
                SHA256.HashData(agentPki.UnregisteredClient.RawData));
            var intentUrl = $"{agentBase}/agent/rotation-intents";
            using var unboundIntent = await candidate.PostAsJsonAsync(intentUrl,
                new { replacementCertificateSha256 = replacementFingerprint });
            Assert.Equal(HttpStatusCode.Forbidden, unboundIntent.StatusCode);
            using var intentResponse = await agent.PostAsJsonAsync(intentUrl,
                new { replacementCertificateSha256 = replacementFingerprint });
            Assert.Equal(HttpStatusCode.OK, intentResponse.StatusCode);
            Assert.Equal("no-store", intentResponse.Headers.CacheControl?.ToString());
            var intentBody = await intentResponse.Content
                .ReadFromJsonAsync<System.Text.Json.JsonElement>();
            var intentId = intentBody.GetProperty("intentId").GetGuid();
            var rotationRequest = new
            {
                displayName = "ignored for existing device",
                expectedCertificateSha256 = currentFingerprint,
                rotationIntentId = intentId
            };
            using var rotationDenied = await admin.PostAsJsonAsync(grantUrl, rotationRequest);
            Assert.Equal(HttpStatusCode.Forbidden, rotationDenied.StatusCode);
            await GrantAdminPermissionAsync(adminId, AgentEnrollmentService.RotationPermission);
            using var expiringGrant = await admin.PostAsJsonAsync(
                grantUrl, rotationRequest);
            Assert.Equal(HttpStatusCode.OK, expiringGrant.StatusCode);
            var expiringResponse = await expiringGrant.Content
                .ReadFromJsonAsync<System.Text.Json.JsonElement>();
            var expiringToken = expiringResponse.GetProperty("token").GetString();
            Assert.NotNull(expiringToken);
            var expiringHash = Convert.ToHexString(SHA256.HashData(
                System.Text.Encoding.ASCII.GetBytes(expiringToken)));
            await using (var expiryScope = fixture.Services.CreateAsyncScope())
            {
                var expiryDatabase = expiryScope.ServiceProvider.GetRequiredService<CoreDbContext>();
                await expiryDatabase.AgentEnrollmentGrants
                    .Where(row => row.TokenSha256 == expiringHash)
                    .ExecuteUpdateAsync(setters => setters
                        .SetProperty(row => row.ExpiresAt, DateTimeOffset.UtcNow.AddMinutes(-1)));
            }

            using var expired = await candidate.PostAsJsonAsync(
                $"{agentBase}/agent/enroll", new { token = expiringToken });
            Assert.Equal(HttpStatusCode.Forbidden, expired.StatusCode);
            using var replayedIntent = await admin.PostAsJsonAsync(grantUrl, rotationRequest);
            Assert.Equal(HttpStatusCode.Conflict, replayedIntent.StatusCode);
            using var renewedIntent = await agent.PostAsJsonAsync(intentUrl,
                new { replacementCertificateSha256 = replacementFingerprint });
            Assert.Equal(HttpStatusCode.OK, renewedIntent.StatusCode);
            var renewedIntentBody = await renewedIntent.Content
                .ReadFromJsonAsync<System.Text.Json.JsonElement>();
            using var limitedIntent = await agent.PostAsJsonAsync(intentUrl,
                new { replacementCertificateSha256 = replacementFingerprint });
            Assert.Equal(HttpStatusCode.TooManyRequests, limitedIntent.StatusCode);
            using var unaffectedIdentity = await agent.GetAsync($"{agentBase}/agent/identity");
            Assert.Equal(HttpStatusCode.NoContent, unaffectedIdentity.StatusCode);
            using var rotationGrant = await admin.PostAsJsonAsync(
                grantUrl, new
                {
                    rotationRequest.displayName,
                    rotationRequest.expectedCertificateSha256,
                    rotationIntentId = renewedIntentBody.GetProperty("intentId").GetGuid()
                });
            Assert.Equal(HttpStatusCode.OK, rotationGrant.StatusCode);
            var rotationResponse = await rotationGrant.Content
                .ReadFromJsonAsync<System.Text.Json.JsonElement>();
            var rotationToken = rotationResponse.GetProperty("token").GetString();
            using var rotated = await candidate.PostAsJsonAsync(
                $"{agentBase}/agent/enroll", new { token = rotationToken });
            Assert.Equal(HttpStatusCode.NoContent, rotated.StatusCode);
            using var rotatedIdentity = await candidate.GetAsync($"{agentBase}/agent/identity");
            Assert.Equal(HttpStatusCode.NoContent, rotatedIdentity.StatusCode);

            await using var scope = fixture.Services.CreateAsyncScope();
            var database = scope.ServiceProvider.GetRequiredService<CoreDbContext>();
            Assert.Equal(2, await database.AgentCertificates.CountAsync(row => row.DeviceId == deviceId));
            Assert.Equal(2, await database.AgentEnrollmentGrants.CountAsync(
                row => row.DeviceId == deviceId && row.ConsumedAt != null));

            var recoveryUrl =
                $"https://127.0.0.1:{ports[2]}/admin/devices/{deviceId.Value:D}/certificate-recoveries";
            var recoveredFingerprint = Convert.ToHexString(
                SHA256.HashData(agentPki.RecoveryClient.RawData));
            var recoveryRequest = new
            {
                expectedCertificateSha256 = replacementFingerprint,
                replacementCertificateSha256 = recoveredFingerprint,
                evidenceSha256 = new string('D', 64),
                incidentReference = "INC-GATEWAY-RECOVERY"
            };
            using var recoveryDenied = await admin.PostAsJsonAsync(recoveryUrl, recoveryRequest);
            Assert.Equal(HttpStatusCode.Forbidden, recoveryDenied.StatusCode);
            await GrantAdminPermissionAsync(adminId,
                AgentCertificateRecoveryService.RequestPermission);
            using var recoveryCreated = await admin.PostAsJsonAsync(recoveryUrl, recoveryRequest);
            Assert.Equal(HttpStatusCode.OK, recoveryCreated.StatusCode);
            var recoveryBody = await recoveryCreated.Content
                .ReadFromJsonAsync<System.Text.Json.JsonElement>();
            var recoveryId = recoveryBody.GetProperty("recoveryId").GetGuid();
            var approvalUrl = $"{recoveryUrl}/{recoveryId:D}/approve";
            var approvalBody = new
            {
                recoveryRequest.replacementCertificateSha256,
                recoveryRequest.evidenceSha256,
                recoveryRequest.incidentReference
            };
            await GrantAdminPermissionAsync(adminId,
                AgentCertificateRecoveryService.ApprovePermission);
            using var sameActor = await admin.PostAsJsonAsync(approvalUrl, approvalBody);
            Assert.Equal(HttpStatusCode.Forbidden, sameActor.StatusCode);
            using var ungrantedApprover = await recoveryApprover.PostAsJsonAsync(
                approvalUrl, approvalBody);
            Assert.Equal(HttpStatusCode.Forbidden, ungrantedApprover.StatusCode);
            await GrantAdminPermissionAsync(recoveryApproverId,
                AgentCertificateRecoveryService.ApprovePermission);
            using var wrongEvidence = await recoveryApprover.PostAsJsonAsync(
                approvalUrl, new
                {
                    approvalBody.replacementCertificateSha256,
                    evidenceSha256 = new string('E', 64),
                    approvalBody.incidentReference
                });
            Assert.Equal(HttpStatusCode.Conflict, wrongEvidence.StatusCode);
            using var recoveryApproved = await recoveryApprover.PostAsJsonAsync(
                approvalUrl, approvalBody);
            Assert.Equal(HttpStatusCode.OK, recoveryApproved.StatusCode);
            Assert.Equal("no-store", recoveryApproved.Headers.CacheControl?.ToString());
            var recoveryGrant = await recoveryApproved.Content
                .ReadFromJsonAsync<System.Text.Json.JsonElement>();
            var recoveryToken = recoveryGrant.GetProperty("token").GetString();
            Assert.NotNull(recoveryToken);
            using var retired = await candidate.GetAsync($"{agentBase}/agent/identity");
            Assert.Equal(HttpStatusCode.Forbidden, retired.StatusCode);
            using var recoveredAgent = agentPki.CreateClient(agentPki.RecoveryClient);
            using var recovered = await recoveredAgent.PostAsJsonAsync(
                $"{agentBase}/agent/enroll", new { token = recoveryToken });
            Assert.Equal(HttpStatusCode.NoContent, recovered.StatusCode);
            using var recoveredIdentity = await recoveredAgent.GetAsync(
                $"{agentBase}/agent/identity");
            Assert.Equal(HttpStatusCode.NoContent, recoveredIdentity.StatusCode);
            Assert.Equal(3, await database.AgentCertificates.CountAsync(
                row => row.DeviceId == deviceId));
            Assert.Equal(2, await database.AgentCertificates.CountAsync(
                row => row.DeviceId == deviceId && row.RevokedAt != null));
        }
        finally
        {
            await app.StopAsync();
        }
    }

    [Fact]
    public void Admin_gateway_rejects_reuse_of_the_agent_root_ca()
    {
        using var pki = new TestPki(new DeviceId(Guid.NewGuid()));
        using var secrets = new TestSecretDirectory();
        secrets.Write("fleetory-postgresql", fixture.ConnectionString);
        secrets.Write("agent-gateway-root-ca", pki.Root.ExportCertificatePem());
        secrets.Write("agent-gateway-server-cert", pki.Server.ExportCertificatePem());
        secrets.Write("agent-gateway-server-key", pki.ServerKey.ExportPkcs8PrivateKeyPem());
        secrets.Write("admin-gateway-root-ca", pki.Root.ExportCertificatePem());
        secrets.Write("admin-gateway-server-cert", pki.Server.ExportCertificatePem());
        secrets.Write("admin-gateway-server-key", pki.ServerKey.ExportPkcs8PrivateKeyPem());

        var exception = Assert.Throws<InvalidOperationException>(() => FleetoryApplication.Build([
            "--environment=Development",
            $"--Fleetory:Secrets:Directory={secrets.Path}",
            "--Fleetory:AgentGateway:Enabled=true",
            "--Fleetory:AdminGateway:Enabled=true",
            "--Fleetory:Web:Port=45101",
            "--Fleetory:AgentGateway:Port=45102",
            "--Fleetory:AdminGateway:Port=45103"
        ]));
        Assert.Contains("separate root CAs", exception.Message, StringComparison.Ordinal);

        using var replacementPki = new TestPki(new DeviceId(Guid.NewGuid()));
        secrets.Write("agent-gateway-root-ca",
            pki.Root.ExportCertificatePem() + "\n" + replacementPki.Root.ExportCertificatePem());
        secrets.Write("admin-gateway-root-ca", replacementPki.Root.ExportCertificatePem());
        secrets.Write("admin-gateway-server-cert", replacementPki.Server.ExportCertificatePem());
        secrets.Write("admin-gateway-server-key", replacementPki.ServerKey.ExportPkcs8PrivateKeyPem());
        var overlap = Assert.Throws<InvalidOperationException>(() => FleetoryApplication.Build([
            "--environment=Development",
            $"--Fleetory:Secrets:Directory={secrets.Path}",
            "--Fleetory:AgentGateway:Enabled=true",
            "--Fleetory:AdminGateway:Enabled=true",
            "--Fleetory:Web:Port=45101",
            "--Fleetory:AgentGateway:Port=45102",
            "--Fleetory:AdminGateway:Port=45103"
        ]));
        Assert.Contains("separate root CAs", overlap.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Revoked_admin_certificate_is_denied_while_replacement_with_same_identity_works()
    {
        var adminId = Guid.NewGuid();
        using var pki = new TestPki(new Uri($"urn:fleetory:admin:{adminId:D}"));
        using var secrets = new TestSecretDirectory();
        secrets.Write("fleetory-postgresql", fixture.ConnectionString);
        secrets.Write("admin-gateway-root-ca", pki.Root.ExportCertificatePem());
        secrets.Write("admin-gateway-server-cert", pki.Server.ExportCertificatePem());
        secrets.Write("admin-gateway-server-key", pki.ServerKey.ExportPkcs8PrivateKeyPem());
        await GrantAdminPermissionAsync(adminId, "platform.authorization.manage");
        var webPort = GetFreePort();
        var adminPort = GetFreePort();
        while (adminPort == webPort) { adminPort = GetFreePort(); }

        await using var app = FleetoryApplication.Build([
            "--environment=Development",
            $"--Fleetory:Secrets:Directory={secrets.Path}",
            "--Fleetory:AdminGateway:Enabled=true",
            $"--Fleetory:Web:Port={webPort}",
            $"--Fleetory:AdminGateway:Port={adminPort}"
        ]);
        await app.StartAsync();
        try
        {
            using var original = pki.CreateClient(pki.Client);
            using var replacement = pki.CreateClient(pki.UnregisteredClient);
            var url = $"https://127.0.0.1:{adminPort}/admin/authorization/roles/" +
                $"{Guid.NewGuid():D}/versions";
            using (var before = await original.GetAsync(url))
            {
                Assert.Equal(HttpStatusCode.NotFound, before.StatusCode);
            }

            var fingerprint = CertificateSha256(pki.Client);
            var sql = await File.ReadAllTextAsync(
                Path.Combine(AppContext.BaseDirectory, "revoke-admin-certificate.sql"));
            await using (var connection = new NpgsqlConnection(fixture.ConnectionString))
            {
                await connection.OpenAsync();
                await using var transaction = await connection.BeginTransactionAsync();
                await using (var configure = new NpgsqlCommand("""
                    SELECT set_config('fleetory.admin_revoke.certificate_sha256', @fingerprint, true),
                           set_config('fleetory.admin_revoke.incident_reference', @incident, true),
                           set_config('fleetory.admin_revoke.operator_reference', @operator, true)
                    """, connection, transaction))
                {
                    configure.Parameters.AddWithValue("fingerprint", fingerprint);
                    configure.Parameters.AddWithValue("incident", "INC-ADMIN-CERT-TEST");
                    configure.Parameters.AddWithValue("operator", "security-operator-test");
                    await configure.ExecuteNonQueryAsync();
                }

                await using (var revoke = new NpgsqlCommand(sql, connection, transaction))
                {
                    await revoke.ExecuteNonQueryAsync();
                }

                await transaction.CommitAsync();
                await using var verify = new NpgsqlCommand("""
                    SELECT count(*) FROM platform.admin_certificate_revocations AS revocation
                    JOIN platform.audit_events AS event
                      ON event.target_id = revocation.certificate_sha256
                    JOIN platform.audit_export_queue AS queue
                      ON queue.audit_event_id = event.event_id
                    WHERE revocation.certificate_sha256 = @fingerprint
                      AND event.action = 'admin.certificate.revoked'
                    """, connection);
                verify.Parameters.AddWithValue("fingerprint", fingerprint);
                Assert.Equal(1L, (long)(await verify.ExecuteScalarAsync())!);
            }

            using var denied = await original.GetAsync(url);
            Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);
            using var allowed = await replacement.GetAsync(url);
            Assert.Equal(HttpStatusCode.NotFound, allowed.StatusCode);

            await using var auditConnection = new NpgsqlConnection(fixture.ConnectionString);
            await auditConnection.OpenAsync();
            await using var deniedAudit = new NpgsqlCommand("""
                SELECT count(*) FROM platform.audit_events
                WHERE action = 'admin.certificate.revoked_denied'
                  AND actor_subject_id = @subject_id
                """, auditConnection);
            deniedAudit.Parameters.AddWithValue("subject_id", $"person:{adminId:N}");
            Assert.Equal(1L, (long)(await deniedAudit.ExecuteScalarAsync())!);
        }
        finally
        {
            await app.StopAsync();
        }
    }

    [Fact]
    public async Task Admin_certificate_registration_requires_exact_leaf_and_rotation_expires_old_leaf()
    {
        var adminId = Guid.NewGuid();
        using var pki = new TestPki(new Uri($"urn:fleetory:admin:{adminId:D}"));
        using var secrets = new TestSecretDirectory();
        secrets.Write("fleetory-postgresql", fixture.ConnectionString);
        secrets.Write("admin-gateway-root-ca", pki.Root.ExportCertificatePem());
        secrets.Write("admin-gateway-server-cert", pki.Server.ExportCertificatePem());
        secrets.Write("admin-gateway-server-key", pki.ServerKey.ExportPkcs8PrivateKeyPem());
        await GrantAdminPermissionAsync(adminId, "platform.authorization.manage");
        var webPort = GetFreePort();
        var adminPort = GetFreePort();
        while (adminPort == webPort) { adminPort = GetFreePort(); }

        await using var app = FleetoryApplication.Build([
            "--environment=Development",
            $"--Fleetory:Secrets:Directory={secrets.Path}",
            "--Fleetory:AdminGateway:Enabled=true",
            "--Fleetory:AdminGateway:RequireCertificateRegistration=true",
            $"--Fleetory:Web:Port={webPort}",
            $"--Fleetory:AdminGateway:Port={adminPort}"
        ]);
        await app.StartAsync();
        try
        {
            using var original = pki.CreateClient(pki.Client);
            using var replacement = pki.CreateClient(pki.UnregisteredClient);
            var url = $"https://127.0.0.1:{adminPort}/admin/authorization/roles/" +
                $"{Guid.NewGuid():D}/versions";
            var oldFingerprint = CertificateSha256(pki.Client);
            var newFingerprint = CertificateSha256(pki.UnregisteredClient);

            using (var denied = await original.GetAsync(url))
            {
                Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);
            }

            await RegisterAdminCertificateAsync("bootstrap", adminId, oldFingerprint);
            using (var allowed = await original.GetAsync(url))
            {
                Assert.Equal(HttpStatusCode.NotFound, allowed.StatusCode);
            }
            using (var denied = await replacement.GetAsync(url))
            {
                Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);
            }

            await Assert.ThrowsAsync<PostgresException>(() => RegisterAdminCertificateAsync(
                "rotate", adminId, newFingerprint, new string('A', 64)));
            await RegisterAdminCertificateAsync("rotate", adminId, newFingerprint, oldFingerprint);
            using (var oldDuringOverlap = await original.GetAsync(url))
            {
                Assert.Equal(HttpStatusCode.NotFound, oldDuringOverlap.StatusCode);
            }
            using (var newDuringOverlap = await replacement.GetAsync(url))
            {
                Assert.Equal(HttpStatusCode.NotFound, newDuringOverlap.StatusCode);
            }

            await using var connection = new NpgsqlConnection(fixture.ConnectionString);
            await connection.OpenAsync();
            await using (var verify = new NpgsqlCommand("""
                SELECT count(*) FROM platform.admin_certificate_registrations AS registration
                JOIN platform.audit_events AS event
                  ON event.target_id = registration.certificate_sha256
                JOIN platform.audit_export_queue AS queue
                  ON queue.audit_event_id = event.event_id
                WHERE registration.actor_subject_id = @actor_id
                  AND event.action IN ('admin.certificate.bootstrap', 'admin.certificate.rotate')
                """, connection))
            {
                verify.Parameters.AddWithValue("actor_id", $"person:{adminId:N}");
                Assert.Equal(2L, (long)(await verify.ExecuteScalarAsync())!);
            }

            await using (var expire = new NpgsqlCommand("""
                UPDATE platform.admin_certificate_registrations
                SET overlap_ends_at = now() - interval '1 second'
                WHERE certificate_sha256 = @fingerprint
                """, connection))
            {
                expire.Parameters.AddWithValue("fingerprint", oldFingerprint);
                Assert.Equal(1, await expire.ExecuteNonQueryAsync());
            }
            using (var oldAfterOverlap = await original.GetAsync(url))
            {
                Assert.Equal(HttpStatusCode.Forbidden, oldAfterOverlap.StatusCode);
            }
            using var current = await replacement.GetAsync(url);
            Assert.Equal(HttpStatusCode.NotFound, current.StatusCode);
        }
        finally
        {
            await app.StopAsync();
        }
    }

    private async Task RegisterAdminCertificateAsync(string mode, Guid personId,
        string fingerprint, string? previousFingerprint = null)
    {
        var script = await File.ReadAllTextAsync(
            Path.Combine(AppContext.BaseDirectory, "register-admin-certificate.sql"));
        await using var connection = new NpgsqlConnection(fixture.ConnectionString);
        await connection.OpenAsync();
        await using var transaction = await connection.BeginTransactionAsync();
        await using (var configure = new NpgsqlCommand("""
            SELECT set_config('fleetory.admin_register.mode', @mode, true),
                   set_config('fleetory.admin_register.person_id', @person_id, true),
                   set_config('fleetory.admin_register.certificate_sha256', @fingerprint, true),
                   set_config('fleetory.admin_register.previous_certificate_sha256', @previous, true),
                   set_config('fleetory.admin_register.incident_reference', @incident, true),
                   set_config('fleetory.admin_register.operator_reference', @operator, true)
            """, connection, transaction))
        {
            configure.Parameters.AddWithValue("mode", mode);
            configure.Parameters.AddWithValue("person_id", personId.ToString("D"));
            configure.Parameters.AddWithValue("fingerprint", fingerprint);
            configure.Parameters.AddWithValue("previous", previousFingerprint ?? "");
            configure.Parameters.AddWithValue("incident", "INC-ADMIN-REGISTRATION-TEST");
            configure.Parameters.AddWithValue("operator", "security-operator-test");
            await configure.ExecuteNonQueryAsync();
        }
        await using (var register = new NpgsqlCommand(script, connection, transaction))
        {
            await register.ExecuteNonQueryAsync();
        }
        await transaction.CommitAsync();
    }

    [Fact]
    public async Task Admin_mtls_route_manages_scoped_roles_with_audit()
    {
        var adminId = Guid.NewGuid();
        using var pki = new TestPki(new Uri($"urn:fleetory:admin:{adminId:D}"));
        using var secrets = new TestSecretDirectory();
        secrets.Write("fleetory-postgresql", fixture.ConnectionString);
        secrets.Write("admin-gateway-root-ca", pki.Root.ExportCertificatePem());
        secrets.Write("admin-gateway-server-cert", pki.Server.ExportCertificatePem());
        secrets.Write("admin-gateway-server-key", pki.ServerKey.ExportPkcs8PrivateKeyPem());
        var webPort = GetFreePort();
        var adminPort = GetFreePort();
        while (adminPort == webPort) { adminPort = GetFreePort(); }

        await using var app = FleetoryApplication.Build([
            "--environment=Development",
            $"--Fleetory:Secrets:Directory={secrets.Path}",
            "--Fleetory:AdminGateway:Enabled=true",
            "--Fleetory:AdminGateway:RateLimitPerMinute=100",
            $"--Fleetory:Web:Port={webPort}",
            $"--Fleetory:AdminGateway:Port={adminPort}"
        ]);
        await app.StartAsync();
        try
        {
            using var admin = pki.CreateClient(pki.Client);
            using var web = new HttpClient();
            var baseUrl = $"https://127.0.0.1:{adminPort}/admin/authorization";
            var roleBody = new { name = "mTLS managed reader", permissions = ReadPermissions };
            using var denied = await admin.PostAsJsonAsync($"{baseUrl}/roles", roleBody);
            Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);
            using var deniedReplacement = await admin.PostAsJsonAsync(
                $"{baseUrl}/roles/{Guid.NewGuid():D}/replacements", roleBody);
            Assert.Equal(HttpStatusCode.Forbidden, deniedReplacement.StatusCode);
            using var deniedHistory = await admin.GetAsync(
                $"{baseUrl}/roles/{Guid.NewGuid():D}/versions");
            Assert.Equal(HttpStatusCode.Forbidden, deniedHistory.StatusCode);
            using var deniedScopeRevision = await admin.PutAsJsonAsync(
                $"{baseUrl}/scopes/{Guid.NewGuid():D}",
                new { name = "Denied revision", expectedRevision = 1 });
            Assert.Equal(HttpStatusCode.Forbidden, deniedScopeRevision.StatusCode);
            using var deniedRetirement = await admin.DeleteAsync(
                $"{baseUrl}/roles/{Guid.NewGuid():D}");
            Assert.Equal(HttpStatusCode.Forbidden, deniedRetirement.StatusCode);
            using var webAttempt = await web.PostAsJsonAsync(
                $"http://127.0.0.1:{webPort}/admin/authorization/roles", roleBody);
            Assert.Equal(HttpStatusCode.NotFound, webAttempt.StatusCode);
            using var webReplacement = await web.PostAsJsonAsync(
                $"http://127.0.0.1:{webPort}/admin/authorization/roles/{Guid.NewGuid():D}/replacements",
                roleBody);
            Assert.Equal(HttpStatusCode.NotFound, webReplacement.StatusCode);
            using var webHistory = await web.GetAsync(
                $"http://127.0.0.1:{webPort}/admin/authorization/roles/{Guid.NewGuid():D}/versions");
            Assert.Equal(HttpStatusCode.NotFound, webHistory.StatusCode);
            using var webScopeRevision = await web.PutAsJsonAsync(
                $"http://127.0.0.1:{webPort}/admin/authorization/scopes/{Guid.NewGuid():D}",
                new { name = "Web revision", expectedRevision = 1 });
            Assert.Equal(HttpStatusCode.NotFound, webScopeRevision.StatusCode);
            using var webRetirement = await web.DeleteAsync(
                $"http://127.0.0.1:{webPort}/admin/authorization/roles/{Guid.NewGuid():D}");
            Assert.Equal(HttpStatusCode.NotFound, webRetirement.StatusCode);

            await GrantAdminPermissionAsync(adminId, "platform.authorization.manage");
            using var emptyRoleName = await admin.PostAsJsonAsync($"{baseUrl}/roles",
                new { name = "", permissions = ReadPermissions });
            Assert.Equal(HttpStatusCode.BadRequest, emptyRoleName.StatusCode);
            using var duplicatePermissions = await admin.PostAsJsonAsync($"{baseUrl}/roles",
                new { name = "Duplicate permissions", permissions = DuplicateReadPermissions });
            Assert.Equal(HttpStatusCode.BadRequest, duplicatePermissions.StatusCode);
            using var malformedRole = await admin.PostAsync($"{baseUrl}/roles",
                new StringContent("{", System.Text.Encoding.UTF8, "application/json"));
            Assert.Equal(HttpStatusCode.BadRequest, malformedRole.StatusCode);
            using var missingParent = await admin.PostAsJsonAsync($"{baseUrl}/scopes",
                new { name = "Orphan scope", parentScopeId = Guid.NewGuid() });
            Assert.Equal(HttpStatusCode.BadRequest, missingParent.StatusCode);
            using var invalidScope = await admin.PostAsJsonAsync($"{baseUrl}/scopes",
                new { name = " ", parentScopeId = (Guid?)null });
            Assert.Equal(HttpStatusCode.BadRequest, invalidScope.StatusCode);
            using var invalidAssignment = await admin.PostAsJsonAsync(
                $"{baseUrl}/roles/{Guid.NewGuid():D}/assignments",
                new { subjectId = "", kind = ActorKind.Person, scopeId = (Guid?)null });
            Assert.Equal(HttpStatusCode.BadRequest, invalidAssignment.StatusCode);
            using var missingRoleAssignment = await admin.PostAsJsonAsync(
                $"{baseUrl}/roles/{Guid.NewGuid():D}/assignments",
                new { subjectId = $"person:{Guid.NewGuid():N}", kind = ActorKind.Person,
                    scopeId = (Guid?)null });
            Assert.Equal(HttpStatusCode.BadRequest, missingRoleAssignment.StatusCode);
            using var emptyRevocation = await admin.DeleteAsync(
                $"{baseUrl}/assignments/{Guid.Empty:D}");
            Assert.Equal(HttpStatusCode.BadRequest, emptyRevocation.StatusCode);
            using var emptyRoleRetirement = await admin.DeleteAsync(
                $"{baseUrl}/roles/{Guid.Empty:D}");
            Assert.Equal(HttpStatusCode.BadRequest, emptyRoleRetirement.StatusCode);
            using var emptyScopeRetirement = await admin.DeleteAsync(
                $"{baseUrl}/scopes/{Guid.Empty:D}");
            Assert.Equal(HttpStatusCode.BadRequest, emptyScopeRetirement.StatusCode);
            var correlation = Guid.NewGuid().ToString("N");
            using var roleRequest = new HttpRequestMessage(HttpMethod.Post, $"{baseUrl}/roles")
            {
                Content = JsonContent.Create(roleBody)
            };
            roleRequest.Headers.Add("X-Correlation-ID", correlation);
            using var roleResponse = await admin.SendAsync(roleRequest);
            Assert.Equal(HttpStatusCode.Created, roleResponse.StatusCode);
            var roleId = (await roleResponse.Content.ReadFromJsonAsync<System.Text.Json.JsonElement>())
                .GetProperty("id").GetGuid();

            using var scopeResponse = await admin.PostAsJsonAsync($"{baseUrl}/scopes",
                new { name = "mTLS scope", parentScopeId = (Guid?)null });
            Assert.Equal(HttpStatusCode.Created, scopeResponse.StatusCode);
            var scopeId = (await scopeResponse.Content.ReadFromJsonAsync<System.Text.Json.JsonElement>())
                .GetProperty("id").GetGuid();
            using var invalidScopeRevision = await admin.PutAsJsonAsync(
                $"{baseUrl}/scopes/{scopeId:D}",
                new { name = "Invalid revision", expectedRevision = 0 });
            Assert.Equal(HttpStatusCode.BadRequest, invalidScopeRevision.StatusCode);
            using var missingScopeRevision = await admin.PutAsJsonAsync(
                $"{baseUrl}/scopes/{Guid.NewGuid():D}",
                new { name = "Missing scope", expectedRevision = 1 });
            Assert.Equal(HttpStatusCode.NotFound, missingScopeRevision.StatusCode);
            using var staleScope = await admin.PutAsJsonAsync(
                $"{baseUrl}/scopes/{scopeId:D}",
                new { name = "Stale scope", expectedRevision = 2 });
            Assert.Equal(HttpStatusCode.Conflict, staleScope.StatusCode);
            using var revisedScope = await admin.PutAsJsonAsync(
                $"{baseUrl}/scopes/{scopeId:D}",
                new { name = "mTLS revised scope", expectedRevision = 1 });
            Assert.Equal(HttpStatusCode.OK, revisedScope.StatusCode);
            Assert.Equal(2, (await revisedScope.Content.ReadFromJsonAsync<System.Text.Json.JsonElement>())
                .GetProperty("revision").GetInt32());
            using var scopeHistory = await admin.GetAsync(
                $"{baseUrl}/scopes/{scopeId:D}/versions");
            Assert.Equal(HttpStatusCode.OK, scopeHistory.StatusCode);
            Assert.Equal(2, (await scopeHistory.Content.ReadFromJsonAsync<System.Text.Json.JsonElement>())
                .GetArrayLength());
            var target = $"person:{Guid.NewGuid():N}";
            using var assignmentResponse = await admin.PostAsJsonAsync(
                $"{baseUrl}/roles/{roleId:D}/assignments",
                new { subjectId = target, kind = ActorKind.Person, scopeId });
            Assert.Equal(HttpStatusCode.Created, assignmentResponse.StatusCode);
            var assignmentId = (await assignmentResponse.Content
                .ReadFromJsonAsync<System.Text.Json.JsonElement>()).GetProperty("id").GetGuid();

            await using var scope = fixture.Services.CreateAsyncScope();
            var authorizer = scope.ServiceProvider.GetRequiredService<IAuthorizationService>();
            var request = new AuthorizationRequest(new ActorReference(target, ActorKind.Person),
                "Core.Device.Read", new ScopeId(scopeId));
            Assert.True((await authorizer.AuthorizeAsync(request)).IsAllowed);
            using var blockedRole = await admin.DeleteAsync($"{baseUrl}/roles/{roleId:D}");
            Assert.Equal(HttpStatusCode.Conflict, blockedRole.StatusCode);
            using var blockedScope = await admin.DeleteAsync($"{baseUrl}/scopes/{scopeId:D}");
            Assert.Equal(HttpStatusCode.Conflict, blockedScope.StatusCode);
            using var invalidReplacement = await admin.PostAsJsonAsync(
                $"{baseUrl}/roles/{roleId:D}/replacements",
                new { name = "Duplicate replacement", permissions = DuplicateReadPermissions });
            Assert.Equal(HttpStatusCode.BadRequest, invalidReplacement.StatusCode);
            using var missingReplacement = await admin.PostAsJsonAsync(
                $"{baseUrl}/roles/{Guid.NewGuid():D}/replacements", roleBody);
            Assert.Equal(HttpStatusCode.NotFound, missingReplacement.StatusCode);
            using var replacement = await admin.PostAsJsonAsync(
                $"{baseUrl}/roles/{roleId:D}/replacements",
                new { name = "mTLS managed writer", permissions = WritePermissions });
            Assert.Equal(HttpStatusCode.Created, replacement.StatusCode);
            roleId = (await replacement.Content.ReadFromJsonAsync<System.Text.Json.JsonElement>())
                .GetProperty("id").GetGuid();
            Assert.False((await authorizer.AuthorizeAsync(request)).IsAllowed);
            Assert.True((await authorizer.AuthorizeAsync(new AuthorizationRequest(
                new ActorReference(target, ActorKind.Person), "Core.Device.Write",
                new ScopeId(scopeId)))).IsAllowed);
            using var history = await admin.GetAsync($"{baseUrl}/roles/{roleId:D}/versions");
            Assert.Equal(HttpStatusCode.OK, history.StatusCode);
            var roleVersions = await history.Content.ReadFromJsonAsync<System.Text.Json.JsonElement>();
            Assert.Equal(2, roleVersions.GetArrayLength());
            Assert.Equal(roleId, roleVersions[0].GetProperty("roleId").GetGuid());
            Assert.Equal("Core.Device.Write",
                roleVersions[0].GetProperty("permissions")[0].GetString());
            using var revoked = await admin.DeleteAsync(
                $"{baseUrl}/assignments/{assignmentId:D}");
            Assert.Equal(HttpStatusCode.NoContent, revoked.StatusCode);
            Assert.False((await authorizer.AuthorizeAsync(request)).IsAllowed);
            using var retiredRole = await admin.DeleteAsync($"{baseUrl}/roles/{roleId:D}");
            Assert.Equal(HttpStatusCode.NoContent, retiredRole.StatusCode);
            using var retiredScope = await admin.DeleteAsync($"{baseUrl}/scopes/{scopeId:D}");
            Assert.Equal(HttpStatusCode.NoContent, retiredScope.StatusCode);
            using var missingRole = await admin.DeleteAsync($"{baseUrl}/roles/{roleId:D}");
            Assert.Equal(HttpStatusCode.NotFound, missingRole.StatusCode);

            await using var connection = new NpgsqlConnection(fixture.ConnectionString);
            await connection.OpenAsync();
            await using var audit = new NpgsqlCommand("""
                SELECT COUNT(*) FROM platform.audit_events
                WHERE correlation_id = @correlation
                  AND action = 'platform.authorization.role_created'
                """, connection);
            audit.Parameters.AddWithValue("correlation", correlation);
            Assert.Equal(1L, (long)(await audit.ExecuteScalarAsync())!);
        }
        finally
        {
            await app.StopAsync();
        }
    }

    [Fact]
    public async Task Separate_admin_mtls_listener_revokes_a_bound_agent_certificate()
    {
        var deviceId = new DeviceId(Guid.NewGuid());
        var adminId = Guid.NewGuid();
        using var agentPki = new TestPki(deviceId);
        using var adminPki = new TestPki(
            new Uri($"urn:fleetory:admin:{adminId:D}"),
            new Uri($"urn:fleetory:admin:{Guid.NewGuid():D}"));
        using var secrets = new TestSecretDirectory();
        secrets.Write("fleetory-postgresql", fixture.ConnectionString);
        secrets.Write("agent-gateway-root-ca", agentPki.Root.ExportCertificatePem());
        secrets.Write("agent-gateway-server-cert", agentPki.Server.ExportCertificatePem());
        secrets.Write("agent-gateway-server-key", agentPki.ServerKey.ExportPkcs8PrivateKeyPem());
        secrets.Write("admin-gateway-root-ca", adminPki.Root.ExportCertificatePem());
        secrets.Write("admin-gateway-server-cert", adminPki.Server.ExportCertificatePem());
        secrets.Write("admin-gateway-server-key", adminPki.ServerKey.ExportPkcs8PrivateKeyPem());

        var ports = Enumerable.Range(0, 3).Select(_ => GetFreePort()).ToArray();
        while (ports.Distinct().Count() != ports.Length)
        {
            ports = Enumerable.Range(0, 3).Select(_ => GetFreePort()).ToArray();
        }

        await using var app = FleetoryApplication.Build([
            "--environment=Development",
            $"--Fleetory:Secrets:Directory={secrets.Path}",
            "--Fleetory:AgentGateway:Enabled=true",
            "--Fleetory:AdminGateway:Enabled=true",
            $"--Fleetory:Web:Port={ports[0]}",
            $"--Fleetory:AgentGateway:Port={ports[1]}",
            $"--Fleetory:AdminGateway:Port={ports[2]}"
        ]);

        await using (var scope = fixture.Services.CreateAsyncScope())
        {
            var database = scope.ServiceProvider.GetRequiredService<CoreDbContext>();
            database.Devices.Add(DeviceRecord.Create(deviceId, "admin gateway test device", DateTimeOffset.UtcNow));
            database.AgentCertificates.Add(AgentCertificateRecord.Create(
                deviceId, Convert.ToHexString(SHA256.HashData(agentPki.Client.RawData)),
                agentPki.Client.NotBefore.ToUniversalTime(),
                agentPki.Client.NotAfter.ToUniversalTime()));
            await database.SaveChangesAsync();
        }

        await GrantAdminRevocationAsync(adminId);
        await app.StartAsync();
        try
        {
            using var agent = agentPki.CreateClient(agentPki.Client);
            using var admin = adminPki.CreateClient(adminPki.Client);
            using var ungranted = adminPki.CreateClient(adminPki.UnregisteredClient);
            using var wrongCa = agentPki.CreateClient(agentPki.Client);
            using var web = new HttpClient();
            var agentUrl = $"https://127.0.0.1:{ports[1]}/agent/identity";
            var revokePath = $"/admin/devices/{deviceId.Value:D}/certificates/" +
                Convert.ToHexString(SHA256.HashData(agentPki.Client.RawData)) + "/revoke";
            var adminUrl = $"https://127.0.0.1:{ports[2]}{revokePath}";

            using var before = await agent.GetAsync(agentUrl);
            Assert.Equal(HttpStatusCode.NoContent, before.StatusCode);
            using var webAttempt = await web.PostAsync($"http://127.0.0.1:{ports[0]}{revokePath}", null);
            Assert.Equal(HttpStatusCode.NotFound, webAttempt.StatusCode);
            using var agentAttempt = await agent.PostAsync(
                $"https://127.0.0.1:{ports[1]}{revokePath}", null);
            Assert.Equal(HttpStatusCode.NotFound, agentAttempt.StatusCode);
            using var denied = await ungranted.PostAsync(adminUrl, null);
            Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);
            using var invalidIdentity = adminPki.CreateClient(adminPki.MalformedIdentityClient);
            using var invalid = await invalidIdentity.PostAsync(adminUrl, null);
            Assert.Equal(HttpStatusCode.Forbidden, invalid.StatusCode);
            await Assert.ThrowsAsync<HttpRequestException>(async () =>
                await wrongCa.PostAsync(adminUrl, null));
            using var noCertificate = adminPki.CreateClient();
            await Assert.ThrowsAsync<HttpRequestException>(async () =>
                await noCertificate.PostAsync(adminUrl, null));

            var correlation = Guid.NewGuid().ToString("N");
            using var request = new HttpRequestMessage(HttpMethod.Post, adminUrl);
            request.Headers.Add("X-Correlation-ID", correlation);
            using var revoked = await admin.SendAsync(request);
            Assert.Equal(HttpStatusCode.NoContent, revoked.StatusCode);
            using var after = await agent.GetAsync(agentUrl);
            Assert.Equal(HttpStatusCode.Forbidden, after.StatusCode);
            using var adminHealth = await admin.GetAsync($"https://127.0.0.1:{ports[2]}/health/live");
            Assert.Equal(HttpStatusCode.NotFound, adminHealth.StatusCode);
            Assert.Equal(2, await CountRevocationAuditAsync(correlation));
        }
        finally
        {
            await app.StopAsync();
        }
    }

    [Fact]
    public async Task Mutual_tls_accepts_only_a_bound_certificate_on_the_agent_listener()
    {
        var deviceId = new DeviceId(Guid.NewGuid());
        using var pki = new TestPki(deviceId);
        using var secrets = new TestSecretDirectory();
        secrets.Write("fleetory-postgresql", fixture.ConnectionString);
        secrets.Write("agent-gateway-root-ca", pki.Root.ExportCertificatePem());
        secrets.Write("agent-gateway-server-cert", pki.Server.ExportCertificatePem());
        secrets.Write("agent-gateway-server-key", pki.ServerKey.ExportPkcs8PrivateKeyPem());

        var webPort = GetFreePort();
        var agentPort = GetFreePort();
        while (webPort == agentPort)
        {
            agentPort = GetFreePort();
        }

        await using var app = FleetoryApplication.Build([
            "--environment=Development",
            $"--Fleetory:Secrets:Directory={secrets.Path}",
            "--Fleetory:AgentGateway:Enabled=true",
            $"--Fleetory:Web:Port={webPort}",
            $"--Fleetory:AgentGateway:Port={agentPort}"
        ]);
        await using (var scope = fixture.Services.CreateAsyncScope())
        {
            var database = scope.ServiceProvider.GetRequiredService<CoreDbContext>();
            database.Devices.Add(DeviceRecord.Create(deviceId, "mTLS test device", DateTimeOffset.UtcNow));
            database.AgentCertificates.Add(AgentCertificateRecord.Create(
                deviceId,
                Convert.ToHexString(SHA256.HashData(pki.Client.RawData)),
                pki.Client.NotBefore.ToUniversalTime(),
                pki.Client.NotAfter.ToUniversalTime()));
            await database.SaveChangesAsync();
        }

        await app.StartAsync();
        try
        {
            using var authenticated = pki.CreateClient(pki.Client);
            using var web = new HttpClient { BaseAddress = new Uri($"http://127.0.0.1:{webPort}") };
            using var agentResponse = await authenticated.GetAsync(
                $"https://127.0.0.1:{agentPort}/agent/identity");
            Assert.Equal(HttpStatusCode.NoContent, agentResponse.StatusCode);
            using var webAgentResponse = await web.GetAsync("/agent/identity");
            using var webHealthResponse = await web.GetAsync("/health/live");
            using var agentHealthResponse = await authenticated.GetAsync(
                $"https://127.0.0.1:{agentPort}/health/live");

            Assert.Equal(HttpStatusCode.NotFound, webAgentResponse.StatusCode);
            Assert.Equal(HttpStatusCode.OK, webHealthResponse.StatusCode);
            Assert.Equal(HttpStatusCode.NotFound, agentHealthResponse.StatusCode);

            await using (var scope = fixture.Services.CreateAsyncScope())
            {
                var database = scope.ServiceProvider.GetRequiredService<CoreDbContext>();
                var fingerprint = Convert.ToHexString(SHA256.HashData(pki.Client.RawData));
                var binding = await database.AgentCertificates.SingleAsync(
                    row => row.CertificateSha256 == fingerprint);
                binding.Revoke(DateTimeOffset.UtcNow);
                await database.SaveChangesAsync();
            }

            using var revokedResponse = await authenticated.GetAsync(
                $"https://127.0.0.1:{agentPort}/agent/identity");
            Assert.Equal(HttpStatusCode.Forbidden, revokedResponse.StatusCode);

            using var unknown = pki.CreateClient(pki.UnregisteredClient);
            using var unknownResponse = await unknown.GetAsync(
                $"https://127.0.0.1:{agentPort}/agent/identity");
            Assert.Equal(HttpStatusCode.Forbidden, unknownResponse.StatusCode);

            using var malformedIdentity = pki.CreateClient(pki.MalformedIdentityClient);
            using var malformedResponse = await malformedIdentity.GetAsync(
                $"https://127.0.0.1:{agentPort}/agent/identity");
            Assert.Equal(HttpStatusCode.Forbidden, malformedResponse.StatusCode);

            using var foreignPki = new TestPki(deviceId);
            using var foreign = pki.CreateClient(foreignPki.Client);
            await Assert.ThrowsAsync<HttpRequestException>(async () =>
                await foreign.GetAsync($"https://127.0.0.1:{agentPort}/agent/identity"));

            using var noCertificate = pki.CreateClient();
            await Assert.ThrowsAsync<HttpRequestException>(async () =>
                await noCertificate.GetAsync($"https://127.0.0.1:{agentPort}/agent/identity"));
        }
        finally
        {
            await app.StopAsync();
        }
    }

    private static string CertificateSha256(X509Certificate2 certificate) =>
        Convert.ToHexString(SHA256.HashData(certificate.RawData));

    private static int GetFreePort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }

    private Task GrantAdminRevocationAsync(Guid adminId) =>
        GrantAdminPermissionAsync(adminId, AgentCertificateRevocationService.Permission);

    private async Task GrantAdminPermissionAsync(Guid adminId, string permission)
    {
        var roleId = Guid.NewGuid();
        await using var connection = new NpgsqlConnection(fixture.ConnectionString);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand("""
            INSERT INTO platform.authorization_roles (role_id, name)
            VALUES (@role_id, @name);
            INSERT INTO platform.authorization_role_permissions (role_id, permission)
            VALUES (@role_id, @permission);
            INSERT INTO platform.authorization_assignments
                (assignment_id, actor_subject_id, actor_kind, role_id, scope_id)
            VALUES (@assignment_id, @actor_subject_id, @actor_kind, @role_id, NULL);
            """, connection);
        command.Parameters.AddWithValue("role_id", roleId);
        command.Parameters.AddWithValue("name", $"Admin Gateway {roleId:N}");
        command.Parameters.AddWithValue("permission", permission);
        command.Parameters.AddWithValue("assignment_id", Guid.NewGuid());
        command.Parameters.AddWithValue("actor_subject_id", $"person:{adminId:N}");
        command.Parameters.AddWithValue("actor_kind", (int)ActorKind.Person);
        await command.ExecuteNonQueryAsync();
    }

    private async Task<int> CountRevocationAuditAsync(string correlation)
    {
        await using var connection = new NpgsqlConnection(fixture.ConnectionString);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand("""
            SELECT count(*) FROM platform.audit_events
            WHERE correlation_id = @correlation_id
              AND action IN ('core.agent_certificate.revoke_requested',
                             'core.agent_certificate.revoke_completed')
            """, connection);
        command.Parameters.AddWithValue("correlation_id", correlation);
        return Convert.ToInt32(await command.ExecuteScalarAsync());
    }

    private async Task<int> CountAuditActionAsync(CorrelationId correlation, string action)
    {
        await using var connection = new NpgsqlConnection(fixture.ConnectionString);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand("""
            SELECT count(*) FROM platform.audit_events
            WHERE correlation_id = @correlation_id AND action = @action
            """, connection);
        command.Parameters.AddWithValue("correlation_id", correlation.Value);
        command.Parameters.AddWithValue("action", action);
        return Convert.ToInt32(await command.ExecuteScalarAsync());
    }

    private sealed class TestSecretDirectory : IDisposable
    {
        public string Path { get; } = System.IO.Path.Combine(
            System.IO.Path.GetTempPath(), "fleetory-mtls-test-" + Guid.NewGuid().ToString("N"));

        public TestSecretDirectory() => Directory.CreateDirectory(Path);

        public void Write(string name, string value)
        {
            var path = System.IO.Path.Combine(Path, name);
            File.WriteAllText(path, value);
            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }
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

    private sealed class FailingAuditWriter : IAuditWriter
    {
        public ValueTask WriteAsync(AuditRecord record, CancellationToken cancellationToken = default) =>
            ValueTask.FromException(new InvalidOperationException("Audit unavailable."));

        public ValueTask WriteInTransactionAsync(AuditRecord record, DbTransaction transaction,
            CancellationToken cancellationToken = default) =>
            ValueTask.FromException(new InvalidOperationException("Audit unavailable."));
    }

    private sealed class FailingTransactionalAuditWriter(IAuditWriter inner) : IAuditWriter
    {
        public ValueTask WriteAsync(AuditRecord record, CancellationToken cancellationToken = default) =>
            inner.WriteAsync(record, cancellationToken);

        public ValueTask WriteInTransactionAsync(AuditRecord record, DbTransaction transaction,
            CancellationToken cancellationToken = default) =>
            ValueTask.FromException(new InvalidOperationException("Completion audit unavailable."));
    }

    private sealed class TestPki : IDisposable
    {
        private readonly ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        private readonly ECDsa? intermediateKey;
        private readonly bool omitLeafBasicConstraints;
        private readonly ECDsa clientKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        private readonly ECDsa unregisteredKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        private readonly ECDsa recoveryKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        private readonly ECDsa malformedIdentityKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        public TestPki(DeviceId deviceId, bool useIntermediate = false,
            bool omitLeafBasicConstraints = false)
            : this(new Uri($"urn:fleetory:device:{deviceId.Value:D}"), null,
                useIntermediate, omitLeafBasicConstraints)
        {
        }

        public TestPki(Uri clientUri, Uri? unregisteredUri = null,
            bool useIntermediate = false, bool omitLeafBasicConstraints = false)
        {
            this.omitLeafBasicConstraints = omitLeafBasicConstraints;
            var now = DateTimeOffset.UtcNow;
            var caIdentity = Guid.NewGuid().ToString("N");
            var rootRequest = new CertificateRequest($"CN=Fleetory Test CA {caIdentity}",
                rootKey, HashAlgorithmName.SHA256);
            rootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            rootRequest.CertificateExtensions.Add(new X509KeyUsageExtension(
                X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
            Root = rootRequest.CreateSelfSigned(now.AddDays(-1), now.AddDays(7));

            if (useIntermediate)
            {
                intermediateKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
                var request = new CertificateRequest(
                    $"CN=Fleetory Test Intermediate {caIdentity}",
                    intermediateKey, HashAlgorithmName.SHA256);
                request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
                request.CertificateExtensions.Add(new X509KeyUsageExtension(
                    X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
                using var publicIntermediate = request.Create(Root, now.AddHours(-1),
                    now.AddDays(3), Guid.NewGuid().ToByteArray());
                Intermediate = publicIntermediate.CopyWithPrivateKey(intermediateKey);
            }

            ServerKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            Server = Issue("CN=localhost", ServerKey, "1.3.6.1.5.5.7.3.1", now,
                san => san.AddIpAddress(IPAddress.Loopback));
            Client = Issue("CN=Fleetory Test Agent", clientKey, "1.3.6.1.5.5.7.3.2", now,
                san => san.AddUri(clientUri));
            UnregisteredClient = Issue("CN=Fleetory Unknown Agent", unregisteredKey,
                "1.3.6.1.5.5.7.3.2", now,
                san => san.AddUri(unregisteredUri ?? clientUri));
            RecoveryClient = Issue("CN=Fleetory Recovery Agent", recoveryKey,
                "1.3.6.1.5.5.7.3.2", now, san => san.AddUri(clientUri));
            MalformedIdentityClient = Issue("CN=Fleetory Malformed Agent", malformedIdentityKey,
                "1.3.6.1.5.5.7.3.2", now,
                san => san.AddUri(new Uri("urn:fleetory:device:not-a-guid")));
        }

        public X509Certificate2 Root { get; }
        public X509Certificate2? Intermediate { get; }
        public string ServerChainPem => Server.ExportCertificatePem() + "\n" + Intermediate?.ExportCertificatePem();
        public X509Certificate2 Server { get; }
        public X509Certificate2 Client { get; }
        public X509Certificate2 UnregisteredClient { get; }
        public X509Certificate2 RecoveryClient { get; }
        public X509Certificate2 MalformedIdentityClient { get; }
        public ECDsa ServerKey { get; }

        public HttpClient CreateClient(X509Certificate2? certificate = null)
        {
            if (Intermediate is not null && certificate is not null)
            {
                var socketsHandler = new SocketsHttpHandler();
                socketsHandler.SslOptions.ClientCertificateContext =
                    SslStreamCertificateContext.Create(certificate,
                        new X509Certificate2Collection { Intermediate }, offline: true);
                socketsHandler.SslOptions.RemoteCertificateValidationCallback =
                    (_, server, peerChain, errors) =>
                        ValidateServer(server as X509Certificate2, peerChain, errors);
                return new HttpClient(socketsHandler);
            }

            var handler = new HttpClientHandler
            {
                ClientCertificateOptions = ClientCertificateOption.Manual
            };
            if (certificate is not null)
            {
                handler.ClientCertificates.Add(certificate);
            }

            handler.ServerCertificateCustomValidationCallback = (_, server, peerChain, errors) =>
                ValidateServer(server, peerChain, errors);
            return new HttpClient(handler);
        }

        private bool ValidateServer(X509Certificate2? server, X509Chain? peerChain,
            SslPolicyErrors errors)
        {
            if (server is null || (errors & SslPolicyErrors.RemoteCertificateNameMismatch) != 0)
            {
                return false;
            }

            using var chain = new X509Chain();
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.CustomTrustStore.Add(Root);
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            if (peerChain is not null)
            {
                foreach (var element in peerChain.ChainElements.Cast<X509ChainElement>().Skip(1))
                {
                    chain.ChainPolicy.ExtraStore.Add(element.Certificate);
                }
            }

            return chain.Build(server);
        }

        public void Dispose()
        {
            UnregisteredClient.Dispose();
            RecoveryClient.Dispose();
            MalformedIdentityClient.Dispose();
            Client.Dispose();
            Server.Dispose();
            ServerKey.Dispose();
            Intermediate?.Dispose();
            intermediateKey?.Dispose();
            Root.Dispose();
            unregisteredKey.Dispose();
            recoveryKey.Dispose();
            malformedIdentityKey.Dispose();
            clientKey.Dispose();
            rootKey.Dispose();
        }

        private X509Certificate2 Issue(
            string subject,
            ECDsa key,
            string purpose,
            DateTimeOffset now,
            Action<SubjectAlternativeNameBuilder> configureSan)
        {
            var request = new CertificateRequest(subject, key, HashAlgorithmName.SHA256);
            if (!omitLeafBasicConstraints)
            {
                request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            }
            request.CertificateExtensions.Add(new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature, true));
            var purposes = new OidCollection { new Oid(purpose) };
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(purposes, true));
            var san = new SubjectAlternativeNameBuilder();
            configureSan(san);
            request.CertificateExtensions.Add(san.Build());

            using var publicCertificate = request.Create(
                Intermediate ?? Root, now.AddHours(-1), now.AddDays(1), Guid.NewGuid().ToByteArray());
            using var withPrivateKey = publicCertificate.CopyWithPrivateKey(key);
            var bundle = new X509Certificate2Collection { withPrivateKey };
            if (Intermediate is not null) { bundle.Add(Intermediate); }
            var pkcs12 = bundle.Export(X509ContentType.Pkcs12)!;
            try
            {
                return X509CertificateLoader.LoadPkcs12(
                    pkcs12, null, X509KeyStorageFlags.UserKeySet);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(pkcs12);
            }
        }
    }
}
