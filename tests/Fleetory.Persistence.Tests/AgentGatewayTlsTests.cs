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
    public async Task Admin_gateway_limits_requests_before_repeated_authorization_work()
    {
        using var adminPki = new TestPki(new Uri($"urn:fleetory:admin:{Guid.NewGuid():D}"));
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
            var url = $"https://127.0.0.1:{adminPort}/admin/devices/{Guid.NewGuid():D}/enrollment-grants";
            for (var attempt = 0; attempt < 3; attempt++)
            {
                using var denied = await admin.PostAsJsonAsync(url, new { displayName = "denied" });
                Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);
            }

            using var limited = await admin.PostAsJsonAsync(url, new { displayName = "denied" });
            Assert.Equal(HttpStatusCode.TooManyRequests, limited.StatusCode);
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
                actor, deviceId, "audit test device", CorrelationId.New()));
        Assert.False(await database.Devices.AnyAsync(row => row.DeviceId == deviceId));
        Assert.False(await database.AgentEnrollmentGrants.AnyAsync(row => row.DeviceId == deviceId));

        var service = services.GetRequiredService<AgentEnrollmentService>();
        var token = await service.CreateGrantAsync(
            actor, deviceId, "audit test device", CorrelationId.New());
        await Assert.ThrowsAsync<UnauthorizedAccessException>(async () =>
            await service.EnrollAsync(new DeviceId(Guid.NewGuid()), pki.Client,
                token, CorrelationId.New()));
        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await unavailableAudit.EnrollAsync(deviceId, pki.Client,
                token, CorrelationId.New()));
        Assert.False(await database.AgentCertificates.AnyAsync(row => row.DeviceId == deviceId));
        Assert.True(await database.AgentEnrollmentGrants.AnyAsync(
            row => row.DeviceId == deviceId && row.ConsumedAt == null));

        await service.EnrollAsync(deviceId, pki.Client, token, CorrelationId.New());
        Assert.True(await database.AgentCertificates.AnyAsync(row => row.DeviceId == deviceId));
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
                    deviceId, "concurrent device", CorrelationId.New());
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
        using var agentPki = new TestPki(deviceId);
        using var adminPki = new TestPki(new Uri($"urn:fleetory:admin:{adminId:D}"));
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
        await app.StartAsync();
        try
        {
            using var agent = agentPki.CreateClient(agentPki.Client);
            using var admin = adminPki.CreateClient(adminPki.Client);
            using var web = new HttpClient();
            var agentBase = $"https://127.0.0.1:{ports[1]}";
            var grantUrl = $"https://127.0.0.1:{ports[2]}/admin/devices/{deviceId.Value:D}/enrollment-grants";

            using var before = await agent.GetAsync($"{agentBase}/agent/identity");
            Assert.Equal(HttpStatusCode.Forbidden, before.StatusCode);
            using var noGrant = await agent.PostAsJsonAsync(
                $"{agentBase}/agent/enroll", new { token = new string('A', 64) });
            Assert.Equal(HttpStatusCode.Forbidden, noGrant.StatusCode);
            using var denied = await admin.PostAsJsonAsync(grantUrl, new { displayName = "enrolled device" });
            Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);

            await GrantAdminPermissionAsync(adminId, AgentEnrollmentService.Permission);
            using var invalidBody = await admin.PostAsync(grantUrl,
                new StringContent("not json"));
            Assert.Equal(HttpStatusCode.BadRequest, invalidBody.StatusCode);
            using var oversized = await admin.PostAsJsonAsync(grantUrl,
                new { displayName = new string('x', 2048) });
            Assert.Equal(HttpStatusCode.BadRequest, oversized.StatusCode);
            using var grant = await admin.PostAsJsonAsync(grantUrl, new { displayName = "enrolled device" });
            Assert.Equal(HttpStatusCode.OK, grant.StatusCode);
            Assert.Equal("no-store", grant.Headers.CacheControl?.ToString());
            var response = await grant.Content.ReadFromJsonAsync<System.Text.Json.JsonElement>();
            var token = response.GetProperty("token").GetString();
            Assert.NotNull(token);
            Assert.Equal(64, token.Length);

            using var webAttempt = await web.PostAsJsonAsync(
                $"http://127.0.0.1:{ports[0]}/agent/enroll", new { token });
            Assert.Equal(HttpStatusCode.NotFound, webAttempt.StatusCode);
            using var malformedIdentity = agentPki.CreateClient(agentPki.MalformedIdentityClient);
            using var malformed = await malformedIdentity.PostAsJsonAsync(
                $"{agentBase}/agent/enroll", new { token });
            Assert.Equal(HttpStatusCode.Forbidden, malformed.StatusCode);
            using var enrolled = await agent.PostAsJsonAsync($"{agentBase}/agent/enroll", new { token });
            Assert.Equal(HttpStatusCode.NoContent, enrolled.StatusCode);
            using var identity = await agent.GetAsync($"{agentBase}/agent/identity");
            Assert.Equal(HttpStatusCode.NoContent, identity.StatusCode);
            using var replay = await agent.PostAsJsonAsync($"{agentBase}/agent/enroll", new { token });
            Assert.Equal(HttpStatusCode.Forbidden, replay.StatusCode);

            using var candidate = agentPki.CreateClient(agentPki.UnregisteredClient);
            using var expiringGrant = await admin.PostAsJsonAsync(
                grantUrl, new { displayName = "ignored for existing device" });
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
            using var rotationGrant = await admin.PostAsJsonAsync(
                grantUrl, new { displayName = "ignored for existing device" });
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
            $"--Fleetory:Web:Port={webPort}",
            $"--Fleetory:AdminGateway:Port={adminPort}"
        ]);
        await app.StartAsync();
        try
        {
            using var admin = pki.CreateClient(pki.Client);
            using var web = new HttpClient();
            var baseUrl = $"https://127.0.0.1:{adminPort}/admin/authorization";
            var roleBody = new { name = "mTLS managed reader", permissions = new[] { "Core.Device.Read" } };
            using var denied = await admin.PostAsJsonAsync($"{baseUrl}/roles", roleBody);
            Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);
            using var deniedRetirement = await admin.DeleteAsync(
                $"{baseUrl}/roles/{Guid.NewGuid():D}");
            Assert.Equal(HttpStatusCode.Forbidden, deniedRetirement.StatusCode);
            using var webAttempt = await web.PostAsJsonAsync(
                $"http://127.0.0.1:{webPort}/admin/authorization/roles", roleBody);
            Assert.Equal(HttpStatusCode.NotFound, webAttempt.StatusCode);
            using var webRetirement = await web.DeleteAsync(
                $"http://127.0.0.1:{webPort}/admin/authorization/roles/{Guid.NewGuid():D}");
            Assert.Equal(HttpStatusCode.NotFound, webRetirement.StatusCode);

            await GrantAdminPermissionAsync(adminId, "platform.authorization.manage");
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
    }

    private sealed class TestPki : IDisposable
    {
        private readonly ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        private readonly ECDsa? intermediateKey;
        private readonly bool omitLeafBasicConstraints;
        private readonly ECDsa clientKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        private readonly ECDsa unregisteredKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
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
            var rootRequest = new CertificateRequest("CN=Fleetory Test CA", rootKey, HashAlgorithmName.SHA256);
            rootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            rootRequest.CertificateExtensions.Add(new X509KeyUsageExtension(
                X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
            Root = rootRequest.CreateSelfSigned(now.AddDays(-1), now.AddDays(7));

            if (useIntermediate)
            {
                intermediateKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
                var request = new CertificateRequest("CN=Fleetory Test Intermediate",
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
            MalformedIdentityClient.Dispose();
            Client.Dispose();
            Server.Dispose();
            ServerKey.Dispose();
            Intermediate?.Dispose();
            intermediateKey?.Dispose();
            Root.Dispose();
            unregisteredKey.Dispose();
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
