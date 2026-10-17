using Fleetory.Core.Contracts;
using Fleetory.Core.Persistence;
using Fleetory.Core.Security;
using Fleetory.Platform.Contracts;
using Fleetory.SharedKernel;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;

namespace Fleetory.Persistence.Tests;

[Collection(PostgreSqlTestCollection.Name)]
public sealed class AgentCertificateRevocationTests(PostgreSqlTestFixture fixture)
{
    [Fact]
    public async Task Revocation_requires_a_grant_and_durable_audit_before_state_changes()
    {
        var deviceId = new DeviceId(Guid.NewGuid());
        var fingerprint = Convert.ToHexString(Guid.NewGuid().ToByteArray()) +
            Convert.ToHexString(Guid.NewGuid().ToByteArray());
        var actor = new ActorReference($"person:{Guid.NewGuid():N}", ActorKind.Person);
        var deniedCorrelation = CorrelationId.New();
        var acceptedCorrelation = CorrelationId.New();

        await using var scope = fixture.Services.CreateAsyncScope();
        var database = scope.ServiceProvider.GetRequiredService<CoreDbContext>();
        database.Devices.Add(DeviceRecord.Create(deviceId, "revocation test device", DateTimeOffset.UtcNow));
        database.AgentCertificates.Add(AgentCertificateRecord.Create(
            deviceId, fingerprint, DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(1)));
        await database.SaveChangesAsync();

        var service = scope.ServiceProvider.GetRequiredService<AgentCertificateRevocationService>();
        await Assert.ThrowsAsync<UnauthorizedAccessException>(async () =>
            await service.RevokeAsync(actor, deviceId, fingerprint, deniedCorrelation));
        Assert.Null(await ReadRevocationAsync(database, fingerprint));
        Assert.Equal("core.agent_certificate.revoke_denied",
            await ReadAuditActionAsync(deniedCorrelation));

        await GrantRevocationAsync(actor);
        var noAudit = new AgentCertificateRevocationService(
            scope.ServiceProvider.GetRequiredService<IAuthorizationService>(),
            new FailingAuditWriter(), database,
            scope.ServiceProvider.GetRequiredService<IClock>());
        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await noAudit.RevokeAsync(actor, deviceId, fingerprint, CorrelationId.New()));
        Assert.Null(await ReadRevocationAsync(database, fingerprint));

        Assert.False(await service.RevokeAsync(
            actor, new DeviceId(Guid.NewGuid()), fingerprint, CorrelationId.New()));
        Assert.Null(await ReadRevocationAsync(database, fingerprint));

        Assert.True(await service.RevokeAsync(actor, deviceId, fingerprint, acceptedCorrelation));
        Assert.NotNull(await ReadRevocationAsync(database, fingerprint));
        Assert.Equal("core.agent_certificate.revoke_requested",
            await ReadAuditActionAsync(acceptedCorrelation));
        Assert.False(await service.RevokeAsync(actor, deviceId, fingerprint, CorrelationId.New()));
    }

    private static async Task<DateTimeOffset?> ReadRevocationAsync(
        CoreDbContext database, string fingerprint) =>
        await database.AgentCertificates.AsNoTracking()
            .Where(row => row.CertificateSha256 == fingerprint)
            .Select(row => row.RevokedAt)
            .SingleAsync();

    private async Task<string?> ReadAuditActionAsync(CorrelationId correlation)
    {
        await using var connection = new NpgsqlConnection(fixture.ConnectionString);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand(
            "SELECT action FROM platform.audit_events WHERE correlation_id = @correlation_id",
            connection);
        command.Parameters.AddWithValue("correlation_id", correlation.Value);
        return (string?)await command.ExecuteScalarAsync();
    }

    private async Task GrantRevocationAsync(ActorReference actor)
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
        command.Parameters.AddWithValue("name", $"Revoker {roleId:N}");
        command.Parameters.AddWithValue("permission", AgentCertificateRevocationService.Permission);
        command.Parameters.AddWithValue("assignment_id", Guid.NewGuid());
        command.Parameters.AddWithValue("actor_subject_id", actor.SubjectId);
        command.Parameters.AddWithValue("actor_kind", (int)actor.Kind);
        await command.ExecuteNonQueryAsync();
    }

    private sealed class FailingAuditWriter : IAuditWriter
    {
        public ValueTask WriteAsync(AuditRecord record, CancellationToken cancellationToken = default) =>
            ValueTask.FromException(new InvalidOperationException("Audit unavailable."));
    }
}
