using System.Security.Cryptography;
using Fleetory.Core.Contracts;
using Fleetory.Core.Security;
using Fleetory.Platform.Authorization;
using Fleetory.Platform.Contracts;
using Fleetory.Platform.Persistence;
using Fleetory.Security.Infrastructure;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using NpgsqlTypes;

namespace ServerBackendProbe;

internal static class RegistryCases
{
    internal const string DenialAction = "admin.certificate.unregistered_denied";
    internal static string Correlation(int port, bool registered = false) =>
        (registered ? "native-registered-" : "native-registry-") + (port switch
    {
        19581 => "agent", 19582 => "admin",
        _ => throw new InvalidOperationException("Unknown registry fixture endpoint.")
    });

    internal static async Task<object> ExecuteAsync(IServiceProvider services, TlsObservation observation,
        CancellationToken cancellation, bool registered = false)
    {
        var files = new FileSecretProvider(Program.PrivateDirectory);
        using var agentRoot = ClientTlsCases.ReadCertificate(files, "agent-gateway-root-ca");
        using var adminRoot = ClientTlsCases.ReadCertificate(files, "admin-gateway-root-ca");
        using var agent = ClientTlsCases.ReadKeyPair(files, "agent-gateway-identity");
        using var admin = ClientTlsCases.ReadKeyPair(files, "admin-gateway-identity");
        var agentHash = Convert.ToHexString(SHA256.HashData(agent.RawData));
        var adminHash = Convert.ToHexString(SHA256.HashData(admin.RawData));
        if (agentHash == adminHash || !AgentCertificateIdentity.TryReadDeviceId(agent, out var device) ||
            !AdminCertificateIdentity.TryReadActor(admin, out var actor) || actor is null)
        { throw new InvalidOperationException("Generated registry identity preflight failed."); }
        await using var scope = services.CreateAsyncScope();
        var binding = await scope.ServiceProvider.GetRequiredService<IAgentCertificateBindingVerifier>()
            .VerifyAsync(device, agent, cancellation);
        var registration = await scope.ServiceProvider.GetRequiredService<IAdminCertificateAccessStore>()
            .CheckAsync(adminHash, actor.SubjectId, true, cancellation);
        if (binding != (registered ? AgentCertificateStatus.Accepted : AgentCertificateStatus.UnknownCertificate) ||
            registration.Status != (registered ? AdminCertificateAccess.Accepted : AdminCertificateAccess.Unregistered))
        { throw new InvalidOperationException("Native registry store preflight drift."); }
        var database = scope.ServiceProvider.GetRequiredService<PlatformDbContext>();
        await database.Database.OpenConnectionAsync(cancellation);
        var connection = (NpgsqlConnection)database.Database.GetDbConnection();
        var inventory = new Inventory(agentHash, adminHash, actor.SubjectId, device.Value,
            agent.NotBefore.ToUniversalTime(), agent.NotAfter.ToUniversalTime(), admin.NotBefore.ToUniversalTime(), registered);
        if (registered)
        {
            await RequireInsertDeniedAsync(connection, "INSERT INTO core.agent_certificates SELECT * FROM core.agent_certificates WHERE FALSE;", cancellation);
            await RequireInsertDeniedAsync(connection, "INSERT INTO platform.admin_certificate_registrations SELECT * FROM platform.admin_certificate_registrations WHERE FALSE;", cancellation);
        }
        var events = registered ? 5 : 4;
        await RequireInventoryAsync(connection, inventory, events, 0, cancellation);
        WorkerCases.RequireQueue(await WorkerCases.ReadQueueAsync(database, cancellation), 0, 0);
        await ClientTlsCases.RequireRegistryRefusalAsync(19581, agentRoot, agent, observation, cancellation, registered);
        await RequireInventoryAsync(connection, inventory, events, 0, cancellation);
        await ClientTlsCases.RequireRegistryRefusalAsync(19582, adminRoot, admin, observation, cancellation, registered);
        await RequireInventoryAsync(connection, inventory, events + 1, 1, cancellation);
        while ((await WorkerCases.ReadQueueAsync(database, cancellation)).Rows != 0)
        { await Task.Delay(TimeSpan.FromMilliseconds(50), cancellation); }
        WorkerCases.RequireQueue(await WorkerCases.ReadQueueAsync(database, cancellation), 0, 0);
        return new { sanParsersAccepted = 2, runtimeStorePreflights = 2, absentRegistryInventories = registered ? 0 : 3,
            registeredInventories = registered ? 3 : 0,
            agentStatus = binding.ToString(), adminStatus = registration.Status.ToString(),
            mutualTlsHttpRefusals = registered ? 1 : 2, statusCode = registered ? 401 : 403, emptyBodies = true, correlatedPrivateGets = 2,
            agentHttpStatus = registered ? 204 : 403, adminHttpStatus = registered ? 401 : 403,
            runtimeIdentityInsertRefusals = registered ? 2 : 0, agentBindingAdmissionVerified = registered,
            newAdminDenialEvents = 1, denialAction = registered ? "admin.oidc.denied" : DenialAction, correlation = Correlation(19582, registered),
            actorSubjectId = actor.SubjectId, actorKind = (int)ActorKind.Person, certificateSha256 = adminHash, automaticWorkerDrain = true,
            positiveIdentityAdmissionVerified = false };
    }

    private sealed record Inventory(string Agent, string Admin, string Subject, Guid Device,
        DateTime AgentBefore, DateTime AgentAfter, DateTime AdminBefore, bool Registered);

    private static async Task RequireInsertDeniedAsync(NpgsqlConnection connection, string sql, CancellationToken cancellation)
    {
        await using var command = new NpgsqlCommand(sql, connection);
        try { await command.ExecuteNonQueryAsync(cancellation); }
        catch (PostgresException exception) when (exception.SqlState == PostgresErrorCodes.InsufficientPrivilege) { return; }
        throw new InvalidOperationException("Runtime identity INSERT unexpectedly permitted.");
    }

    private static async Task RequireInventoryAsync(NpgsqlConnection connection, Inventory expected,
        int events, int denials, CancellationToken cancellation)
    {
        await using var command = new NpgsqlCommand("""
            SELECT (CASE WHEN @registered THEN
                  EXISTS(SELECT 1 FROM core.devices WHERE device_id=@device AND display_name='Native registered fixture'
                    AND updated_at=@agent_before AND revision=1)
                  AND EXISTS(SELECT 1 FROM core.agent_certificates WHERE certificate_sha256=@agent AND device_id=@device
                    AND not_before=@agent_before AND not_after=@agent_after AND revoked_at IS NULL)
                  AND EXISTS(SELECT 1 FROM platform.admin_certificate_registrations WHERE certificate_sha256=@admin
                    AND actor_subject_id=@subject AND registered_at=@admin_before AND overlap_ends_at IS NULL
                    AND previous_certificate_sha256 IS NULL AND incident_reference='fixture-not-approval'
                    AND operator_reference='fixture-not-approval')
                ELSE NOT EXISTS(SELECT 1 FROM core.agent_certificates WHERE certificate_sha256=@agent)
                  AND NOT EXISTS(SELECT 1 FROM platform.admin_certificate_registrations WHERE certificate_sha256=@admin) END)
              AND NOT EXISTS(SELECT 1 FROM platform.admin_certificate_revocations WHERE certificate_sha256=@admin)
              AND (SELECT count(*) FROM platform.audit_events)=@events
              AND (SELECT count(*) FROM platform.audit_events WHERE action=@action)=@denials
              AND (SELECT count(*) FROM platform.audit_events WHERE action=@action
                    AND actor_subject_id=@subject AND actor_kind=@kind AND correlation_id=@correlation
                    AND ((@registered AND target_type IS NULL AND target_id IS NULL) OR
                         (NOT @registered AND target_type='admin_certificate' AND target_id=@admin)))=@denials;
            """, connection);
        foreach (var (name, type, value) in new (string, NpgsqlDbType, object)[] {
            ("agent", NpgsqlDbType.Varchar, expected.Agent), ("admin", NpgsqlDbType.Varchar, expected.Admin),
            ("subject", NpgsqlDbType.Varchar, expected.Subject), ("device", NpgsqlDbType.Uuid, expected.Device),
            ("agent_before", NpgsqlDbType.TimestampTz, expected.AgentBefore), ("agent_after", NpgsqlDbType.TimestampTz, expected.AgentAfter),
            ("admin_before", NpgsqlDbType.TimestampTz, expected.AdminBefore), ("registered", NpgsqlDbType.Boolean, expected.Registered),
            ("action", NpgsqlDbType.Varchar, expected.Registered ? "admin.oidc.denied" : DenialAction),
            ("correlation", NpgsqlDbType.Varchar, Correlation(19582, expected.Registered)),
            ("kind", NpgsqlDbType.Integer, (int)ActorKind.Person), ("events", NpgsqlDbType.Integer, events),
            ("denials", NpgsqlDbType.Integer, denials) }) { command.Parameters.AddWithValue(name, type, value); }
        if (await command.ExecuteScalarAsync(cancellation) is not true)
        { throw new InvalidOperationException("Native registry/audit inventory drift."); }
    }
}
