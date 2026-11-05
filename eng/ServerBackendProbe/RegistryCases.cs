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
    internal static string Correlation(int port) => port switch
    {
        19581 => "native-registry-agent", 19582 => "native-registry-admin",
        _ => throw new InvalidOperationException("Unknown registry fixture endpoint.")
    };

    internal static async Task<object> ExecuteAsync(IServiceProvider services, TlsObservation observation,
        CancellationToken cancellation)
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
        if (binding != AgentCertificateStatus.UnknownCertificate || registration.Status != AdminCertificateAccess.Unregistered)
        { throw new InvalidOperationException("Native registry store preflight drift."); }
        var database = scope.ServiceProvider.GetRequiredService<PlatformDbContext>();
        await database.Database.OpenConnectionAsync(cancellation);
        var connection = (NpgsqlConnection)database.Database.GetDbConnection();
        await RequireInventoryAsync(connection, agentHash, adminHash, actor.SubjectId, 4, 0, cancellation);
        WorkerCases.RequireQueue(await WorkerCases.ReadQueueAsync(database, cancellation), 0, 0);
        await ClientTlsCases.RequireRegistryRefusalAsync(19581, agentRoot, agent, observation, cancellation);
        await RequireInventoryAsync(connection, agentHash, adminHash, actor.SubjectId, 4, 0, cancellation);
        await ClientTlsCases.RequireRegistryRefusalAsync(19582, adminRoot, admin, observation, cancellation);
        await RequireInventoryAsync(connection, agentHash, adminHash, actor.SubjectId, 5, 1, cancellation);
        while ((await WorkerCases.ReadQueueAsync(database, cancellation)).Rows != 0)
        { await Task.Delay(TimeSpan.FromMilliseconds(50), cancellation); }
        WorkerCases.RequireQueue(await WorkerCases.ReadQueueAsync(database, cancellation), 0, 0);
        return new { sanParsersAccepted = 2, runtimeStorePreflights = 2, absentRegistryInventories = 3,
            agentStatus = binding.ToString(), adminStatus = registration.Status.ToString(),
            mutualTlsHttpRefusals = 2, statusCode = 403, emptyBodies = true, correlatedPrivateGets = 2,
            newAdminDenialEvents = 1, denialAction = DenialAction, correlation = Correlation(19582),
            actorSubjectId = actor.SubjectId, actorKind = (int)ActorKind.Person, certificateSha256 = adminHash, automaticWorkerDrain = true,
            positiveIdentityAdmissionVerified = false };
    }

    private static async Task RequireInventoryAsync(NpgsqlConnection connection, string agent, string admin,
        string subject, int events, int denials, CancellationToken cancellation)
    {
        await using var command = new NpgsqlCommand("""
            SELECT NOT EXISTS(SELECT 1 FROM core.agent_certificates WHERE certificate_sha256=@agent)
              AND NOT EXISTS(SELECT 1 FROM platform.admin_certificate_registrations WHERE certificate_sha256=@admin)
              AND NOT EXISTS(SELECT 1 FROM platform.admin_certificate_revocations WHERE certificate_sha256=@admin)
              AND (SELECT count(*) FROM platform.audit_events)=@events
              AND (SELECT count(*) FROM platform.audit_events WHERE action=@action)=@denials
              AND (SELECT count(*) FROM platform.audit_events WHERE action=@action
                    AND actor_subject_id=@subject AND actor_kind=@kind AND target_type='admin_certificate'
                    AND target_id=@admin AND correlation_id=@correlation)=@denials;
            """, connection);
        command.Parameters.AddWithValue("agent", NpgsqlDbType.Varchar, agent);
        command.Parameters.AddWithValue("admin", NpgsqlDbType.Varchar, admin);
        command.Parameters.AddWithValue("subject", NpgsqlDbType.Varchar, subject);
        command.Parameters.AddWithValue("action", NpgsqlDbType.Varchar, DenialAction);
        command.Parameters.AddWithValue("correlation", NpgsqlDbType.Varchar, Correlation(19582));
        command.Parameters.AddWithValue("kind", NpgsqlDbType.Integer, (int)ActorKind.Person);
        command.Parameters.AddWithValue("events", NpgsqlDbType.Integer, events);
        command.Parameters.AddWithValue("denials", NpgsqlDbType.Integer, denials);
        if (await command.ExecuteScalarAsync(cancellation) is not true)
        { throw new InvalidOperationException("Native registry/audit inventory drift."); }
    }
}
