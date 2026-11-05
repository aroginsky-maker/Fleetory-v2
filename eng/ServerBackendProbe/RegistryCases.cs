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

internal enum CredentialState { Unregistered, Registered, Revoked }

internal static class RegistryCases
{
    internal const string DenialAction = "admin.certificate.unregistered_denied";
    internal static string Correlation(int port, CredentialState state) =>
        (state switch
        {
            CredentialState.Unregistered => "native-registry-",
            CredentialState.Registered => "native-registered-",
            CredentialState.Revoked => "native-revoked-",
            _ => throw new InvalidOperationException("Unknown fixture credential state.")
        }) + (port switch
    {
        19581 => "agent", 19582 => "admin",
        _ => throw new InvalidOperationException("Unknown registry fixture endpoint.")
    });

    internal static async Task<object> ExecuteAsync(IServiceProvider services, TlsObservation observation,
        CredentialState state, CancellationToken cancellation)
    {
        var (expectedAgent, expectedAdmin, events, action) = state switch
        {
            CredentialState.Unregistered => (AgentCertificateStatus.UnknownCertificate, AdminCertificateAccess.Unregistered, 4, DenialAction),
            CredentialState.Registered => (AgentCertificateStatus.Accepted, AdminCertificateAccess.Accepted, 5, "admin.oidc.denied"),
            CredentialState.Revoked => (AgentCertificateStatus.Revoked, AdminCertificateAccess.Revoked, 6, "admin.certificate.revoked_denied"),
            _ => throw new InvalidOperationException("Unknown fixture credential state.")
        };
        var registered = state != CredentialState.Unregistered;
        var admitted = state == CredentialState.Registered;
        var revoked = state == CredentialState.Revoked;
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
        if (binding != expectedAgent || registration.Status != expectedAdmin)
        { throw new InvalidOperationException("Native registry store preflight drift."); }
        var database = scope.ServiceProvider.GetRequiredService<PlatformDbContext>();
        await database.Database.OpenConnectionAsync(cancellation);
        var connection = (NpgsqlConnection)database.Database.GetDbConnection();
        var inventory = new Inventory(agentHash, adminHash, actor.SubjectId, device.Value,
            agent.NotBefore.ToUniversalTime(), agent.NotAfter.ToUniversalTime(), admin.NotBefore.ToUniversalTime(),
            admin.NotAfter.ToUniversalTime(), state, revoked ? await ReadRevokedAtAsync(connection, agentHash, cancellation) : null);
        if (registered)
        {
            await RequireWriteDeniedAsync(connection, "INSERT INTO core.agent_certificates SELECT * FROM core.agent_certificates WHERE FALSE;", cancellation);
            await RequireWriteDeniedAsync(connection, "INSERT INTO platform.admin_certificate_registrations SELECT * FROM platform.admin_certificate_registrations WHERE FALSE;", cancellation);
        }
        if (revoked)
        {
            await RequireWriteDeniedAsync(connection, "UPDATE core.agent_certificates SET revoked_at=NULL WHERE FALSE;", cancellation);
            await RequireWriteDeniedAsync(connection, "INSERT INTO platform.admin_certificate_revocations SELECT * FROM platform.admin_certificate_revocations WHERE FALSE;", cancellation);
        }
        await RequireInventoryAsync(connection, inventory, events, 0, cancellation);
        WorkerCases.RequireQueue(await WorkerCases.ReadQueueAsync(database, cancellation), 0, 0);
        await ClientTlsCases.RequireRegistryResponseAsync(19581, agentRoot, agent, observation, state, cancellation);
        await RequireInventoryAsync(connection, inventory, events, 0, cancellation);
        await ClientTlsCases.RequireRegistryResponseAsync(19582, adminRoot, admin, observation, state, cancellation);
        await RequireInventoryAsync(connection, inventory, events + 1, 1, cancellation);
        while ((await WorkerCases.ReadQueueAsync(database, cancellation)).Rows != 0)
        { await Task.Delay(TimeSpan.FromMilliseconds(50), cancellation); }
        WorkerCases.RequireQueue(await WorkerCases.ReadQueueAsync(database, cancellation), 0, 0);
        return new { sanParsersAccepted = 2, runtimeStorePreflights = 2, absentRegistryInventories = registered ? 0 : 3,
            registeredInventories = admitted ? 3 : 0, revokedInventories = revoked ? 3 : 0,
            agentStatus = binding.ToString(), adminStatus = registration.Status.ToString(),
            mutualTlsHttpRefusals = admitted ? 1 : 2, statusCode = admitted ? 401 : 403, emptyBodies = true, correlatedPrivateGets = 2,
            agentHttpStatus = admitted ? 204 : 403, adminHttpStatus = admitted ? 401 : 403,
            runtimeIdentityInsertRefusals = registered ? 2 : 0, runtimeRevocationWriteRefusals = revoked ? 2 : 0,
            agentBindingAdmissionVerified = admitted, durableRevocationVerified = revoked,
            newAdminDenialEvents = 1, denialAction = action, correlation = Correlation(19582, state),
            actorSubjectId = actor.SubjectId, actorKind = (int)ActorKind.Person, certificateSha256 = adminHash, automaticWorkerDrain = true,
            positiveIdentityAdmissionVerified = false };
    }

    private sealed record Inventory(string Agent, string Admin, string Subject, Guid Device,
        DateTime AgentBefore, DateTime AgentAfter, DateTime AdminBefore, DateTime AdminAfter,
        CredentialState State, DateTime? RevokedAt);

    private static async Task<DateTime> ReadRevokedAtAsync(NpgsqlConnection connection, string hash, CancellationToken cancellation)
    {
        await using var command = new NpgsqlCommand("SELECT revoked_at FROM core.agent_certificates WHERE certificate_sha256=@hash;", connection);
        command.Parameters.AddWithValue("hash", NpgsqlDbType.Varchar, hash);
        return await command.ExecuteScalarAsync(cancellation) is DateTime instant ? instant :
            throw new InvalidOperationException("Fixture revocation timestamp absent.");
    }

    private static async Task RequireWriteDeniedAsync(NpgsqlConnection connection, string sql, CancellationToken cancellation)
    {
        await using var command = new NpgsqlCommand(sql, connection);
        try { await command.ExecuteNonQueryAsync(cancellation); }
        catch (PostgresException exception) when (exception.SqlState == PostgresErrorCodes.InsufficientPrivilege) { return; }
        throw new InvalidOperationException("Runtime identity write unexpectedly permitted.");
    }

    private static async Task RequireInventoryAsync(NpgsqlConnection connection, Inventory expected,
        int events, int denials, CancellationToken cancellation)
    {
        await using var command = new NpgsqlCommand("""
            SELECT (CASE WHEN @registered THEN
                  EXISTS(SELECT 1 FROM core.devices WHERE device_id=@device AND display_name='Native registered fixture'
                    AND updated_at=@agent_before AND revision=1)
                  AND EXISTS(SELECT 1 FROM core.agent_certificates WHERE certificate_sha256=@agent AND device_id=@device
                    AND not_before=@agent_before AND not_after=@agent_after
                    AND ((NOT @revoked AND revoked_at IS NULL) OR (@revoked AND revoked_at=@revoked_at)))
                  AND EXISTS(SELECT 1 FROM platform.admin_certificate_registrations WHERE certificate_sha256=@admin
                    AND actor_subject_id=@subject AND registered_at=@admin_before AND overlap_ends_at IS NULL
                    AND previous_certificate_sha256 IS NULL AND incident_reference='fixture-not-approval'
                    AND operator_reference='fixture-not-approval')
                ELSE NOT EXISTS(SELECT 1 FROM core.agent_certificates WHERE certificate_sha256=@agent)
                  AND NOT EXISTS(SELECT 1 FROM platform.admin_certificate_registrations WHERE certificate_sha256=@admin) END)
              AND (CASE WHEN @revoked THEN
                EXISTS(SELECT 1 FROM platform.admin_certificate_revocations WHERE certificate_sha256=@admin
                  AND revoked_at=@revoked_at AND incident_reference='fixture-not-approval' AND operator_reference='fixture-not-approval')
                AND @revoked_at>=@agent_before AND @revoked_at>=@admin_before AND @revoked_at<=clock_timestamp()
                AND clock_timestamp()<@agent_after AND clock_timestamp()<@admin_after
                ELSE NOT EXISTS(SELECT 1 FROM platform.admin_certificate_revocations WHERE certificate_sha256=@admin) END)
              AND (SELECT count(*) FROM platform.audit_events)=@events
              AND (SELECT count(*) FROM platform.audit_events WHERE action=@action)=@denials
              AND (SELECT count(*) FROM platform.audit_events WHERE action=@action
                    AND actor_subject_id=@subject AND actor_kind=@kind AND correlation_id=@correlation
                    AND ((@oidc AND target_type IS NULL AND target_id IS NULL) OR
                         (NOT @oidc AND target_type='admin_certificate' AND target_id=@admin)))=@denials;
            """, connection);
        foreach (var (name, type, value) in new (string, NpgsqlDbType, object)[] {
            ("agent", NpgsqlDbType.Varchar, expected.Agent), ("admin", NpgsqlDbType.Varchar, expected.Admin),
            ("subject", NpgsqlDbType.Varchar, expected.Subject), ("device", NpgsqlDbType.Uuid, expected.Device),
            ("agent_before", NpgsqlDbType.TimestampTz, expected.AgentBefore), ("agent_after", NpgsqlDbType.TimestampTz, expected.AgentAfter),
            ("admin_before", NpgsqlDbType.TimestampTz, expected.AdminBefore), ("admin_after", NpgsqlDbType.TimestampTz, expected.AdminAfter),
            ("registered", NpgsqlDbType.Boolean, expected.State != CredentialState.Unregistered),
            ("revoked", NpgsqlDbType.Boolean, expected.State == CredentialState.Revoked),
            ("revoked_at", NpgsqlDbType.TimestampTz, (object?)expected.RevokedAt ?? DBNull.Value),
            ("oidc", NpgsqlDbType.Boolean, expected.State == CredentialState.Registered),
            ("action", NpgsqlDbType.Varchar, expected.State switch { CredentialState.Registered => "admin.oidc.denied",
                CredentialState.Revoked => "admin.certificate.revoked_denied", _ => DenialAction }),
            ("correlation", NpgsqlDbType.Varchar, Correlation(19582, expected.State)),
            ("kind", NpgsqlDbType.Integer, (int)ActorKind.Person), ("events", NpgsqlDbType.Integer, events),
            ("denials", NpgsqlDbType.Integer, denials) }) { command.Parameters.AddWithValue(name, type, value); }
        if (await command.ExecuteScalarAsync(cancellation) is not true)
        { throw new InvalidOperationException("Native registry/audit inventory drift."); }
    }
}
