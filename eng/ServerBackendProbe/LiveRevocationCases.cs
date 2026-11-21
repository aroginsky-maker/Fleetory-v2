using Fleetory.Security.Infrastructure;

namespace ServerBackendProbe;

internal sealed record LiveRevocationResult(object Registered, object Revoked, object Connections);

internal static class LiveRevocationCases
{
    private const string ControlDirectory = "/run/fleetory-native/live";
    private static readonly int[] FirstResponses = [204, 401];
    private static readonly int[] SecondResponses = [403, 403];

    internal static async Task<LiveRevocationResult> ExecuteAsync(IServiceProvider services, CancellationToken cancellation)
    {
        var files = new FileSecretProvider(Program.PrivateDirectory);
        using var agentRoot = ClientTlsCases.ReadCertificate(files, "agent-gateway-root-ca");
        using var adminRoot = ClientTlsCases.ReadCertificate(files, "admin-gateway-root-ca");
        using var agentLeaf = ClientTlsCases.ReadKeyPair(files, "agent-gateway-identity");
        using var adminLeaf = ClientTlsCases.ReadKeyPair(files, "admin-gateway-identity");
        using var observation = new TlsObservation(true);
        using var agent = await PersistentGateway.OpenAsync(19581, agentRoot, agentLeaf, cancellation);
        using var admin = await PersistentGateway.OpenAsync(19582, adminRoot, adminLeaf, cancellation);
        var pair = new LiveGatewayPair(agent, admin, observation);
        var registered = await RegistryCases.ExecuteAsync(services, observation, CredentialState.Registered, pair, cancellation);
        await WaitForOwnerAsync(cancellation);
        var revoked = await RegistryCases.ExecuteAsync(services, observation, CredentialState.LiveRevoked, pair, cancellation);
        if (agent.CompletedConnectionId == admin.CompletedConnectionId)
        { throw new InvalidOperationException("Independent gateway connection IDs collided."); }
        return new(registered, revoked, new { connections = 2, requestsPerConnection = 2, nativeHandshakes = 2,
            replacementConnections = 0, firstResponses = FirstResponses, secondResponses = SecondResponses,
            agentConnectionId = agent.CompletedConnectionId, adminConnectionId = admin.CompletedConnectionId });
    }

    private static async Task WaitForOwnerAsync(CancellationToken cancellation)
    {
        if (!OperatingSystem.IsLinux()) { throw new InvalidOperationException("Live fixture requires its Linux sandbox."); }
        await using (var ready = new FileStream(ControlDirectory + "/ready-staging", new FileStreamOptions
        { Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None,
            UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite }))
        { await ready.WriteAsync("admitted"u8.ToArray(), cancellation); }
        File.Move(ControlDirectory + "/ready-staging", ControlDirectory + "/ready");
        while (!File.Exists(ControlDirectory + "/revoked"))
        { await Task.Delay(TimeSpan.FromMilliseconds(50), cancellation); }
        await using var done = new FileStream(ControlDirectory + "/revoked", FileMode.Open, FileAccess.Read, FileShare.Read);
        var buffer = new byte[17];
        var length = 0;
        while (length < buffer.Length)
        {
            var read = await done.ReadAsync(buffer.AsMemory(length), cancellation);
            if (read == 0) { break; }
            length += read;
        }
        if (!buffer.AsSpan(0, length).SequenceEqual("revoked"u8))
        { throw new InvalidOperationException("Owner fixture signal drift."); }
    }
}
