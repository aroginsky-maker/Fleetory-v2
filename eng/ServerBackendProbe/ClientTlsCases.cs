using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Fleetory.Security.Infrastructure;

namespace ServerBackendProbe;

internal static class ClientTlsCases
{
    private const string ClientPurpose = "1.3.6.1.5.5.7.3.2";
    private const string ServerPurpose = "1.3.6.1.5.5.7.3.1";
    private enum TlsCase { Trusted, Identity, Registry, Registered, MissingClient, CrossRootClient, WrongEkuClient, ServerRoot, ServerHostname }

    internal static async Task<object> ExecuteAsync(IServiceProvider services, CancellationToken cancellation)
    {
        var files = new FileSecretProvider(Program.PrivateDirectory);
        using var agentRoot = ReadCertificate(files, "agent-gateway-root-ca");
        using var adminRoot = ReadCertificate(files, "admin-gateway-root-ca");
        using var agentClient = ReadKeyPair(files, "agent-gateway-client");
        using var adminClient = ReadKeyPair(files, "admin-gateway-client");
        using var agentServer = ReadKeyPair(files, "agent-gateway-server");
        using var adminServer = ReadKeyPair(files, "admin-gateway-server");
        if (agentRoot.RawData.AsSpan().SequenceEqual(adminRoot.RawData))
        { throw Failure("IndependentRoots"); }
        using var observation = new TlsObservation();
        await GatewayAsync(19581, agentRoot, adminRoot, agentClient, adminClient, agentServer, observation, cancellation);
        await GatewayAsync(19582, adminRoot, agentRoot, adminClient, agentClient, adminServer, observation, cancellation);
        var registry = await RegistryCases.ExecuteAsync(services, observation, cancellation);
        return new { gateways = 2, trustedClientHttpResponses = 2, missingClientRefusals = 2,
            crossRootClientRefusals = 2, wrongEkuClientRefusals = 2, serverRootRefusals = 2,
            serverHostnameRefusals = 2, protocol = "TLS1.2", responseStatus = 404,
            nativeAuthenticationRefusals = 10, serverCorrelatedHandshakeRefusals = 6,
            serverCorrelatedTrustedHandshakes = 6, httpRequestsInClientRefusals = 0, arbitraryTransportFailuresAccepted = 0,
            identityBoundary = new { mutualTlsHttpRefusals = 2, statusCode = 403, emptyBodies = true,
                clientsWithoutSan = 2, correlatedPrivateGets = 2, positiveIdentityAdmissionVerified = false },
            registryBoundary = registry, identityAdmissionVerified = false };
    }

    internal static Task RequireRegistryRefusalAsync(int port, X509Certificate2 root, X509Certificate2 client,
        TlsObservation observation, CancellationToken cancellation, bool registered = false) =>
        ConnectAsync(port, root, client, registered ? TlsCase.Registered : TlsCase.Registry, observation, cancellation);

    private static async Task GatewayAsync(int port, X509Certificate2 root, X509Certificate2 otherRoot,
        X509Certificate2 client, X509Certificate2 otherClient, X509Certificate2 server,
        TlsObservation observation, CancellationToken cancellation)
    {
        RequireChain(client, root, ClientPurpose, true);
        RequireChain(otherClient, otherRoot, ClientPurpose, true);
        RequireChain(otherClient, root, ClientPurpose, false);
        RequireChain(server, root, ServerPurpose, true);
        RequireChain(server, root, ClientPurpose, false);
        if (client.Extensions.Any(extension => extension.Oid?.Value == "2.5.29.17"))
        { throw Failure("UnexpectedIdentitySan"); }
        await ConnectAsync(port, root, client, TlsCase.Trusted, observation, cancellation);
        await ConnectAsync(port, root, client, TlsCase.Identity, observation, cancellation);
        await ConnectAsync(port, root, null, TlsCase.MissingClient, observation, cancellation);
        await ConnectAsync(port, root, otherClient, TlsCase.CrossRootClient, observation, cancellation);
        // Explicit selection forces the server-auth-only leaf rather than silently omitting it.
        await ConnectAsync(port, root, server, TlsCase.WrongEkuClient, observation, cancellation);
        await ConnectAsync(port, otherRoot, client, TlsCase.ServerRoot, observation, cancellation);
        await ConnectAsync(port, root, client, TlsCase.ServerHostname, observation, cancellation);
    }

    private static async Task ConnectAsync(int port, X509Certificate2 root, X509Certificate2? client,
        TlsCase mode, TlsObservation observation, CancellationToken cancellation)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
        deadline.CancelAfter(TimeSpan.FromSeconds(2));
        using var tcp = new TcpClient(AddressFamily.InterNetwork);
        // A failed TCP connect is outside the authentication catch and can never pass a refusal.
        await tcp.ConnectAsync(IPAddress.Loopback, port, deadline.Token);
        var serverEndpoint = tcp.Client.RemoteEndPoint!.ToString()!;
        var clientEndpoint = tcp.Client.LocalEndPoint!.ToString()!;
        using var tls = new SslStream(tcp.GetStream(), false);
        var policy = CreatePolicy(root, ServerPurpose);
        var selected = false;
        var options = new SslClientAuthenticationOptions
        {
            TargetHost = mode == TlsCase.ServerHostname ? "wrong.fixture.invalid" : "localhost", EnabledSslProtocols = SslProtocols.Tls12,
            CertificateChainPolicy = policy, AllowRenegotiation = false,
            LocalCertificateSelectionCallback = (_, _, _, _, _) => { selected = true; return client; }
        };
        if (mode is TlsCase.ServerRoot or TlsCase.ServerHostname)
        {
            try { await tls.AuthenticateAsClientAsync(options, deadline.Token); }
            catch (AuthenticationException) { return; }
            throw Failure("ServerTrustAccepted");
        }
        if (mode is not (TlsCase.Trusted or TlsCase.Identity or TlsCase.Registry or TlsCase.Registered))
        {
            await ObservePeerRefusalAsync(tls, options, deadline.Token);
            if (mode is TlsCase.CrossRootClient or TlsCase.WrongEkuClient && !selected) { throw Failure("ClientSelection"); }
            await observation.RequireAsync(serverEndpoint, clientEndpoint, true, null, deadline.Token);
            return;
        }
        await tls.AuthenticateAsClientAsync(options, deadline.Token);
        if (!tls.IsMutuallyAuthenticated || !selected || tls.SslProtocol != SslProtocols.Tls12 ||
            tls.LocalCertificate is null || client is null ||
            !tls.LocalCertificate.GetRawCertData().AsSpan().SequenceEqual(client.RawData))
        { throw Failure("MutualAuthentication"); }
        var path = mode is TlsCase.Identity or TlsCase.Registry or TlsCase.Registered ?
            (port == 19581 ? "/agent/identity" : "/admin/authorization/roles/00000000-0000-4000-8000-000000000001/versions") :
            "/fixture/client-tls";
        var expected = mode == TlsCase.Registered ? (port == 19581 ? HttpStatusCode.NoContent : HttpStatusCode.Unauthorized) :
            (mode == TlsCase.Trusted ? HttpStatusCode.NotFound : HttpStatusCode.Forbidden);
        await RequireHttpAsync(tls, path, expected,
            mode is TlsCase.Registry or TlsCase.Registered ? RegistryCases.Correlation(port, mode == TlsCase.Registered) : null, deadline.Token);
        await observation.RequireAsync(serverEndpoint, clientEndpoint, false, path, deadline.Token);
    }

    private static async Task ObservePeerRefusalAsync(SslStream tls, SslClientAuthenticationOptions options,
        CancellationToken cancellation)
    {
        try
        {
            await tls.AuthenticateAsClientAsync(options, cancellation);
            // Client-side completion can precede the server's certificate-validation result.
            if (await tls.ReadAsync(new byte[1], cancellation) != 0) { throw Failure("UnexpectedPeerData"); }
        }
        catch (Exception exception) when (exception is AuthenticationException or IOException)
        { /* Peer outcome alone NEVER passes: require the matching native Kestrel failure below. */ }
    }

    private static async Task RequireHttpAsync(SslStream tls, string path, HttpStatusCode expected, string? correlation, CancellationToken cancellation)
    {
        var header = correlation is null ? "" : "X-Correlation-ID: " + correlation + "\r\n";
        var request = Encoding.ASCII.GetBytes("GET " + path + " HTTP/1.1\r\nHost: localhost\r\n" + header + "Connection: close\r\n\r\n");
        await tls.WriteAsync(request, cancellation);
        var buffer = new byte[1025];
        var length = 0;
        while (length < buffer.Length)
        {
            var read = await tls.ReadAsync(buffer.AsMemory(length), cancellation);
            if (read == 0) { break; }
            length += read;
        }
        var response = Encoding.ASCII.GetString(buffer, 0, length);
        HttpFixtureResponse.RequireEmpty(response, expected, correlation);
    }

    internal static X509Certificate2 ReadCertificate(FileSecretProvider files, string name) =>
        X509Certificate2.CreateFromPem(files.GetRequiredSecret(name));

    internal static X509Certificate2 ReadKeyPair(FileSecretProvider files, string prefix) =>
        X509Certificate2.CreateFromPem(files.GetRequiredSecret(prefix + "-cert"), files.GetRequiredSecret(prefix + "-key"));

    private static X509ChainPolicy CreatePolicy(X509Certificate2 root, string purpose)
    {
        var policy = new X509ChainPolicy { TrustMode = X509ChainTrustMode.CustomRootTrust,
            RevocationMode = X509RevocationMode.NoCheck, DisableCertificateDownloads = true,
            VerificationFlags = X509VerificationFlags.NoFlag };
        policy.CustomTrustStore.Add(root);
        policy.ApplicationPolicy.Add(new Oid(purpose));
        return policy;
    }

    private static void RequireChain(X509Certificate2 leaf, X509Certificate2 root, string purpose, bool expected)
    {
        using var chain = new X509Chain { ChainPolicy = CreatePolicy(root, purpose) };
        if (chain.Build(leaf) != expected || expected && (chain.ChainElements.Count != 2 ||
            !chain.ChainElements[^1].Certificate.RawData.AsSpan().SequenceEqual(root.RawData)))
        { throw Failure("FixtureChain"); }
    }

    private static InvalidOperationException Failure(string code) =>
        new("Native client TLS fixture failed.") { Data = { ["fixtureTlsFailure"] = code } };
}
