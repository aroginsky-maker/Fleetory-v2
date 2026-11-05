using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace ServerBackendProbe;

// One TcpClient/SslStream, one authentication, exactly two sequential requests. No reconnect path.
internal sealed class PersistentGateway(int port, TcpClient tcp, SslStream tls) : IDisposable
{
    private int requests;
    private string? connectionId;

    internal static async Task<PersistentGateway> OpenAsync(int port, X509Certificate2 root,
        X509Certificate2 leaf, CancellationToken cancellation)
    {
        if (port is not (19581 or 19582)) { throw new InvalidOperationException("Unknown persistent fixture port."); }
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
        deadline.CancelAfter(TimeSpan.FromSeconds(2));
        var tcp = new TcpClient(AddressFamily.InterNetwork);
        SslStream? tls = null;
        try
        {
            await tcp.ConnectAsync(IPAddress.Loopback, port, deadline.Token);
            tls = new SslStream(tcp.GetStream(), false);
            var selected = false;
            await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = "localhost", EnabledSslProtocols = SslProtocols.Tls12, AllowRenegotiation = false,
                CertificateChainPolicy = ClientTlsCases.CreatePolicy(root, "1.3.6.1.5.5.7.3.1"),
                LocalCertificateSelectionCallback = (_, _, _, _, _) => { selected = true; return leaf; }
            }, deadline.Token);
            if (!selected || !tls.IsMutuallyAuthenticated || tls.SslProtocol != SslProtocols.Tls12 ||
                tls.LocalCertificate is null || !tls.LocalCertificate.GetRawCertData().AsSpan().SequenceEqual(leaf.RawData))
            { throw new InvalidOperationException("Persistent native TLS identity drift."); }
            return new PersistentGateway(port, tcp, tls);
        }
        catch { tls?.Dispose(); tcp.Dispose(); throw; }
    }

    internal async Task RequireAsync(CredentialState state, TlsObservation observation, CancellationToken cancellation)
    {
        var last = state == CredentialState.LiveRevoked;
        if ((state != CredentialState.Registered && !last) || requests != (last ? 1 : 0))
        { throw new InvalidOperationException("Persistent credential request order drift."); }
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
        deadline.CancelAfter(TimeSpan.FromSeconds(2));
        var path = port == 19581 ? "/agent/identity" : "/admin/authorization/roles/00000000-0000-4000-8000-000000000001/versions";
        var expected = last ? HttpStatusCode.Forbidden : port == 19581 ? HttpStatusCode.NoContent : HttpStatusCode.Unauthorized;
        var correlation = RegistryCases.Correlation(port, state);
        var request = "GET " + path + " HTTP/1.1\r\nHost: localhost\r\nX-Correlation-ID: " + correlation +
            (last ? "\r\nConnection: close\r\n\r\n" : "\r\nConnection: keep-alive\r\n\r\n");
        await tls.WriteAsync(Encoding.ASCII.GetBytes(request), deadline.Token);
        await PersistentHttpResponse.ReadAsync(tls, expected, correlation, last, deadline.Token);
        requests++;
        var id = await observation.RequirePersistentAsync(tcp.Client.RemoteEndPoint!.ToString()!,
            tcp.Client.LocalEndPoint!.ToString()!, path, requests, deadline.Token);
        if (connectionId is not null) { TlsObservation.RequireSameConnection(connectionId, id); }
        connectionId = id;
    }

    internal string CompletedConnectionId => requests == 2 && connectionId is not null ? connectionId :
        throw new InvalidOperationException("Persistent connection proof incomplete.");

    public void Dispose() { tls.Dispose(); tcp.Dispose(); }
}

internal sealed class LiveGatewayPair(PersistentGateway agent, PersistentGateway admin, TlsObservation observation)
{
    internal Task RequireAsync(int port, CredentialState state, CancellationToken cancellation) => port switch
    {
        19581 => agent.RequireAsync(state, observation, cancellation),
        19582 => admin.RequireAsync(state, observation, cancellation),
        _ => throw new InvalidOperationException("Unknown live fixture endpoint.")
    };
}
