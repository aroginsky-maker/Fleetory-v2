using System.Diagnostics;
using System.Globalization;
using System.Net;
using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Server.Kestrel.Https;

namespace Fleetory.CommandSigner.Host;

/// <summary>Emits bounded transport metadata for connections that never finish TLS admission.</summary>
public sealed class SigningTlsHandshakeAudit(ILogger<SigningTlsHandshakeAudit> logger)
{
    public static readonly EventId FailureEvent = new(701, "SignerTlsHandshakeNotEstablished");

    public void Configure(ListenOptions listener, Action<HttpsConnectionAdapterOptions> configureHttps)
    {
        listener.Use(next => connection => ObserveAsync(connection, next));
        listener.UseHttps(configureHttps);
        listener.Use(next => connection =>
        {
            connection.Features.Get<HandshakeState>()!.Established = true;
            return next(connection);
        });
    }

    public async Task ObserveAsync(ConnectionContext connection, ConnectionDelegate next)
    {
        var state = new HandshakeState();
        connection.Features.Set(state);
        var started = Stopwatch.GetTimestamp();
        try { await next(connection); }
        finally
        {
            if (!state.Established)
            {
                var peer = connection.RemoteEndPoint as IPEndPoint;
                var id = connection.ConnectionId;
                var safeId = id is { Length: >= 1 and <= 64 } &&
                    id.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_' or ':')
                    ? id : "invalid";
                logger.LogWarning(FailureEvent,
                    "Signer TLS admission failed. Schema={Schema} AuditEventId={AuditEventId} ObservedAt={ObservedAt} " +
                    "ConnectionId={ConnectionId} RemoteAddress={RemoteAddress} RemotePort={RemotePort} " +
                    "ElapsedMilliseconds={ElapsedMilliseconds} Reason={Reason}",
                    "fleetory.signer-tls-failure.v1", Guid.NewGuid(),
                    DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture), safeId,
                    peer?.Address.ToString() ?? "unknown", peer?.Port ?? 0,
                    (long)Stopwatch.GetElapsedTime(started).TotalMilliseconds, "TlsNotEstablished");
            }
        }
    }

    private sealed class HandshakeState
    {
        public bool Established { get; set; }
    }
}
