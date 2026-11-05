using System.Diagnostics.Tracing;
using System.Net;

namespace ServerBackendProbe;

// Read-only native Kestrel events. No TLS callbacks, validator or application options replaced.
internal sealed class TlsObservation : EventListener
{
    private State? state;
    private State Current => LazyInitializer.EnsureInitialized(ref state);

    protected override void OnEventSourceCreated(EventSource source)
    {
        if (source.Name == "Microsoft-AspNetCore-Server-Kestrel")
        { EnableEvents(source, EventLevel.Informational, EventKeywords.None); }
    }

    protected override void OnEventWritten(EventWrittenEventArgs data)
    {
        // In particular, never read the Configuration event or raw HTTP payloads.
        if (data.EventName is not ("ConnectionStart" or "TlsHandshakeStop" or "TlsHandshakeFailed" or "RequestStart"))
        { return; }
        var current = Current;
        lock (current)
        {
            if (data.Payload is not { Count: > 0 } || data.Payload[0] is not string id) { current.Invalid = true; return; }
            if (data.EventName == "ConnectionStart")
            {
                if (current.Connections.Count >= 32 || data.Payload.Count != 3 ||
                    data.Payload[1] is not string local || data.Payload[2] is not string remote ||
                    !current.Connections.TryAdd(id, new Connection(Normalize(local), Normalize(remote)))) { current.Invalid = true; }
            }
            else if (current.Connections.TryGetValue(id, out var connection))
            {
                if (data.EventName == "TlsHandshakeFailed") { connection.Failed = true; }
                else if (data.EventName == "RequestStart") { connection.Http = true; }
                else if (data.Payload.Count == 4 && data.Payload[1] is string protocol)
                { connection.Established = protocol == "Tls12"; connection.Stopped = true; }
                else { current.Invalid = true; }
            }
        }
    }

    private static string Normalize(string endpoint) => IPEndPoint.TryParse(endpoint, out var parsed) ?
        new IPEndPoint(parsed.Address.IsIPv4MappedToIPv6 ? parsed.Address.MapToIPv4() : parsed.Address, parsed.Port).ToString() : "";

    internal async Task RequireAsync(string server, string client, bool refused, CancellationToken cancellation)
    {
        while (true)
        {
            var current = Current;
            lock (current)
            {
                if (current.Invalid) { throw new InvalidOperationException("Native Kestrel event contract drift."); }
                var found = current.Connections.Values.Where(item => item.Local == server && item.Remote == client).ToArray();
                if (found.Length > 1) { throw new InvalidOperationException("Native TLS connection correlation ambiguous."); }
                if (found.Length == 1 && found[0].Stopped)
                {
                    var connection = found[0];
                    if (refused ? connection.Failed && !connection.Established && !connection.Http :
                        !connection.Failed && connection.Established && connection.Http) { return; }
                    throw new InvalidOperationException("Native Kestrel handshake outcome drift.");
                }
            }
            await Task.Delay(TimeSpan.FromMilliseconds(10), cancellation);
        }
    }

    private sealed class State
    {
        internal readonly Dictionary<string, Connection> Connections = new(StringComparer.Ordinal);
        internal bool Invalid;
    }

    private sealed class Connection(string local, string remote)
    {
        internal readonly string Local = local;
        internal readonly string Remote = remote;
        internal bool Failed;
        internal bool Stopped;
        internal bool Established;
        internal bool Http;
    }
}
