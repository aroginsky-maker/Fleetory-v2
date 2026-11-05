using System.Diagnostics.Tracing;
using System.Net;

namespace ServerBackendProbe;

// Read-only native Kestrel events. No TLS callbacks, validator or application options replaced.
internal sealed class TlsObservation(bool persistent = false) : EventListener
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
        // Read only endpoint/GET-path metadata; never Configuration, headers or bodies.
        if (data.EventName is not ("ConnectionStart" or "TlsHandshakeStop" or "TlsHandshakeFailed" or "RequestStart"))
        { return; }
        var current = Current;
        lock (current)
        {
            if (data.Payload is not { Count: > 0 } || data.Payload[0] is not string { Length: > 0 and <= 128 } id)
            { current.Invalid = true; return; }
            if (data.EventName == "ConnectionStart")
            {
                if (current.Connections.Count >= 32 || data.Payload.Count != 3 ||
                    data.Payload[1] is not string local || data.Payload[2] is not string remote ||
                    !current.Connections.TryAdd(id, new Connection(Normalize(local), Normalize(remote)))) { current.Invalid = true; }
            }
            else if (current.Connections.TryGetValue(id, out var connection))
            {
                if (data.EventName == "TlsHandshakeFailed") { connection.Failed = true; }
                else if (data.EventName == "RequestStart")
                {
                    if (connection.Paths.Count >= (persistent ? 2 : 1) || data.Payload.Count != 5 || data.Payload[3] is not string path ||
                        path.Length > 180 || data.Payload[4] is not string method || method != "GET") { current.Invalid = true; }
                    else { connection.Paths.Add(path); }
                }
                else if (data.Payload.Count == 4 && data.Payload[1] is string protocol)
                { connection.Established = protocol == "Tls12"; connection.Stopped = true; }
                else { current.Invalid = true; }
            }
        }
    }

    private static string Normalize(string endpoint) => IPEndPoint.TryParse(endpoint, out var parsed) ?
        new IPEndPoint(parsed.Address.IsIPv4MappedToIPv6 ? parsed.Address.MapToIPv4() : parsed.Address, parsed.Port).ToString() : "";

    internal async Task RequireAsync(string server, string client, bool refused, string? expectedPath, CancellationToken cancellation)
    { await WaitAsync(server, client, refused, expectedPath, refused ? 0 : 1, cancellation); }

    internal Task<string> RequirePersistentAsync(string server, string client, string path, int requests, CancellationToken cancellation)
    {
        if (!persistent || requests is < 1 or > 2) { throw new InvalidOperationException("Persistent observation scope drift."); }
        return WaitAsync(server, client, false, path, requests, cancellation);
    }

    private async Task<string> WaitAsync(string server, string client, bool refused, string? expectedPath,
        int requests, CancellationToken cancellation)
    {
        while (true)
        {
            var current = Current;
            lock (current)
            {
                if (current.Invalid) { throw new InvalidOperationException("Native Kestrel event contract drift."); }
                var found = current.Connections.Where(item => item.Value.Local == server && item.Value.Remote == client).ToArray();
                if (found.Length > 1) { throw new InvalidOperationException("Native TLS connection correlation ambiguous."); }
                if (found.Length == 1 && found[0].Value.Stopped)
                {
                    var connection = found[0].Value;
                    if (refused ? connection.Failed && !connection.Established && connection.Paths.Count == 0 :
                        !connection.Failed && connection.Established && connection.Paths.Count == requests &&
                        connection.Paths.All(path => path == expectedPath)) { return found[0].Key; }
                    throw new InvalidOperationException("Native Kestrel handshake outcome drift.");
                }
            }
            await Task.Delay(TimeSpan.FromMilliseconds(10), cancellation);
        }
    }

    internal static void RequireSameConnection(string first, string second)
    {
        if (first.Length is < 1 or > 128 || first != second)
        { throw new InvalidOperationException("Persistent request used a replacement native connection."); }
    }

    internal static object VerifyPersistentContract()
    {
        RequireSameConnection("native-1", "native-1");
        var refused = 0;
        foreach (var (first, second) in new[] { ("native-1", "native-2"), ("", ""), (new string('x', 129), new string('x', 129)) })
        {
            try { RequireSameConnection(first, second); }
            catch (InvalidOperationException) { refused++; continue; }
            throw new InvalidOperationException("Unsafe persistent connection identity accepted.");
        }
        return new { sameConnectionAccepted = 1, replacementOrInvalidRefusals = refused };
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
        internal readonly List<string> Paths = [];
    }
}
