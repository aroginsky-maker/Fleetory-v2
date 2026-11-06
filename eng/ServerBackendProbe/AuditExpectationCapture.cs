using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Fleetory.Platform.Audit;

namespace ServerBackendProbe;

// No delegating handler, sockets, redirects, file API or backend endpoint is used.
internal sealed class AuditExpectationCapture(ExpectedAuditSource source) : HttpMessageHandler
{
    private string? _value;
    private readonly string _key = FixtureAuditClient.EventKey(source.Event.EventId);
    internal int Requests { get; private set; }
    internal string ValueSha256 => AuditObservation.Hash(Convert.FromBase64String(_value!));

    internal static async Task<(string Hash, int Requests)> SerializeAsync(ExpectedAuditSource source, CancellationToken cancellation)
    {
        using var handler = new AuditExpectationCapture(source);
        var password = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(32));
        using var sink = new ImmudbAuditExportSink(new Uri("https://127.0.0.1:8090/"), "generated_expectation", password,
            handler: handler, databaseName: "fleetoryaudit");
        await sink.PublishAsync(source.Event, cancellation);
        if (handler.Requests != 4 || handler._value is null) { throw new AuditExpectationCaptureException(); }
        return (handler.ValueSha256, handler.Requests);
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var path = request.RequestUri?.AbsolutePath;
        if (request.RequestUri?.GetLeftPart(UriPartial.Authority) != "https://127.0.0.1:8090" || Requests >= 4)
        { throw new AuditExpectationCaptureException(); }
        object body;
        if (Requests == 0 && request.Method == HttpMethod.Post && path == "/api/login")
        { body = new { token = "generated-expectation-only" }; }
        else if (Requests == 1 && request.Method == HttpMethod.Get && path == "/api/db/use/fleetoryaudit")
        { body = new { token = "generated-expectation-only" }; }
        else if (Requests == 2 && request.Method == HttpMethod.Post && path == "/api/db/set")
        {
            await CaptureAsync(request, cancellationToken);
            body = new { };
        }
        else if (Requests == 3 && request.Method == HttpMethod.Get && path == "/api/db/get/" + Uri.EscapeDataString(_key))
        { body = new { key = _key, value = _value, revision = "1" }; }
        else { throw new AuditExpectationCaptureException(); }
        Requests++;
        return new HttpResponseMessage(HttpStatusCode.OK)
        { Content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json") };
    }

    private async Task CaptureAsync(HttpRequestMessage request, CancellationToken cancellation)
    {
        using var json = JsonDocument.Parse(await request.Content!.ReadAsByteArrayAsync(cancellation));
        var root = json.RootElement;
        if (root.ValueKind != JsonValueKind.Object || root.EnumerateObject().Count() != 2)
        { throw new AuditExpectationCaptureException(); }
        var kvs = root.GetProperty("KVs").EnumerateArray().ToArray();
        var conditions = root.GetProperty("preconditions").EnumerateArray().ToArray();
        if (kvs.Length != 1 || conditions.Length != 1 || kvs[0].GetProperty("key").GetString() != _key ||
            conditions[0].GetProperty("keyMustNotExist").GetProperty("key").GetString() != _key)
        { throw new AuditExpectationCaptureException(); }
        var value = kvs[0].GetProperty("value").GetString()!;
        var bytes = Convert.FromBase64String(value);
        if (bytes.Length > AuditObservation.MaximumValueBytes) { throw new AuditExpectationValueBoundException(); }
        using var wire = JsonDocument.Parse(bytes);
        FreshPairModel.RequireFields(wire.RootElement, AuditExpectationSnapshot.WireFields(source.Row, source.Profile));
        var context = AuditExpectationSnapshot.Context(source.Row.GetProperty("context_json"), source.Profile);
        if (context is not null && !wire.RootElement.GetProperty("context").EnumerateObject().Select(field => field.Name)
                .SequenceEqual(context.Keys.Order(StringComparer.Ordinal)))
        { throw new AuditExpectationCaptureException(); }
        _value = value;
    }
}

internal sealed class AuditExpectationCaptureException : Exception;
internal sealed class AuditExpectationValueBoundException : Exception;
