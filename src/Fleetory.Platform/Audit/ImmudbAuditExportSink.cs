using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Fleetory.Platform.Contracts;
using Fleetory.Platform.Secrets;

namespace Fleetory.Platform.Audit;

/// <summary>Writes each audit event once to immudb's conditional REST key-value API.</summary>
public sealed class ImmudbAuditExportSink : IAuditExportSink, IDisposable
{
    private const int MaximumResponseBytes = 16 * 1024;
    private readonly Uri _address;
    private readonly string _username;
    private readonly string _password;
    private readonly HttpClient _client;

    public ImmudbAuditExportSink(Uri address, string username, string password,
        bool allowInsecureLoopback = false, HttpMessageHandler? handler = null)
    {
        HttpOriginPolicy.Validate(address, allowInsecureLoopback, "Immudb");

        ArgumentException.ThrowIfNullOrWhiteSpace(username);
        ArgumentException.ThrowIfNullOrWhiteSpace(password);
        if (username.Length > 128 || password.Length > 1024)
        {
            throw new ArgumentException("Immudb credentials are too long.");
        }

        _address = address;
        _username = username;
        _password = password;
        _client = handler is null ? new HttpClient() : new HttpClient(handler);
        _client.Timeout = TimeSpan.FromSeconds(20);
    }

    public async ValueTask PublishAsync(AuditExportEvent auditEvent,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(auditEvent);
        if (auditEvent.EventId == Guid.Empty)
        {
            throw new ArgumentException("Audit event ID is empty.", nameof(auditEvent));
        }

        var key = Convert.ToBase64String(Encoding.UTF8.GetBytes(
            "fleetory/audit/v1/" + auditEvent.EventId.ToString("N")));
        var value = Convert.ToBase64String(Serialize(auditEvent));
        var token = await LoginAsync(cancellationToken);
        var payload = JsonSerializer.Serialize(new
        {
            KVs = new[] { new { key, value } },
            preconditions = new[] { new { keyMustNotExist = new { key } } }
        });

        using (var request = NewAuthenticatedRequest(HttpMethod.Post, "api/db/set", token))
        {
            request.Content = new StringContent(payload, Encoding.UTF8, "application/json");
            using var response = await _client.SendAsync(request,
                HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            if (!response.IsSuccessStatusCode && (int)response.StatusCode != 400)
            {
                throw new InvalidOperationException("Immudb audit write failed.");
            }
        }

        // This also resolves an ambiguous response after a successful write and a lost acknowledgement.
        using var readRequest = NewAuthenticatedRequest(HttpMethod.Get,
            "api/db/get/" + Uri.EscapeDataString(key), token);
        using var readResponse = await _client.SendAsync(readRequest,
            HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        if (!readResponse.IsSuccessStatusCode)
        {
            throw new InvalidOperationException("Immudb audit readback failed.");
        }

        using var stored = await ReadJsonAsync(readResponse, cancellationToken);
        var root = stored.RootElement;
        if (root.GetProperty("key").GetString() != key ||
            root.GetProperty("value").GetString() != value ||
            root.GetProperty("revision").GetString() != "1")
        {
            throw new InvalidOperationException("Immudb audit event conflicts with an existing key.");
        }
    }

    private async Task<string> LoginAsync(CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, new Uri(_address, "api/login"));
        request.Content = new StringContent(JsonSerializer.Serialize(new
        {
            user = Convert.ToBase64String(Encoding.UTF8.GetBytes(_username)),
            password = Convert.ToBase64String(Encoding.UTF8.GetBytes(_password))
        }), Encoding.UTF8, "application/json");
        using var response = await _client.SendAsync(request,
            HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            throw new InvalidOperationException("Immudb audit authentication failed.");
        }

        using var body = await ReadJsonAsync(response, cancellationToken);
        var token = body.RootElement.GetProperty("token").GetString();
        if (string.IsNullOrWhiteSpace(token) || token.Length > 8192 ||
            token.Any(char.IsWhiteSpace))
        {
            throw new InvalidOperationException("Immudb audit authentication response is invalid.");
        }

        return token;
    }

    private HttpRequestMessage NewAuthenticatedRequest(HttpMethod method, string path, string token)
    {
        var request = new HttpRequestMessage(method, new Uri(_address, path));
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return request;
    }

    private static byte[] Serialize(AuditExportEvent auditEvent)
    {
        var record = auditEvent.Record;
        var context = record.Context is null ? null :
            new SortedDictionary<string, string>(
                record.Context.ToDictionary(pair => pair.Key, pair => pair.Value),
                StringComparer.Ordinal);
        return JsonSerializer.SerializeToUtf8Bytes(new
        {
            eventId = auditEvent.EventId.ToString("N"),
            actorSubjectId = record.Actor.SubjectId,
            actorKind = (int)record.Actor.Kind,
            record.Action,
            targetType = record.Target?.Type,
            targetId = record.Target?.Id,
            correlationId = record.CorrelationId.Value,
            occurredAt = record.OccurredAt.ToUniversalTime(),
            recordedAt = auditEvent.RecordedAt.ToUniversalTime(),
            context
        });
    }

    private static async Task<JsonDocument> ReadJsonAsync(HttpResponseMessage response,
        CancellationToken cancellationToken)
    {
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var buffer = new MemoryStream();
        var chunk = new byte[4096];
        int count;
        while ((count = await stream.ReadAsync(chunk, cancellationToken)) != 0)
        {
            await buffer.WriteAsync(chunk.AsMemory(0, count), cancellationToken);
            if (buffer.Length > MaximumResponseBytes)
            {
                throw new InvalidOperationException("Immudb audit response is too large.");
            }
        }

        try
        {
            return JsonDocument.Parse(buffer.ToArray());
        }
        catch (JsonException)
        {
            throw new InvalidOperationException("Immudb audit response is invalid.");
        }
    }

    public void Dispose() => _client.Dispose();
}
