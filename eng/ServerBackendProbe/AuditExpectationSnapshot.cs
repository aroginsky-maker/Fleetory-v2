using System.Globalization;
using System.Text;
using System.Text.Json;
using Fleetory.Platform.Contracts;
using Fleetory.SharedKernel;

namespace ServerBackendProbe;

internal enum AuditExpectationProfile { StrictWriter, HistoricalReadOnly }

internal sealed record ExpectedAuditSource(AuditExportEvent Event, JsonElement Row, AuditExpectationProfile Profile);

// Fixed four-event PostgreSQL export profile, not a generic archive or inventory parser.
internal static class AuditExpectationSnapshot
{
    internal const int MaximumBytes = 128 * 1024;
    private static readonly string[] Fields = ["event_id", "actor_subject_id", "actor_kind", "action", "target_type",
        "target_id", "correlation_id", "occurred_at", "recorded_at", "context_json"];

    internal static void Require(bool condition)
    {
        if (!condition) { throw new AuditExpectationInputException(); }
    }

    internal static void Object(JsonElement value, params string[] fields)
    {
        Require(value.ValueKind == JsonValueKind.Object);
        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (var item in value.EnumerateObject()) { Require(names.Add(item.Name)); }
        Require(names.SetEquals(fields));
    }

    internal static ExpectedAuditSource[] Parse(byte[] bytes, AuditExpectationProfile profile = AuditExpectationProfile.StrictWriter)
    {
        try
        {
            using var doc = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 8 });
            var root = doc.RootElement;
            Object(root, "schema", "pendingExportCount", "events");
            Require(root.GetProperty("schema").GetString() == "fleetory.audit-snapshot.v1");
            Require(Integer(root.GetProperty("pendingExportCount"), 0, 0) == 0);
            var rows = root.GetProperty("events").EnumerateArray().ToArray();
            Require(rows.Length == 4);
            Require(Enum.IsDefined(profile));
            var result = rows.Select(row => ParseRow(row, profile)).ToArray();
            var ids = result.Select(item => item.Event.EventId.ToString("D")).ToArray();
            Require(ids.Distinct(StringComparer.Ordinal).Count() == 4 && ids.SequenceEqual(ids.Order(StringComparer.Ordinal)));
            return result;
        }
        catch (Exception error) when (error is JsonException or FormatException or InvalidOperationException or ArgumentException or KeyNotFoundException)
        { throw new AuditExpectationInputException(); }
    }

    private static ExpectedAuditSource ParseRow(JsonElement row, AuditExpectationProfile profile)
    {
        Object(row, Fields);
        var id = Identity(row.GetProperty("event_id").GetString());
        var type = NullableText(row.GetProperty("target_type"), 64);
        var target = NullableText(row.GetProperty("target_id"), 128);
        Require((type is null) == (target is null));
        var record = new AuditRecord(new ActorReference(Text(row.GetProperty("actor_subject_id"), 128),
            (ActorKind)Integer(row.GetProperty("actor_kind"), 0, 3)), Text(row.GetProperty("action"), 128),
            type is null ? null : new AuditTarget(type, target!), new CorrelationId(Text(row.GetProperty("correlation_id"), 128)),
            Time(row.GetProperty("occurred_at")), Context(row.GetProperty("context_json"), profile));
        return new ExpectedAuditSource(new AuditExportEvent(id, record, Time(row.GetProperty("recorded_at"))), row.Clone(), profile);
    }

    internal static Guid Identity(string? value)
    {
        Require(Guid.TryParseExact(value, "D", out var id) && id != Guid.Empty && id.ToString("D") == value);
        return id;
    }

    internal static DateTimeOffset Time(JsonElement value) => DateTimeOffset.ParseExact(value.GetString()!,
        "yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'", CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal);

    private static int Integer(JsonElement value, int minimum, int maximum)
    {
        Require(value.ValueKind == JsonValueKind.Number && value.TryGetInt32(out _));
        var number = value.GetInt32();
        Require(number >= minimum && number <= maximum && value.GetRawText() == number.ToString(CultureInfo.InvariantCulture));
        return number;
    }

    private static string Text(JsonElement value, int maximum)
    {
        var text = value.GetString();
        Require(!string.IsNullOrWhiteSpace(text) && text.Length <= maximum && !text.Contains('\0'));
        return text!;
    }

    private static string? NullableText(JsonElement value, int maximum) =>
        value.ValueKind == JsonValueKind.Null ? null : Text(value, maximum);

    internal static Dictionary<string, string>? Context(JsonElement value, AuditExpectationProfile profile = AuditExpectationProfile.StrictWriter)
    {
        if (value.ValueKind == JsonValueKind.Null) { return null; }
        var text = value.GetString()!;
        Require(Encoding.UTF8.GetByteCount(text) <= 16384);
        using var document = JsonDocument.Parse(text, new JsonDocumentOptions { MaxDepth = 2 });
        Require(document.RootElement.ValueKind == JsonValueKind.Object);
        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (var field in document.RootElement.EnumerateObject())
        {
            Require(!string.IsNullOrWhiteSpace(field.Name) && field.Name.Length <= 64 && !field.Name.Contains('\0'));
            var content = field.Value.GetString();
            Require(content is null
                ? profile == AuditExpectationProfile.HistoricalReadOnly && field.Value.ValueKind == JsonValueKind.Null
                : content.Length <= 1024 && !content.Contains('\0'));
            Require(names.Add(field.Name));
        }
        Require(names.Count <= 16);
        // Same deserialization as PostgreSqlAuditExportPump: preserve literal null members for read-only comparison.
        return JsonSerializer.Deserialize<Dictionary<string, string>>(text) ?? throw new AuditExpectationInputException();
    }

    // Independent semantic witness from the source row, not the reconstructed Event model or an audit Get.
    internal static JsonElement WireFields(JsonElement row, AuditExpectationProfile profile) => JsonSerializer.SerializeToElement(new Dictionary<string, object?>
    {
        ["eventId"] = Identity(row.GetProperty("event_id").GetString()).ToString("N"),
        ["actorSubjectId"] = row.GetProperty("actor_subject_id"), ["actorKind"] = row.GetProperty("actor_kind"),
        ["Action"] = row.GetProperty("action"), ["targetType"] = row.GetProperty("target_type"), ["targetId"] = row.GetProperty("target_id"),
        ["correlationId"] = row.GetProperty("correlation_id"), ["occurredAt"] = Time(row.GetProperty("occurred_at")),
        ["recordedAt"] = Time(row.GetProperty("recorded_at")), ["context"] = Context(row.GetProperty("context_json"), profile)
    });

    internal static int NullContextMembers(ExpectedAuditSource source)
    {
        var value = source.Row.GetProperty("context_json");
        if (value.ValueKind == JsonValueKind.Null) { return 0; }
        using var document = JsonDocument.Parse(value.GetString()!);
        return document.RootElement.EnumerateObject().Count(field => field.Value.ValueKind == JsonValueKind.Null);
    }
}

internal sealed class AuditExpectationInputException : Exception;
