using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Fleetory.Platform.Contracts;
using Fleetory.SharedKernel;

namespace ServerBackendProbe;

// Generated fixture identities only. This model is not an original inventory format.
internal static class FreshPairModel
{
    internal static Guid Fixture(JsonElement packet)
    {
        if (!Guid.TryParseExact(packet.GetProperty("fixture").GetString(), "D", out var fixture) || fixture == Guid.Empty)
        { throw new InvalidOperationException("Fresh pair fixture identity refused."); }
        return fixture;
    }

    internal static Guid Id(Guid fixture, int number) => new(SHA256.HashData(
        Encoding.UTF8.GetBytes(fixture.ToString("D") + ":" + number))[..16]);

    internal static AuditExportEvent[] Events(Guid fixture) => Enumerable.Range(0, 4).Select(index =>
        new AuditExportEvent(Id(fixture, index), new AuditRecord(
            new ActorReference("fixture:pair:" + fixture.ToString("N"), ActorKind.Person),
            "Fixture.Pair.'Read." + index,
            index == 0 ? null : new AuditTarget("Fixture", "generated-'" + index),
            new CorrelationId("pair-" + index), DateTimeOffset.UnixEpoch.AddSeconds(index),
            index == 1 ? null : new Dictionary<string, string> { ["Zulu"] = "last", ["Alpha"] = "first ' value" }),
            DateTimeOffset.UnixEpoch.AddSeconds(10 + index))).ToArray();

    internal static JsonElement Fields(AuditExportEvent item)
    {
        var record = item.Record;
        return JsonSerializer.SerializeToElement(new Dictionary<string, object?>
        {
            ["eventId"] = item.EventId.ToString("N"), ["actorSubjectId"] = record.Actor.SubjectId,
            ["actorKind"] = (int)record.Actor.Kind, ["Action"] = record.Action,
            ["targetType"] = record.Target?.Type, ["targetId"] = record.Target?.Id,
            ["correlationId"] = record.CorrelationId.Value, ["occurredAt"] = record.OccurredAt.ToUniversalTime(),
            ["recordedAt"] = item.RecordedAt.ToUniversalTime(), ["context"] = record.Context
        });
    }

    internal static void RequireFields(JsonElement actual, JsonElement expected)
    {
        if (actual.ValueKind != JsonValueKind.Object || actual.EnumerateObject().Count() != 10)
        { throw new InvalidOperationException("Fresh pair field count drift."); }
        foreach (var field in expected.EnumerateObject())
        {
            var value = actual.GetProperty(field.Name);
            var same = field.Name is "occurredAt" or "recordedAt"
                ? value.GetDateTimeOffset() == field.Value.GetDateTimeOffset() : JsonElement.DeepEquals(value, field.Value);
            if (!same) { throw new InvalidOperationException("Fresh pair field drift."); }
        }
    }

    internal static string SeedSql(Guid fixture)
    {
        static string Literal(string? value) => value is null ? "NULL" : "'" + value.Replace("'", "''", StringComparison.Ordinal) + "'";
        static string Time(DateTimeOffset value) => "'" + value.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture) + "'";
        var sql = new StringBuilder("BEGIN;SET LOCAL standard_conforming_strings=on;SET LOCAL timezone='UTC';SET LOCAL ROLE fleetory_migrator;\n");
        for (var index = 0; index < 2; index++)
        {
            sql.Append("INSERT INTO core.devices(device_id,display_name,updated_at) VALUES('").Append(Id(fixture, 10 + index))
                .Append("','pair-device','1970-01-01Z');\n");
            sql.Append("INSERT INTO platform.person_projections(person_id,display_name,updated_at) VALUES('").Append(Id(fixture, 20 + index))
                .Append("','pair-person','1970-01-01Z');\n");
        }
        foreach (var item in Events(fixture))
        {
            var r = item.Record;
            sql.Append("INSERT INTO platform.audit_events(event_id,actor_subject_id,actor_kind,action,target_type,target_id,correlation_id,occurred_at,recorded_at,context_json) VALUES('")
                .Append(item.EventId).Append("',").Append(Literal(r.Actor.SubjectId)).Append(',').Append((int)r.Actor.Kind).Append(',')
                .Append(Literal(r.Action)).Append(',').Append(Literal(r.Target?.Type)).Append(',').Append(Literal(r.Target?.Id)).Append(',')
                .Append(Literal(r.CorrelationId.Value)).Append(',').Append(Time(r.OccurredAt)).Append(',').Append(Time(item.RecordedAt)).Append(',')
                .Append(r.Context is null ? "NULL" : Literal(JsonSerializer.Serialize(r.Context)) + "::jsonb").Append(");\n");
        }
        return sql.Append("COMMIT;\n").ToString();
    }
}
