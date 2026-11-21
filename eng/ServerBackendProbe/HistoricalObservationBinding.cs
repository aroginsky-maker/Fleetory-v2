using System.Globalization;
using System.Text;
using System.Text.Json;

namespace ServerBackendProbe;

internal static class HistoricalObservationBinding
{
    internal const string Expected = "fleetory.historical-audit-observation-expectation.v1";
    internal const string Observed = "fleetory.historical-audit-native-observation.v1";
    internal const string Profile = "historical-one-null-member-readonly.v1";
    private static readonly string[] ComparisonFields = ["profile", "sourceExpectationSha256", "snapshotSha256", "sourceNonce",
        "knownValuesCommitment", "nullContextMembersPreserved", "historicalComparisonOnly", "writerAdmissionVerified",
        "stateMutationAuthorized", "sourceOriginAuthenticated", "sourceIndependenceAuthenticated", "executionAuthorized",
        "fullSystemRecoveryVerified", "phase7Complete"];

    private static void Require(bool condition)
    {
        if (!condition) { throw new AuditObservationBindingException(); }
    }

    private static void Fields(JsonElement value, params string[] names)
    {
        Require(value.ValueKind == JsonValueKind.Object);
        var found = new HashSet<string>(StringComparer.Ordinal);
        foreach (var field in value.EnumerateObject()) { Require(found.Add(field.Name)); }
        Require(found.SetEquals(names));
    }

    internal static void Validate(JsonElement expected, bool historical)
    {
        if (!historical)
        {
            Fields(expected, "schema", "nonce", "point", "knownEvents", "producer");
            Require(expected.GetProperty("schema").GetString() == "fleetory.audit-observation-expectation.v1");
            return;
        }
        Fields(expected, "schema", "nonce", "point", "knownEvents", "producer", "comparison");
        Require(expected.GetProperty("schema").GetString() == Expected);
        var scope = expected.GetProperty("comparison");
        Fields(scope, ComparisonFields);
        Require(scope.GetProperty("profile").GetString() == Profile && scope.GetProperty("historicalComparisonOnly").ValueKind == JsonValueKind.True);
        var count = scope.GetProperty("nullContextMembersPreserved");
        Require(count.ValueKind == JsonValueKind.Number && count.TryGetInt32(out var number) && number == 1 && count.GetRawText() == "1");
        foreach (var name in new[] { "writerAdmissionVerified", "stateMutationAuthorized", "sourceOriginAuthenticated",
            "sourceIndependenceAuthenticated", "executionAuthorized", "fullSystemRecoveryVerified", "phase7Complete" })
        { Require(scope.GetProperty(name).ValueKind == JsonValueKind.False); }
        foreach (var name in new[] { "sourceExpectationSha256", "snapshotSha256", "knownValuesCommitment" })
        {
            var value = scope.GetProperty(name);
            Require(value.ValueKind == JsonValueKind.String && value.GetString()?.Length == 64 && value.GetString()!.All(char.IsAsciiHexDigitLower));
        }
        var nonce = scope.GetProperty("sourceNonce").GetString();
        Require(Guid.TryParseExact(nonce, "D", out var identity) && identity != Guid.Empty && identity.ToString("D") == nonce);
        Require(scope.GetProperty("knownValuesCommitment").GetString() == Commitment(expected.GetProperty("knownEvents")));
    }

    private static string Commitment(JsonElement value)
    {
        var rows = value.EnumerateArray().ToArray();
        Require(rows.Length == 4);
        var ids = rows.Select(row => row.GetProperty("eventId").GetString()).ToArray();
        Require(ids.SequenceEqual(ids.Order(StringComparer.Ordinal)));
        var builder = new StringBuilder("fleetory.historical.known-values.v1\n");
        foreach (var row in rows)
        {
            Fields(row, "eventId", "key", "revision", "valueSha256");
            builder.Append(row.GetProperty("eventId").GetString()).Append('\n')
                .Append(row.GetProperty("key").GetString()).Append('\n')
                .Append(row.GetProperty("revision").GetInt32().ToString(CultureInfo.InvariantCulture)).Append('\n')
                .Append(row.GetProperty("valueSha256").GetString()).Append('\n');
        }
        return AuditObservation.Hash(Encoding.ASCII.GetBytes(builder.ToString()));
    }
}
