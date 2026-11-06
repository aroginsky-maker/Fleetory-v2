namespace ServerBackendProbe;

internal static class AuditEventExpectations
{
    internal static async Task<object> ExecuteAsync(string expectedPin, string nonce, bool historical = false)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(18));
        AuditExpectationSnapshot.Require(expectedPin.Length == 64 && expectedPin.All(char.IsAsciiHexDigitLower));
        _ = AuditExpectationSnapshot.Identity(nonce);
        var bytes = await ReadAsync(deadline.Token);
        AuditExpectationSnapshot.Require(AuditObservation.Hash(bytes) == expectedPin);
        var profile = historical ? AuditExpectationProfile.HistoricalReadOnly : AuditExpectationProfile.StrictWriter;
        var events = AuditExpectationSnapshot.Parse(bytes, profile);
        var nullMembers = events.Sum(AuditExpectationSnapshot.NullContextMembers);
        AuditExpectationSnapshot.Require(!historical || nullMembers == 1);
        var known = new List<object>();
        var requests = 0;
        foreach (var source in events)
        {
            var captured = await AuditExpectationCapture.SerializeAsync(source, deadline.Token);
            requests += captured.Requests;
            known.Add(new { eventId = source.Event.EventId, key = FixtureAuditClient.EventKey(source.Event.EventId), revision = 1, valueSha256 = captured.Hash });
        }
        var result = new Dictionary<string, object?>
        {
            ["category"] = historical ? "audit-history-expectations" : "audit-expectations",
            ["schema"] = historical ? "fleetory.audit-historical-expectations.v1" : "fleetory.audit-event-expectations.v1",
            ["nonce"] = nonce, ["snapshotSha256"] = expectedPin, ["knownEvents"] = known,
            ["eventFields"] = 10, ["inMemoryRequests"] = requests, ["productionSinkSerializationUsed"] = true,
            ["sourceOriginAuthenticated"] = false, ["sourceIndependenceAuthenticated"] = false,
            ["realBackendContacted"] = false, ["sourceFileOpened"] = false, ["signaturesVerified"] = false,
            ["executionAuthorized"] = false, ["fullSystemRecoveryVerified"] = false, ["phase7Complete"] = false
        };
        if (historical)
        {
            result["profile"] = "historical-one-null-member-readonly.v1";
            result["nullContextMembersPreserved"] = nullMembers;
            result["productionPumpDeserializationUsed"] = true;
            result["historicalComparisonOnly"] = true;
            result["strictContextValueTypesCompatible"] = false;
            result["writerAdmissionVerified"] = false;
            result["stateMutationAuthorized"] = false;
            result["originalExpectationsAccepted"] = false;
        }
        return result;
    }

    private static async Task<byte[]> ReadAsync(CancellationToken cancellation)
    {
        var buffer = new byte[AuditExpectationSnapshot.MaximumBytes + 1];
        var size = 0;
        var input = Console.OpenStandardInput();
        while (size < buffer.Length)
        {
            var read = await input.ReadAsync(buffer.AsMemory(size), cancellation);
            if (read == 0) { break; }
            size += read;
        }
        AuditExpectationSnapshot.Require(size is > 0 and <= AuditExpectationSnapshot.MaximumBytes);
        return buffer[..size];
    }
}
