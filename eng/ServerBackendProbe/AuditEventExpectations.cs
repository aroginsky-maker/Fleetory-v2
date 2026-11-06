namespace ServerBackendProbe;

internal static class AuditEventExpectations
{
    internal static async Task<object> ExecuteAsync(string expectedPin, string nonce)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(18));
        AuditExpectationSnapshot.Require(expectedPin.Length == 64 && expectedPin.All(char.IsAsciiHexDigitLower));
        _ = AuditExpectationSnapshot.Identity(nonce);
        var bytes = await ReadAsync(deadline.Token);
        AuditExpectationSnapshot.Require(AuditObservation.Hash(bytes) == expectedPin);
        var events = AuditExpectationSnapshot.Parse(bytes);
        var known = new List<object>();
        var requests = 0;
        foreach (var source in events)
        {
            var captured = await AuditExpectationCapture.SerializeAsync(source, deadline.Token);
            requests += captured.Requests;
            known.Add(new { eventId = source.Event.EventId, key = FixtureAuditClient.EventKey(source.Event.EventId), revision = 1, valueSha256 = captured.Hash });
        }
        return new { category = "audit-expectations", schema = "fleetory.audit-event-expectations.v1", nonce,
            snapshotSha256 = expectedPin, knownEvents = known, eventFields = 10, inMemoryRequests = requests,
            productionSinkSerializationUsed = true, sourceOriginAuthenticated = false, sourceIndependenceAuthenticated = false,
            realBackendContacted = false, sourceFileOpened = false, signaturesVerified = false,
            executionAuthorized = false, fullSystemRecoveryVerified = false, phase7Complete = false };
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
