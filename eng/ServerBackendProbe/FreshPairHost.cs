using Fleetory.Platform.Persistence;
using Microsoft.AspNetCore.Builder;
using Microsoft.EntityFrameworkCore;

namespace ServerBackendProbe;

internal static class FreshPairHost
{
    internal static async Task<object> ExecuteAsync(WebApplication app, PlatformDbContext platform, bool v2, CancellationToken cancellation)
    {
        using var input = await FixtureAuditClient.ReadPacketAsync(cancellation);
        var packet = input.RootElement;
        NativeHostLifecycle.RequireUnstarted(app);
        // Both native stores must match before StartAsync can run or the worker can claim anything.
        var before = await PreflightAsync(packet, platform, v2, cancellation);
        var stopMilliseconds = await NativeHostLifecycle.ExecuteAsync(app, cancellation);
        var after = await InspectAsync(packet, platform, v2, cancellation);
        var beforeJson = System.Text.Json.JsonSerializer.SerializeToElement(before);
        var afterJson = System.Text.Json.JsonSerializer.SerializeToElement(after);
        foreach (var field in (v2 ? new[] { "historySha256", "events", "keys", "transactions" } : new[] { "eventsSha256", "eventCount", "queueRows" }))
        { if (!System.Text.Json.JsonElement.DeepEquals(beforeJson.GetProperty(field), afterJson.GetProperty(field))) { throw new InvalidOperationException("Fresh pair host changed audit data."); } }
        foreach (var field in new[] { "db", "txId", "txHash" })
        { if (!System.Text.Json.JsonElement.DeepEquals(beforeJson.GetProperty("state").GetProperty(field), afterJson.GetProperty("state").GetProperty(field))) { throw new InvalidOperationException("Fresh pair host changed audit tip."); } }
        return new { category = v2 ? "v2pair-host" : "pair-host", applicationStarts = 1, applicationStops = 1, readiness = "Healthy", healthBodies = 2,
            publicPrivatePathRefusals = 2, listeningPorts = 3, initialClosedPorts = 3, finalClosedPorts = 3,
            workerStopped = true, stopMilliseconds, nonemptyDataUnchanged = true, issuerActivated = false };
    }

    private static async Task<object> PreflightAsync(System.Text.Json.JsonElement packet, PlatformDbContext platform, bool v2, CancellationToken cancellation)
    {
        try { return await InspectAsync(packet, platform, v2, cancellation); }
        catch (InvalidOperationException error) when (error.Message is
            "Fresh pair field count drift." or "Fresh pair field drift." or "Fresh pair event identity drift." or
            "Fresh pair missing event." or "Fresh pair row count drift." or "Fresh pair audit key set drift." or
            "Fresh pair audit revision drift." or "Fresh pair audit changed during readback.")
        { throw new FreshPairPreflightException(); }
    }
    private static Task<object> InspectAsync(System.Text.Json.JsonElement packet, PlatformDbContext platform, bool v2, CancellationToken cancellation) =>
        v2 ? V2PairControl.InspectAsync("v2pair-read", packet, platform.Database.GetDbConnection(), cancellation)
            : FreshPairControl.InspectAsync("pair-read", packet, platform.Database.GetDbConnection(), cancellation);

}

internal sealed class FreshPairPreflightException : Exception;
