using System.Security.Authentication;
using Fleetory.Platform.Contracts;
using Fleetory.SharedKernel;
using Microsoft.Extensions.DependencyInjection;

namespace ServerBackendProbe;

internal static class AuditCases
{
    internal static readonly Guid EventId = Guid.Parse("7cc47965-c6de-4c2a-82e8-5935b38fecea");
    internal static AuditExportEvent Event(string action) => new(EventId,
        new AuditRecord(new ActorReference("fixture:operator", ActorKind.Person), action,
            new AuditTarget("Fixture", "generated"), new CorrelationId("fixture-export"), DateTimeOffset.UnixEpoch,
            new Dictionary<string, string> { ["Decision"] = "Allowed" }), DateTimeOffset.UnixEpoch.AddSeconds(1));

    internal static async Task<string> ExecuteAsync(string mode, IServiceProvider services, CancellationToken cancellation)
    {
        var sink = services.GetRequiredService<IAuditExportSink>();
        try
        {
            var auditEvent = Event(mode == "audit-conflict" ? "Fixture.Conflicting.Write" : "Fixture.Audit.Read");
            if (mode is not ("audit-publish" or "audit-repeat" or "audit-conflict"))
            { auditEvent = auditEvent with { EventId = Guid.Parse("d356549c-77df-46d2-a1da-3c13fe35a8c6") }; }
            await sink.PublishAsync(auditEvent, cancellation);
            return mode is "audit-publish" or "audit-repeat" ? mode : "unexpected-acceptance";
        }
        catch (InvalidOperationException exception) when (Expected(mode, exception.Message) is { } category)
        { return category; }
        catch (HttpRequestException exception) when (mode == "audit-tls" && exception.InnerException is AuthenticationException)
        { return "audit-tls"; }
    }

    private static string? Expected(string mode, string message) => (mode, message) switch
    {
        ("audit-conflict", "Immudb audit event conflicts with an existing key.") => "audit-conflict",
        ("audit-password", "Immudb audit authentication failed.") => "audit-authentication",
        ("audit-readonly", "Immudb audit write failed.") => "audit-privilege",
        ("audit-database", "Immudb audit database selection failed.") => "audit-database",
        _ => null
    };
}
