namespace Fleetory.Platform.Contracts;

public sealed record AuthorizationRequest(
    ActorReference Actor,
    string Permission,
    ScopeId? ScopeId = null);

public readonly record struct AuthorizationDecision(
    bool IsAllowed,
    string? Reason)
{
    public static AuthorizationDecision Allow() => new(true, null);

    public static AuthorizationDecision Deny(string reason) => new(false, reason);
}

public interface IAuthorizationService
{
    ValueTask<AuthorizationDecision> AuthorizeAsync(
        AuthorizationRequest request,
        CancellationToken cancellationToken = default);
}
