using System.Security.Claims;
using Fleetory.Server.Infrastructure;

namespace Fleetory.Server.Tests;

public sealed class AdminOidcAuthenticationTests
{
    private static readonly Guid PersonId = Guid.Parse("05d409dc-f03c-497c-a0d7-43cc095e8fe5");
    private static readonly string SubjectId = $"person:{PersonId:N}";

    [Fact]
    public void Mfa_token_must_match_certificate_identity_client_and_webauthn_method()
    {
        Assert.True(AdminOidcAuthentication.MatchesMfaActor(
            Principal(PersonId.ToString("D"), "fleetory-admin-lab", "webauthn"),
            SubjectId, "fleetory-admin-lab"));

        Assert.False(AdminOidcAuthentication.MatchesMfaActor(
            Principal(Guid.NewGuid().ToString("D"), "fleetory-admin-lab", "webauthn"),
            SubjectId, "fleetory-admin-lab"));
        Assert.False(AdminOidcAuthentication.MatchesMfaActor(
            Principal(PersonId.ToString("D"), "other-client", "webauthn"),
            SubjectId, "fleetory-admin-lab"));
        Assert.False(AdminOidcAuthentication.MatchesMfaActor(
            Principal(PersonId.ToString("D"), "fleetory-admin-lab", "pwd"),
            SubjectId, "fleetory-admin-lab"));
        Assert.False(AdminOidcAuthentication.MatchesMfaActor(
            Principal(PersonId.ToString("D"), "fleetory-admin-lab", null),
            SubjectId, "fleetory-admin-lab"));
        Assert.False(AdminOidcAuthentication.MatchesMfaActor(
            Principal(PersonId.ToString("D"), "fleetory-admin-lab", "webauthn", authenticated: false),
            SubjectId, "fleetory-admin-lab"));
        Assert.False(AdminOidcAuthentication.MatchesMfaActor(
            Principal("malformed", "fleetory-admin-lab", "webauthn"),
            SubjectId, "fleetory-admin-lab"));
    }

    private static ClaimsPrincipal Principal(
        string subject,
        string authorizedParty,
        string? method,
        bool authenticated = true)
    {
        var claims = new List<Claim>
        {
            new("sub", subject),
            new("azp", authorizedParty)
        };
        if (method is not null)
        {
            claims.Add(new Claim("amr", method));
        }

        return new ClaimsPrincipal(new ClaimsIdentity(claims, authenticated ? "test" : null));
    }
}
