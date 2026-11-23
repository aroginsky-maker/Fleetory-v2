using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;

namespace Fleetory.Server.Infrastructure;

public static class AdminOidcAuthentication
{
    public const string Scheme = "FleetoryAdminOidc";

    public static bool Configure(WebApplicationBuilder builder)
    {
        var adminEnabled = builder.Configuration.GetValue<bool>("Fleetory:AdminGateway:Enabled");
        var oidcEnabled = builder.Configuration.GetValue<bool>("Fleetory:AdminGateway:Oidc:Enabled");
        if (!adminEnabled)
        {
            if (oidcEnabled)
            {
                throw new InvalidOperationException("Admin OIDC requires the Admin Gateway.");
            }

            return false;
        }

        if (!oidcEnabled)
        {
            if (!builder.Environment.IsDevelopment())
            {
                throw new InvalidOperationException("Non-development Admin Gateway requires OIDC authentication.");
            }

            return false;
        }

        var authorityValue = builder.Configuration["Fleetory:AdminGateway:Oidc:Authority"];
        var audience = builder.Configuration["Fleetory:AdminGateway:Oidc:Audience"];
        var clientId = builder.Configuration["Fleetory:AdminGateway:Oidc:ClientId"];
        if (!Uri.TryCreate(authorityValue, UriKind.Absolute, out var authority) ||
            authority.UserInfo.Length != 0 || authority.Query.Length != 0 ||
            authority.Fragment.Length != 0 ||
            !(authority.Scheme == Uri.UriSchemeHttps ||
              builder.Environment.IsDevelopment() &&
              authority.Scheme == Uri.UriSchemeHttp && authority.IsLoopback) ||
            string.IsNullOrWhiteSpace(audience) || audience.Length > 128 ||
            string.IsNullOrWhiteSpace(clientId) || clientId.Length > 128)
        {
            throw new InvalidOperationException("Admin OIDC requires a valid Authority, Audience and ClientId.");
        }

        builder.Services.AddAuthentication()
            .AddJwtBearer(Scheme, options =>
            {
                options.Authority = authority.AbsoluteUri.TrimEnd('/');
                options.Audience = audience;
                options.RequireHttpsMetadata = authority.Scheme == Uri.UriSchemeHttps;
                options.MapInboundClaims = false;
                options.SaveToken = false;
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    RequireExpirationTime = true,
                    ClockSkew = TimeSpan.FromSeconds(30)
                };
            });
        return true;
    }

    public static bool MatchesMfaActor(ClaimsPrincipal principal, string actorSubjectId, string clientId)
    {
        if (principal.Identity?.IsAuthenticated != true ||
            !actorSubjectId.StartsWith("person:", StringComparison.Ordinal) ||
            !Guid.TryParseExact(actorSubjectId.AsSpan("person:".Length), "N", out var certificateId) ||
            !Guid.TryParseExact(principal.FindFirstValue("sub"), "D", out var tokenId) ||
            tokenId != certificateId ||
            !string.Equals(principal.FindFirstValue("azp"), clientId, StringComparison.Ordinal))
        {
            return false;
        }

        return principal.FindAll("amr")
            .Any(claim => string.Equals(claim.Value, "webauthn", StringComparison.Ordinal));
    }
}
