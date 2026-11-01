using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Fleetory.AdminLogin;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.IdentityModel.Tokens;

namespace Fleetory.Server.Tests;

// Synthetic protocol fixtures prove cryptographic validation, not real passkey enrollment.
public sealed class AdminLoginProtocolTests
{
    [Theory]
    [InlineData("")]
    [InlineData("mixed-jwks")]
    [InlineData("session-state")]
    [InlineData("no-at-hash")]
    public async Task Valid_signed_tokens_bind_nonce_identity_and_pkce_verifier(string mutation)
    {
        using var fixture = new Provider { Mutation=mutation };
        var authorization = await fixture.BeginAsync();
        var query = QueryHelpers.ParseQuery(authorization.Query);
        Assert.Equal("code", query["response_type"]);
        Assert.Equal("S256", query["code_challenge_method"]);
        Assert.Equal("login", query["prompt"]);
        Assert.Equal("0", query["max_age"]);
        Assert.Equal(OidcLoginProtocol.RedirectUriString, query["redirect_uri"]);
        Assert.True(query["state"].ToString().Length >= 32);
        Assert.True(query["nonce"].ToString().Length >= 32);
        Assert.Equal(fixture.AccessToken, await fixture.Protocol.CompleteAsync(fixture.Callback(), default));
        Assert.NotNull(fixture.Verifier);
        Assert.Equal(query["code_challenge"].ToString(), Base64UrlEncoder.Encode(
            SHA256.HashData(Encoding.ASCII.GetBytes(fixture.Verifier!))));
        Assert.Equal(1, fixture.TokenRequests);
    }

    [Theory]
    [InlineData("state")]
    [InlineData("duplicate-state")]
    [InlineData("duplicate-code")]
    [InlineData("origin")]
    [InlineData("callback-path")]
    [InlineData("oauth-error")]
    public async Task Invalid_callback_is_denied_before_token_exchange(string mutation)
    {
        using var fixture = new Provider();
        await fixture.BeginAsync();
        var callback = fixture.Callback().AbsoluteUri;
        callback = mutation switch
        {
            "state" => callback.Replace(fixture.State, "wrong-state", StringComparison.Ordinal),
            "duplicate-state" => callback + "&state=" + fixture.State,
            "duplicate-code" => callback + "&code=second",
            "origin" => callback.Replace("127.0.0.1", "localhost", StringComparison.Ordinal),
            "callback-path" => callback.Replace("/auth/callback", "/wrong", StringComparison.Ordinal),
            _ => OidcLoginProtocol.RedirectUriString + "?error=access_denied&state=" + fixture.State
        };
        await Assert.ThrowsAnyAsync<Exception>(() => fixture.Protocol.CompleteAsync(new Uri(callback), default));
        Assert.Equal(0, fixture.TokenRequests);
        await Assert.ThrowsAnyAsync<Exception>(() => fixture.Protocol.CompleteAsync(fixture.Callback(), default));
    }

    [Theory]
    [InlineData("issuer")]
    [InlineData("nonce")]
    [InlineData("subject")]
    [InlineData("access-audience")]
    [InlineData("id-audience")]
    [InlineData("azp")]
    [InlineData("amr")]
    [InlineData("expired")]
    [InlineData("signature")]
    [InlineData("none")]
    [InlineData("at-hash")]
    [InlineData("token-size")]
    [InlineData("duplicate-json")]
    [InlineData("stale-auth-time")]
    [InlineData("future-auth-time")]
    [InlineData("noninteger-auth-time")]
    [InlineData("missing-auth-time")]
    [InlineData("multi-audience-missing-azp")]
    [InlineData("missing-kid")]
    [InlineData("unknown-kid")]
    public async Task Invalid_provider_tokens_fail_closed(string mutation)
    {
        using var fixture = new Provider { Mutation = mutation };
        await fixture.BeginAsync();
        await Assert.ThrowsAnyAsync<Exception>(() => fixture.Protocol.CompleteAsync(fixture.Callback(), default));
        Assert.Equal(1, fixture.TokenRequests);
        await Assert.ThrowsAnyAsync<Exception>(() => fixture.Protocol.CompleteAsync(fixture.Callback(), default));
        Assert.Equal(1, fixture.TokenRequests);
    }

    [Theory]
    [InlineData("metadata-redirect")]
    [InlineData("metadata-origin")]
    [InlineData("metadata-issuer")]
    [InlineData("metadata-duplicate")]
    [InlineData("jwks-private")]
    [InlineData("jwks-duplicate-kid")]
    [InlineData("jwks-key-ops")]
    public async Task Untrusted_discovery_is_rejected(string mutation)
    {
        using var fixture = new Provider { Mutation = mutation };
        await Assert.ThrowsAnyAsync<Exception>(() => fixture.BeginAsync());
        Assert.Equal(0, fixture.TokenRequests);
    }

    [Fact]
    public async Task Successful_exchange_cannot_be_replayed_or_begun_twice()
    {
        using var fixture = new Provider();
        await fixture.BeginAsync();
        await Assert.ThrowsAnyAsync<Exception>(() => fixture.Protocol.BeginAsync(default));
        Assert.Equal(fixture.AccessToken, await fixture.Protocol.CompleteAsync(fixture.Callback(), default));
        await Assert.ThrowsAnyAsync<Exception>(() => fixture.Protocol.CompleteAsync(fixture.Callback(), default));
        Assert.Equal(1, fixture.TokenRequests);
    }

    [Fact]
    public async Task Cancelled_completion_sends_no_credentials()
    {
        using var fixture = new Provider();
        await fixture.BeginAsync();
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => fixture.Protocol.CompleteAsync(fixture.Callback(), cancellation.Token));
        Assert.Equal(0, fixture.TokenRequests);
    }

    private sealed class Provider : HttpMessageHandler
    {
        private static readonly Uri Issuer = new("https://login.pilot.invalid/realms/fleetory");
        private const string Client = "pilot-client";
        private const string Audience = "fleetory-admin-api";
        private readonly RSA _rsa = RSA.Create(2048);
        private readonly RSA _foreign = RSA.Create(2048);
        private readonly Guid _person = Guid.NewGuid();
        private readonly HttpClient _http;
        public OidcLoginProtocol Protocol { get; }
        public string Mutation { get; init; } = "";
        public string State { get; private set; } = "";
        public string AccessToken { get; private set; } = "";
        public string? Verifier { get; private set; }
        public int TokenRequests { get; private set; }

        public Provider()
        {
            _http = new HttpClient(this, disposeHandler: false);
            Protocol = new OidcLoginProtocol(new LoginSettings(Issuer,Client,Audience,_person),_http);
        }

        public async Task<Uri> BeginAsync()
        {
            var uri = await Protocol.BeginAsync(default);
            var query = QueryHelpers.ParseQuery(uri.Query);
            State = query["state"].ToString();
            var nonce = query["nonce"].ToString();
            AccessToken = Token(false, nonce);
            _idToken = Token(true, nonce);
            return uri;
        }

        private string _idToken = "";
        public Uri Callback() => new(OidcLoginProtocol.RedirectUriString + "?code=synthetic-code&state=" + Uri.EscapeDataString(State) +
            (Mutation == "session-state" ? "&session_state=synthetic-session" : ""));

        private string Token(bool idToken, string nonce)
        {
            var claims = new Dictionary<string,object>
            {
                ["sub"] = Mutation == "subject" ? Guid.NewGuid().ToString("D") : _person.ToString("D"),
                ["azp"] = Mutation == "azp" ? "foreign-client" : Client
            };
            if (idToken)
            {
                claims["nonce"] = Mutation == "nonce" ? "foreign-nonce" : nonce;
                if (Mutation != "no-at-hash")
                    claims["at_hash"] = Mutation == "at-hash" ? "incorrect" : Base64UrlEncoder.Encode(
                        SHA256.HashData(Encoding.ASCII.GetBytes(AccessToken)).AsSpan(0,16).ToArray());
            }
            else claims["amr"] = new[] { Mutation == "amr" ? "pwd" : "webauthn" };
            var now = DateTime.UtcNow;
            if (idToken)
            {
                claims["auth_time"]=DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                if (Mutation=="stale-auth-time") claims["auth_time"]=DateTimeOffset.UtcNow.AddMinutes(-10).ToUnixTimeSeconds();
                if (Mutation=="future-auth-time") claims["auth_time"]=DateTimeOffset.UtcNow.AddMinutes(10).ToUnixTimeSeconds();
                if (Mutation=="noninteger-auth-time") claims["auth_time"]="not-integer";
                if (Mutation=="missing-auth-time") claims.Remove("auth_time");
                if (Mutation=="multi-audience-missing-azp") claims.Remove("azp");
            }
            var key = new RsaSecurityKey(Mutation == "signature" ? _foreign : _rsa)
                { KeyId=Mutation=="missing-kid" ? null : Mutation=="unknown-kid" ? "unknown" : "test-key" };
            var descriptor = new SecurityTokenDescriptor
            {
                Issuer = Mutation == "issuer" ? "https://foreign.invalid/realms/fleetory" : Issuer.AbsoluteUri,
                Audience = Mutation == (idToken ? "id-audience" : "access-audience") ? "foreign-api" : idToken ? Client : Audience,
                Claims = claims,
                IssuedAt = Mutation == "expired" ? now.AddHours(-2) : now,
                NotBefore = Mutation == "expired" ? now.AddHours(-2) : now.AddMinutes(-1),
                Expires = Mutation == "expired" ? now.AddHours(-1) : now.AddMinutes(5),
                SigningCredentials = Mutation == "none" ? null : new SigningCredentials(key,SecurityAlgorithms.RsaSha256)
            };
            if (idToken && Mutation=="multi-audience-missing-azp")
            {
                descriptor.Audience=null;
                descriptor.Audiences.Add(Client);
                descriptor.Audiences.Add("other-client");
            }
            return new JwtSecurityTokenHandler().CreateEncodedJwt(descriptor);
        }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Assert.Equal(Issuer.Host,request.RequestUri!.Host);
            if (request.RequestUri.AbsolutePath.EndsWith("/.well-known/openid-configuration",StringComparison.Ordinal))
            {
                if (Mutation == "metadata-redirect") return new HttpResponseMessage(HttpStatusCode.Redirect) {RequestMessage=request,Headers={Location=new Uri("https://foreign.invalid/discovery")}};
                var metadata = JsonSerializer.Serialize(new {
                    issuer=Mutation=="metadata-issuer" ? "https://foreign.invalid" : Issuer.AbsoluteUri,
                    authorization_endpoint=Issuer+"/protocol/openid-connect/auth",
                    token_endpoint=Mutation=="metadata-origin" ? "https://foreign.invalid/token" : Issuer+"/protocol/openid-connect/token",
                    jwks_uri=Issuer+"/protocol/openid-connect/certs",
                    response_types_supported=new[]{"code"},code_challenge_methods_supported=new[]{"S256"},
                    id_token_signing_alg_values_supported=new[]{"RS256"}});
                if (Mutation=="metadata-duplicate") metadata=metadata.Insert(1,"\"issuer\":\"https://foreign.invalid\",");
                return Json(metadata,request);
            }
            if (request.RequestUri.AbsolutePath.EndsWith("/certs",StringComparison.Ordinal))
            {
                var parameters=_rsa.ExportParameters(false);
                var signingKey=new Dictionary<string,object> {
                    ["kty"]="RSA",["kid"]="test-key",["use"]="sig",["alg"]="RS256",
                    ["n"]=Base64UrlEncoder.Encode(parameters.Modulus!),["e"]=Base64UrlEncoder.Encode(parameters.Exponent!)};
                if (Mutation == "jwks-private") signingKey["d"]="AQAB";
                if (Mutation == "jwks-key-ops") signingKey["key_ops"]=new[]{"sign"};
                var keys=new List<object> {signingKey};
                if (Mutation == "jwks-duplicate-kid") keys.Add(signingKey);
                if (Mutation == "mixed-jwks") keys.Add(new {
                    kty="RSA",kid="encryption-key",use="enc",alg="RSA-OAEP",
                    n=Base64UrlEncoder.Encode(parameters.Modulus!),e=Base64UrlEncoder.Encode(parameters.Exponent!)});
                return Json(JsonSerializer.Serialize(new {keys}),request);
            }
            Assert.EndsWith("/token",request.RequestUri.AbsolutePath,StringComparison.Ordinal);
            TokenRequests++;
            Assert.Equal(HttpMethod.Post,request.Method);
            var form=QueryHelpers.ParseQuery(await request.Content!.ReadAsStringAsync(cancellationToken));
            Verifier=form["code_verifier"].ToString();
            Assert.Equal("authorization_code",form["grant_type"]);
            Assert.Equal("synthetic-code",form["code"]);
            Assert.Equal(Client,form["client_id"]);
            Assert.Equal(OidcLoginProtocol.RedirectUriString,form["redirect_uri"]);
            Assert.InRange(Verifier.Length,43,128);
            var response=JsonSerializer.Serialize(new {access_token=AccessToken,id_token=_idToken,token_type="Bearer",expires_in=300});
            if (Mutation=="token-size") response=new string('x',1024*1024);
            if (Mutation=="duplicate-json") response=response.Insert(1,"\"access_token\":\"duplicate\",");
            return Json(response,request);
        }

        private static HttpResponseMessage Json(string text,HttpRequestMessage request) => new(HttpStatusCode.OK) {RequestMessage=request,Content=new StringContent(text,Encoding.UTF8,"application/json")};
        protected override void Dispose(bool disposing)
        {
            if (disposing) {Protocol.Dispose();_http.Dispose();_rsa.Dispose();_foreign.Dispose();}
            base.Dispose(disposing);
        }
    }
}
