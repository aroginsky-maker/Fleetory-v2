using System.Net;
using System.Text;
using Fleetory.Platform.Secrets;

namespace Fleetory.Server.Tests;

public sealed class OpenBaoSecretProviderTests
{
    [Fact]
    public void Reads_kv_v2_secret_once_and_sends_token_only_as_header()
    {
        var calls = 0;
        using var handler = new StubHandler(request =>
        {
            calls++;
            Assert.Equal("/v1/secret/data/fleetory/fleetory-postgresql", request.RequestUri?.AbsolutePath);
            Assert.Equal("local-token", request.Headers.GetValues("X-Vault-Token").Single());
            Assert.DoesNotContain("local-token", request.RequestUri!.ToString(), StringComparison.Ordinal);
            return Json(HttpStatusCode.OK, "{\"data\":{\"data\":{\"value\":\"safe-value\"}}}");
        });
        using var provider = new OpenBaoSecretProvider(new Uri("http://127.0.0.1:8200/"),
            "local-token", allowInsecureLoopback: true, handler);

        Assert.Equal("safe-value", provider.GetRequiredSecret("fleetory-postgresql"));
        Assert.Equal("safe-value", provider.GetRequiredSecret("fleetory-postgresql"));
        Assert.Equal(1, calls);
    }

    [Theory]
    [InlineData("http://example.com/")]
    [InlineData("http://127.0.0.1:8200/other")]
    [InlineData("https://example.com/path")]
    [InlineData("https://user:password@example.com/")]
    public void Rejects_insecure_or_non_origin_address(string address)
    {
        Assert.Throws<ArgumentException>(() => new OpenBaoSecretProvider(new Uri(address),
            "token", allowInsecureLoopback: true));
    }

    [Fact]
    public void Rejects_invalid_name_before_network_access()
    {
        using var handler = new StubHandler(_ => throw new Exception("Unexpected network request."));
        using var provider = new OpenBaoSecretProvider(new Uri("https://vault.example/"),
            "token", handler: handler);

        Assert.Throws<ArgumentException>(() => provider.GetRequiredSecret("../escape"));
    }

    [Theory]
    [InlineData(HttpStatusCode.Forbidden, "{}")]
    [InlineData(HttpStatusCode.OK, "{\"data\":{\"data\":{}}}")]
    [InlineData(HttpStatusCode.OK, "not-json")]
    public void Rejects_failed_or_invalid_response_without_exposing_it(HttpStatusCode status, string body)
    {
        using var handler = new StubHandler(_ => Json(status, body));
        using var provider = new OpenBaoSecretProvider(new Uri("https://vault.example/"),
            "token", handler: handler);

        var exception = Assert.Throws<InvalidOperationException>(() =>
            provider.GetRequiredSecret("fleetory-postgresql"));
        Assert.DoesNotContain(body, exception.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void Rejects_oversized_response()
    {
        var body = "{\"data\":{\"data\":{\"value\":\"" + new string('x', 21 * 1024) + "\"}}}";
        using var handler = new StubHandler(_ => Json(HttpStatusCode.OK, body));
        using var provider = new OpenBaoSecretProvider(new Uri("https://vault.example/"),
            "token", handler: handler);

        Assert.Throws<InvalidOperationException>(() => provider.GetRequiredSecret("fleetory-postgresql"));
    }

    private static HttpResponseMessage Json(HttpStatusCode status, string body) => new(status)
    {
        Content = new StringContent(body, Encoding.UTF8, "application/json")
    };

    private sealed class StubHandler(Func<HttpRequestMessage, HttpResponseMessage> respond)
        : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(respond(request));
    }
}
