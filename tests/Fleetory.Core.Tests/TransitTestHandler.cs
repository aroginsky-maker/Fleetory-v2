using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Fleetory.Core.Tests;

internal sealed class TransitTestHandler(ECDsa key) : HttpMessageHandler
{
    public Action? OnSigning { get; set; }
    public string? Replacement { get; set; }
    public bool Redirect { get; set; }
    public HttpStatusCode? FailureStatus { get; set; }
    public string? FailureReason { get; set; }
    public string? JsonResponse { get; set; }
    public string? Token { get; private set; }
    public int RequestedVersion { get; private set; }
    public int CallCount { get; private set; }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        CallCount++;
        Token = request.Headers.GetValues("X-Vault-Token").Single();
        Assert.Equal("/v1/transit/sign/test-key/sha2-256", request.RequestUri?.AbsolutePath);
        if (FailureStatus is { } status)
        {
            return new HttpResponseMessage(status) { ReasonPhrase = FailureReason };
        }
        if (Redirect)
        {
            return new HttpResponseMessage(HttpStatusCode.Redirect)
            {
                Headers = { Location = new Uri("https://evil.example/") }
            };
        }

        using var body = JsonDocument.Parse(await request.Content!.ReadAsStringAsync(cancellationToken));
        RequestedVersion = body.RootElement.GetProperty("key_version").GetInt32();
        Assert.Equal("jws", body.RootElement.GetProperty("marshaling_algorithm").GetString());
        var input = Convert.FromBase64String(body.RootElement.GetProperty("input").GetString()!);
        var signature = key.SignData(input, HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        var encoded = Convert.ToBase64String(signature).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        OnSigning?.Invoke();
        var value = Replacement ?? $"vault:v2:{encoded}";
        return new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(
                JsonResponse ?? JsonSerializer.Serialize(new { data = new { signature = value } }),
                Encoding.UTF8, "application/json")
        };
    }
}
