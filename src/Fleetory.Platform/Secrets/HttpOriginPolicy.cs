namespace Fleetory.Platform.Secrets;

internal static class HttpOriginPolicy
{
    public static HttpClient CreateNonRedirectingClient(HttpMessageHandler? handler)
    {
        return handler is null
            ? new HttpClient(new HttpClientHandler { AllowAutoRedirect = false })
            : new HttpClient(handler);
    }

    public static void Validate(Uri address, bool allowInsecureLoopback, string service)
    {
        ArgumentNullException.ThrowIfNull(address);
        if (!address.IsAbsoluteUri || address.AbsolutePath != "/" ||
            address.Query.Length != 0 || address.Fragment.Length != 0 ||
            address.Scheme != Uri.UriSchemeHttps &&
            !(allowInsecureLoopback && address.Scheme == Uri.UriSchemeHttp && address.IsLoopback))
        {
            throw new ArgumentException($"{service} address must be an HTTPS origin.", nameof(address));
        }
    }
}
