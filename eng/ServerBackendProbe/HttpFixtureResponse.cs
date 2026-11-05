using System.Net;

namespace ServerBackendProbe;

internal static class HttpFixtureResponse
{
    internal static void RequireEmpty(string response, HttpStatusCode expected, string? correlation)
    {
        var status = expected switch
        {
            HttpStatusCode.NoContent => "204 No Content", HttpStatusCode.Unauthorized => "401 Unauthorized",
            HttpStatusCode.Forbidden => "403 Forbidden", HttpStatusCode.NotFound => "404 Not Found",
            _ => throw new InvalidOperationException("Unsupported fixture HTTP status.")
        };
        if (response.Length > 1024 || !response.StartsWith("HTTP/1.1 " + status + "\r\n", StringComparison.Ordinal) ||
            response.IndexOf("\r\n\r\n", StringComparison.Ordinal) != response.Length - 4)
        { throw new InvalidOperationException("Fixture HTTP status/body drift."); }
        var lengths = Headers(response, "Content-Length");
        var correlations = Headers(response, "X-Correlation-ID");
        if ((expected == HttpStatusCode.NoContent ? lengths.Length != 0 : lengths is not ["0"]) ||
            Headers(response, "Transfer-Encoding").Length != 0 ||
            correlation is not null && (correlations.Length != 1 || correlations[0] != correlation))
        { throw new InvalidOperationException("Fixture HTTP framing/correlation drift."); }
    }

    private static string[] Headers(string response, string name) => response.Split("\r\n")
        .Where(line => line.StartsWith(name + ":", StringComparison.OrdinalIgnoreCase))
        .Select(line => line[(name.Length + 1)..].Trim()).ToArray();

    internal static object VerifyContract()
    {
        foreach (var (code, text) in new[] { (204, "204 No Content"), (401, "401 Unauthorized"), (403, "403 Forbidden"), (404, "404 Not Found") })
        {
            var length = code == 204 ? "" : "content-length: 0\r\n";
            RequireEmpty("HTTP/1.1 " + text + "\r\n" + length + "x-correlation-id: fixture\r\n\r\n", (HttpStatusCode)code, "fixture");
        }
        const string valid = "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nX-Correlation-ID: fixture\r\n\r\n";
        var refused = 0;
        foreach (var bad in new[] { valid + "\r\n\r\n", valid + "x", valid[..^2],
            valid.Replace("403 Forbidden", "404 Not Found", StringComparison.Ordinal),
            valid.Replace("Length: 0", "Length: 1", StringComparison.Ordinal),
            valid.Replace("Content-Length: 0", "Content-Length: 0\r\nContent-Length: 0", StringComparison.Ordinal),
            valid.Replace("Content-Length: 0", "Transfer-Encoding: chunked", StringComparison.Ordinal),
            valid.Replace("X-Correlation-ID: fixture", "X-Correlation-ID: other", StringComparison.Ordinal),
            valid.Replace("X-Correlation-ID: fixture", "X-Correlation-ID: fixture\r\nX-Correlation-ID: fixture", StringComparison.Ordinal),
            valid.Replace("X-Correlation-ID: fixture\r\n", "", StringComparison.Ordinal), new string('x', 1025) })
        {
            try { RequireEmpty(bad, HttpStatusCode.Forbidden, "fixture"); }
            catch (InvalidOperationException) { refused++; continue; }
            throw new InvalidOperationException("Unsafe fixture HTTP response accepted.");
        }
        try { RequireEmpty("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n", HttpStatusCode.NoContent, null); }
        catch (InvalidOperationException) { refused++; }
        if (refused != 12) { throw new InvalidOperationException("Fixture HTTP refusal matrix incomplete."); }
        return new { accepted = 4, refused };
    }
}
