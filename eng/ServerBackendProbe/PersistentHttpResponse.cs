using System.Net;
using System.Text;

namespace ServerBackendProbe;

// Separate keep-alive framing: first response ends at its validated zero-body frame,
// second must also reach EOF. The existing one-request EOF reader stays unchanged.
internal static class PersistentHttpResponse
{
    internal static async Task ReadAsync(Stream stream, HttpStatusCode expected, string correlation,
        bool last, CancellationToken cancellation)
    {
        var bytes = new byte[1025];
        var length = 0;
        while (length < bytes.Length)
        {
            if (await stream.ReadAsync(bytes.AsMemory(length, 1), cancellation) == 0)
            { throw new InvalidOperationException("Persistent response ended before its headers."); }
            length++;
            if (length >= 4 && bytes.AsSpan(length - 4, 4).SequenceEqual("\r\n\r\n"u8)) { break; }
        }
        var response = Encoding.ASCII.GetString(bytes, 0, length);
        HttpFixtureResponse.RequireEmpty(response, expected, correlation);
        if (!last && HttpFixtureResponse.Headers(response, "Connection")
            .Any(value => value.Split(',').Any(token => token.Trim().Equals("close", StringComparison.OrdinalIgnoreCase))))
        { throw new InvalidOperationException("Persistent first response closed the connection."); }
        if (last && await stream.ReadAsync(bytes.AsMemory(0, 1), cancellation) != 0)
        { throw new InvalidOperationException("Persistent final response has trailing bytes."); }
    }

    internal static async Task<object> VerifyContractAsync(CancellationToken cancellation)
    {
        const string first = "HTTP/1.1 204 No Content\r\nX-Correlation-ID: before\r\n\r\n";
        const string second = "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nX-Correlation-ID: after\r\n\r\n";
        await RequirePairAsync(first + second, HttpStatusCode.NoContent, cancellation);
        await RequirePairAsync(first.Replace("204 No Content", "401 Unauthorized", StringComparison.Ordinal)
            .Replace("X-Correlation-ID", "Content-Length: 0\r\nX-Correlation-ID", StringComparison.Ordinal) + second,
            HttpStatusCode.Unauthorized, cancellation);
        var refused = 0;
        foreach (var bad in new[] { first + "x" + second, first + "\r\n" + second,
            first + second + "\r\n\r\n", first + second + "x", first + second[..^2],
            first.Replace("204 No Content", "401 Unauthorized", StringComparison.Ordinal) + second,
            first.Replace("X-Correlation-ID", "Content-Length: 0\r\nX-Correlation-ID", StringComparison.Ordinal) + second,
            first.Replace("before", "wrong", StringComparison.Ordinal) + second,
            first.Replace("X-Correlation-ID: before", "X-Correlation-ID: before\r\nX-Correlation-ID: before", StringComparison.Ordinal) + second,
            first.Replace("X-Correlation-ID", "Connection: close\r\nX-Correlation-ID", StringComparison.Ordinal) + second,
            first + second.Replace("403 Forbidden", "401 Unauthorized", StringComparison.Ordinal),
            first + second.Replace("Content-Length: 0", "Transfer-Encoding: chunked", StringComparison.Ordinal),
            first + second.Replace("after", "wrong", StringComparison.Ordinal), new string('x', 1025) + second })
        {
            try { await RequirePairAsync(bad, HttpStatusCode.NoContent, cancellation); }
            catch (InvalidOperationException) { refused++; continue; }
            throw new InvalidOperationException("Unsafe persistent HTTP pair accepted.");
        }
        return new { acceptedPairs = 2, refusedPairs = refused };
    }

    private static async Task RequirePairAsync(string bytes, HttpStatusCode first, CancellationToken cancellation)
    {
        using var stream = new MemoryStream(Encoding.ASCII.GetBytes(bytes), false);
        await ReadAsync(stream, first, "before", false, cancellation);
        await ReadAsync(stream, HttpStatusCode.Forbidden, "after", true, cancellation);
    }
}
