using System.Diagnostics;

namespace Fleetory.Server.Infrastructure;

public sealed class CorrelationIdMiddleware
{
    public const string HeaderName = "X-Correlation-ID";

    private const int MaxCorrelationIdLength = 128;
    private readonly RequestDelegate _next;
    private readonly ILogger<CorrelationIdMiddleware> _logger;

    public CorrelationIdMiddleware(
        RequestDelegate next,
        ILogger<CorrelationIdMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var correlationId = ResolveCorrelationId(context);

        context.TraceIdentifier = correlationId;
        context.Response.Headers[HeaderName] = correlationId;
        Activity.Current?.SetTag("fleetory.correlation_id", correlationId);

        using var scope = _logger.BeginScope(new Dictionary<string, object?>
        {
            ["CorrelationId"] = correlationId
        });

        await _next(context);
    }

    private static string ResolveCorrelationId(HttpContext context)
    {
        var supplied = context.Request.Headers[HeaderName].ToString();
        return IsValid(supplied) ? supplied : Guid.NewGuid().ToString("N");
    }

    private static bool IsValid(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > MaxCorrelationIdLength)
        {
            return false;
        }

        foreach (var character in value)
        {
            if (!char.IsLetterOrDigit(character) && character != '-' && character != '_' && character != '.' && character != ':')
            {
                return false;
            }
        }

        return true;
    }
}
