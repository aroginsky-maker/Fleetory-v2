using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;

namespace Fleetory.ModuleAbstractions;

public static class BoundedJsonRequestReader
{
    public static async Task<T?> ReadAsync<T>(
        HttpContext context,
        long maximumBodyBytes,
        JsonSerializerOptions? options = null)
    {
        if (maximumBodyBytes < 1 || context.Request.ContentLength is { } length &&
            length > maximumBodyBytes)
        {
            return default;
        }
        if (!context.Request.HasJsonContentType()) { return default; }

        var sizeFeature = context.Features.Get<IHttpMaxRequestBodySizeFeature>();
        if (sizeFeature is { IsReadOnly: false })
        {
            sizeFeature.MaxRequestBodySize = maximumBodyBytes;
        }

        try
        {
            var original = context.Request.Body;
            var bytes = await BoundedStreamReader.ReadAsync(original,
                maximumBodyBytes, context.RequestAborted);
            if (bytes is null) { return default; }
            using var buffered = new MemoryStream(bytes, writable: false);
            try
            {
                context.Request.Body = buffered;
                return await context.Request.ReadFromJsonAsync<T>(options, context.RequestAborted);
            }
            finally { context.Request.Body = original; }
        }
        catch (Exception exception) when (exception is JsonException or BadHttpRequestException or InvalidOperationException)
        {
            return default;
        }
    }
}
