using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;

namespace Fleetory.ModuleAbstractions;

public static class BoundedJsonRequestReader
{
    public static async Task<T?> ReadAsync<T>(
        HttpContext context,
        long maximumBodyBytes)
    {
        if (maximumBodyBytes < 1 || context.Request.ContentLength is { } length &&
            length > maximumBodyBytes)
        {
            return default;
        }

        var sizeFeature = context.Features.Get<IHttpMaxRequestBodySizeFeature>();
        if (sizeFeature is { IsReadOnly: false })
        {
            sizeFeature.MaxRequestBodySize = maximumBodyBytes;
        }

        try
        {
            return await context.Request.ReadFromJsonAsync<T>(context.RequestAborted);
        }
        catch (Exception exception) when (exception is JsonException or BadHttpRequestException or InvalidOperationException)
        {
            return default;
        }
    }
}
