using System.Text;
using Fleetory.ModuleAbstractions;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;

namespace Fleetory.Server.Tests;

public sealed class BoundedJsonRequestReaderTests
{
    [Theory]
    [InlineData("missing", false)]
    [InlineData("missing", true)]
    [InlineData("writable", false)]
    [InlineData("writable", true)]
    [InlineData("readonly", false)]
    [InlineData("readonly", true)]
    public async Task Byte_limit_is_enforced_independently_of_host_features(string feature, bool oversized)
    {
        const string json = "{\"name\":\"x\"}";
        var limit = Encoding.UTF8.GetByteCount(json);
        using var body = new MemoryStream(Encoding.UTF8.GetBytes(json + (oversized ? new string(' ', 4096) : "")));
        var context = CreateContext(body);
        if (feature != "missing")
        {
            context.Features.Set<IHttpMaxRequestBodySizeFeature>(new BodySizeFeature(feature == "readonly"));
        }

        var result = await BoundedJsonRequestReader.ReadAsync<Payload>(context, limit);
        if (oversized) { Assert.Null(result); }
        else { Assert.Equal("x", result?.Name); }
        Assert.Same(body, context.Request.Body);
        Assert.True(body.CanRead);
        Assert.InRange(body.Position, 0L, limit + 1L);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    public async Task Limit_counts_original_wire_bytes_before_charset_transcoding(int excess)
    {
        var bytes = Encoding.Unicode.GetBytes("{\"name\":\"Ж\"}");
        using var body = new MemoryStream(bytes);
        var context = CreateContext(body);
        context.Request.ContentType = "application/json; charset=utf-16";
        var result = await BoundedJsonRequestReader.ReadAsync<Payload>(context, bytes.Length - excess);
        if (excess == 0) { Assert.Equal("Ж", result?.Name); }
        else { Assert.Null(result); }
        Assert.Same(body, context.Request.Body);
        Assert.True(body.CanRead);
    }

    [Fact]
    public async Task Declared_oversize_is_rejected_before_body_read()
    {
        using var body = new MemoryStream(Encoding.UTF8.GetBytes("{\"name\":\"x\"}"));
        var context = CreateContext(body);
        context.Request.ContentLength = 101;
        Assert.Null(await BoundedJsonRequestReader.ReadAsync<Payload>(context, 100));
        Assert.Equal(0L, body.Position);
    }

    [Fact]
    public async Task Malformed_json_preserves_host_stream_ownership()
    {
        using var body = new MemoryStream(Encoding.UTF8.GetBytes("{"));
        var context = CreateContext(body);
        Assert.Null(await BoundedJsonRequestReader.ReadAsync<Payload>(context, 100));
        Assert.Same(body, context.Request.Body);
        Assert.True(body.CanRead);
    }

    [Fact]
    public async Task Unsupported_media_type_does_not_consume_the_body()
    {
        using var body = new MemoryStream(Encoding.UTF8.GetBytes("{\"name\":\"x\"}"));
        var context = CreateContext(body);
        context.Request.ContentType = "text/plain";
        Assert.Null(await BoundedJsonRequestReader.ReadAsync<Payload>(context, 100));
        Assert.Equal(0L, body.Position);
    }

    [Fact]
    public async Task Client_cancellation_propagates()
    {
        using var body = new MemoryStream(Encoding.UTF8.GetBytes("{\"name\":\"x\"}"));
        using var cancellation = new CancellationTokenSource();
        await cancellation.CancelAsync();
        var context = CreateContext(body);
        context.RequestAborted = cancellation.Token;
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => BoundedJsonRequestReader.ReadAsync<Payload>(context, 100));
        Assert.Same(body, context.Request.Body);
        Assert.True(body.CanRead);
    }

    private static DefaultHttpContext CreateContext(Stream body)
    {
        var context = new DefaultHttpContext();
        context.Request.ContentType = "application/json";
        context.Request.Body = body;
        return context;
    }

    private sealed class BodySizeFeature(bool readOnly) : IHttpMaxRequestBodySizeFeature
    {
        public bool IsReadOnly => readOnly;
        public long? MaxRequestBodySize { get; set; } = 30_000_000;
    }

    private sealed record Payload(string Name);
}
