using System.Net;
using System.Net.Sockets;
using Fleetory.AdminLogin;

namespace Fleetory.Server.Tests;

[CollectionDefinition("Admin login fixed callback port", DisableParallelization=true)]
public sealed class AdminLoginCallbackCollection;

[Collection("Admin login fixed callback port")]
public sealed class AdminLoginCallbackTests
{
    [Fact]
    public async Task Callback_is_delivered_once_without_reflection_or_caching()
    {
        using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(10));
        await using var receiver=await LoopbackCallbackReceiver.StartAsync(timeout.Token);
        using var http=Client();
        const string query="?code=synthetic-sensitive-code&state=synthetic-sensitive-state";
        using var first=await http.GetAsync(OidcLoginProtocol.RedirectUriString+query,timeout.Token);
        Assert.Equal(HttpStatusCode.OK,first.StatusCode);
        Assert.True(first.Headers.CacheControl?.NoStore);
        Assert.Equal("no-referrer",Assert.Single(first.Headers.GetValues("Referrer-Policy")));
        var body=await first.Content.ReadAsStringAsync(timeout.Token);
        Assert.DoesNotContain("synthetic-sensitive",body,StringComparison.Ordinal);
        Assert.Equal(OidcLoginProtocol.RedirectUriString+query,(await receiver.WaitAsync(timeout.Token)).AbsoluteUri);
        using var second=await http.GetAsync(OidcLoginProtocol.RedirectUriString+"?code=second&state=second",timeout.Token);
        Assert.Equal(HttpStatusCode.Conflict,second.StatusCode);
        Assert.True(second.Headers.CacheControl?.NoStore);
        Assert.DoesNotContain("second",await second.Content.ReadAsStringAsync(timeout.Token),StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("host")]
    [InlineData("method")]
    [InlineData("path")]
    [InlineData("missing-query")]
    public async Task Invalid_request_does_not_consume_callback(string mutation)
    {
        using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(10));
        await using var receiver=await LoopbackCallbackReceiver.StartAsync(timeout.Token);
        using var http=Client();
        var uri=OidcLoginProtocol.RedirectUriString+"?code=not-reflected&state=not-reflected";
        if (mutation=="path") uri=uri.Replace("/auth/callback","/unexpected",StringComparison.Ordinal);
        if (mutation=="missing-query") uri=OidcLoginProtocol.RedirectUriString;
        using var request=new HttpRequestMessage(mutation=="method" ? HttpMethod.Post : HttpMethod.Get,uri);
        if (mutation=="host") request.Headers.Host="localhost:48329";
        using var rejected=await http.SendAsync(request,timeout.Token);
        Assert.Equal(HttpStatusCode.BadRequest,rejected.StatusCode);
        Assert.True(rejected.Headers.CacheControl?.NoStore);
        Assert.DoesNotContain("not-reflected",await rejected.Content.ReadAsStringAsync(timeout.Token),StringComparison.Ordinal);
        using var accepted=await http.GetAsync(OidcLoginProtocol.RedirectUriString+"?code=accepted&state=accepted",timeout.Token);
        Assert.Equal(HttpStatusCode.OK,accepted.StatusCode);
        Assert.Contains("code=accepted",(await receiver.WaitAsync(timeout.Token)).Query,StringComparison.Ordinal);
    }

    [Fact]
    public async Task Occupied_port_fails_and_disposal_releases_listener()
    {
        using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var blocker=new TcpListener(IPAddress.Loopback,48329);
        blocker.Start();
        try { await Assert.ThrowsAnyAsync<Exception>(()=>LoopbackCallbackReceiver.StartAsync(timeout.Token)); }
        finally { blocker.Stop(); }
        var receiver=await LoopbackCallbackReceiver.StartAsync(timeout.Token);
        await receiver.DisposeAsync();
        var probe=new TcpListener(IPAddress.Loopback,48329);
        try { probe.Start(); }
        finally { probe.Stop(); }
    }

    [Fact]
    public async Task Cancelled_wait_does_not_complete_or_consume_receiver()
    {
        using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(10));
        await using var receiver=await LoopbackCallbackReceiver.StartAsync(timeout.Token);
        using var cancelled=new CancellationTokenSource();
        cancelled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(()=>receiver.WaitAsync(cancelled.Token));
        using var http=Client();
        using var response=await http.GetAsync(OidcLoginProtocol.RedirectUriString+"?code=after-cancel&state=after-cancel",timeout.Token);
        Assert.Equal(HttpStatusCode.OK,response.StatusCode);
        Assert.Contains("after-cancel",(await receiver.WaitAsync(timeout.Token)).Query,StringComparison.Ordinal);
    }

    [Fact]
    public async Task Disposing_receiver_cancels_pending_wait()
    {
        using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var receiver=await LoopbackCallbackReceiver.StartAsync(timeout.Token);
        var pending=receiver.WaitAsync(timeout.Token);
        await receiver.DisposeAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(()=>pending);
    }

    private static HttpClient Client() => new(new HttpClientHandler {AllowAutoRedirect=false,UseProxy=false})
        {Timeout=TimeSpan.FromSeconds(5)};
}
