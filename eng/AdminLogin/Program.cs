using System.Diagnostics;
using System.Text.Json;
using Fleetory.AdminLogin;

if (args.Length is < 1 or > 2 || args.Length == 2 && args[1] is not ("--no-browser" or "--check-config"))
{
    Console.Error.WriteLine("Usage: AdminLogin <absolute protected profile.json> [--no-browser|--check-config]");
    return 2;
}
using var lifetime = new CancellationTokenSource(TimeSpan.FromMinutes(5));
ConsoleCancelEventHandler cancel = (_, e) => { e.Cancel = true; lifetime.Cancel(); };
Console.CancelKeyPress += cancel;
try
{
    using var document = JsonDocument.Parse(OperatorFiles.Read(args[0]), new JsonDocumentOptions { MaxDepth = 4 });
    var root = document.RootElement;
    var expected = new HashSet<string>(["schema","issuer","clientId","audience","personId","adminApiOrigin",
        "probeRoleId","adminServerRootPem","adminClientLeafPem","adminClientKeyPem"], StringComparer.Ordinal);
    foreach (var member in root.EnumerateObject())
        if (!expected.Remove(member.Name)) throw new InvalidOperationException();
    if (expected.Count != 0 || Read("schema") != "fleetory.admin-login.v1") throw new InvalidOperationException();
    var person = Guid.ParseExact(Read("personId"), "D");
    var role = Guid.ParseExact(Read("probeRoleId"), "D");
    var settings = new LoginSettings(new Uri(Read("issuer"), UriKind.Absolute), Read("clientId"), Read("audience"), person);
    using var probe = new AdminApiProbe(new Uri(Read("adminApiOrigin"), UriKind.Absolute), person, role,
        OperatorFiles.Read(Read("adminServerRootPem")), OperatorFiles.Read(Read("adminClientLeafPem")),
        OperatorFiles.Read(Read("adminClientKeyPem")));
    using var http = new HttpClient(new HttpClientHandler
    {
        AllowAutoRedirect = false, UseCookies = false, UseProxy = false, UseDefaultCredentials = false
    }) { Timeout = TimeSpan.FromSeconds(15) };
    using var protocol = new OidcLoginProtocol(settings, http);
    var authorization = await protocol.BeginAsync(lifetime.Token);
    if (args.Length == 2 && args[1] == "--check-config")
    {
        Console.WriteLine("PASS: protected profile, Admin identity/material and HTTPS provider discovery verified. No human login was performed.");
        return 0;
    }
    await using var callback = await LoopbackCallbackReceiver.StartAsync(lifetime.Token);
    Console.WriteLine("Complete this login in your browser with your actual passkey:");
    Console.WriteLine(authorization.AbsoluteUri); // Contains no code, bearer token or PKCE verifier.
    if (args.Length == 1)
        Process.Start(new ProcessStartInfo(authorization.AbsoluteUri) { UseShellExecute = true });
    var returned = await callback.WaitAsync(lifetime.Token);
    var accessToken = await protocol.CompleteAsync(returned, lifetime.Token);
    try
    {
        var status = await probe.RunAsync(accessToken, lifetime.Token);
        Console.WriteLine($"PASS: provider-validated WebAuthn identity matched Admin mTLS; read-only probe HTTP {status}.");
    }
    finally { accessToken = string.Empty; }
    return 0;
    string Read(string name)
    {
        var value = root.GetProperty(name).GetString();
        if (string.IsNullOrWhiteSpace(value) || value.Length > 4096 || value.Any(char.IsControl))
            throw new InvalidOperationException();
        return value;
    }
}
catch (OperationCanceledException)
{
    Console.Error.WriteLine("Login cancelled or timed out. No token was saved.");
    return 1;
}
catch
{
    Console.Error.WriteLine("Admin login failed. No code, token, credentials or response data was logged.");
    return 1;
}
finally { Console.CancelKeyPress -= cancel; }
