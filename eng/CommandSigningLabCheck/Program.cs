using System.Net;
using System.Net.Http.Json;
using Fleetory.Agent.Security;
using Fleetory.CommandSigning;
using Fleetory.Core.Contracts;
using Fleetory.SharedKernel;

if (args.Length != 3)
{
    throw new ArgumentException("Expected lab directory, signer directory and DeviceId.");
}

var labDirectory = Path.GetFullPath(args[0]);
var signerDirectory = Path.GetFullPath(args[1]);
var deviceId = new DeviceId(Guid.Parse(args[2]));
var trustDirectory = Path.Combine(labDirectory, "agent-trust");
var signerToken = File.ReadAllText(Path.Combine(signerDirectory, "command-signer-token"));
var serverToken = File.ReadAllText(Path.Combine(labDirectory, "openbao-token"));
const string keyName = "fleetory-lab-command";

using var client = new HttpClient(new SocketsHttpHandler { AllowAutoRedirect = false });
var rootTokenLine = File.ReadAllLines(Path.Combine(labDirectory, "lab.env"))
    .Single(line => line.StartsWith("FLEETORY_LAB_OPENBAO_TOKEN=", StringComparison.Ordinal));
var rootToken = rootTokenLine[(rootTokenLine.IndexOf('=') + 1)..];
using var keyRequest = new HttpRequestMessage(HttpMethod.Get,
    $"http://127.0.0.1:8200/v1/transit/keys/{keyName}");
keyRequest.Headers.Add("X-Vault-Token", rootToken);
using var keyResponse = await client.SendAsync(keyRequest);
keyResponse.EnsureSuccessStatusCode();
var keyData = await keyResponse.Content.ReadFromJsonAsync<System.Text.Json.JsonElement>();
var version = keyData.GetProperty("data").GetProperty("latest_version").GetInt32();
var keyId = $"{keyName}-v{version}";
var keyPath = Path.Combine(trustDirectory, $"{deviceId.Value:N}-{keyId}.spki");
var publicKey = await File.ReadAllBytesAsync(keyPath);

using var signer = new OpenBaoCommandSigner(
    new Uri("http://127.0.0.1:8200/"), signerToken, keyName, version,
    publicKey, allowHttpLoopback: true);
var envelope = await signer.SignInventoryRefreshAsync(deviceId);

var replayDirectory = Path.Combine(Path.GetTempPath(), $"fleetory-command-lab-{Guid.NewGuid():N}");
Directory.CreateDirectory(replayDirectory);
if (!OperatingSystem.IsWindows())
{
    File.SetUnixFileMode(replayDirectory, UnixFileMode.UserRead |
        UnixFileMode.UserWrite | UnixFileMode.UserExecute);
}

try
{
    var verifier = new SignedCommandVerifier(
        new DirectoryCommandVerificationKeys(deviceId, trustDirectory),
        new SqliteCommandReplayStore(Path.Combine(replayDirectory, "replay.db")),
        new AgentCommandExecutionPolicy(deviceId), new SystemClock());
    var first = await verifier.VerifyAsync(envelope, deviceId);
    var second = await verifier.VerifyAsync(envelope, deviceId);
    if (first.Status != CommandVerificationStatus.Accepted ||
        second.Status != CommandVerificationStatus.Replay)
    {
        throw new InvalidOperationException(
            $"Agent verification failed: first={first.Status}, second={second.Status}.");
    }

    using var deniedRequest = new HttpRequestMessage(HttpMethod.Post,
        $"http://127.0.0.1:8200/v1/transit/sign/{keyName}/sha2-256");
    deniedRequest.Headers.Add("X-Vault-Token", serverToken);
    deniedRequest.Content = JsonContent.Create(new
    {
        input = Convert.ToBase64String(envelope.GetSigningBytes()),
        key_version = version,
        marshaling_algorithm = "jws"
    });
    using var deniedResponse = await client.SendAsync(deniedRequest);
    if (deniedResponse.StatusCode != HttpStatusCode.Forbidden)
    {
        throw new InvalidOperationException(
            $"Server token unexpectedly reached Transit sign: {(int)deniedResponse.StatusCode}.");
    }

    Console.WriteLine($"PASS: OpenBao Transit {keyId}, Agent accepted once, replay rejected, Server token denied (403).");
}
finally
{
    Directory.Delete(replayDirectory, recursive: true);
}
