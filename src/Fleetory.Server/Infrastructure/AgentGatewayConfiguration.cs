using System.Net;
using Fleetory.Platform.Contracts.Secrets;
using Microsoft.AspNetCore.Server.Kestrel.Https;

namespace Fleetory.Server.Infrastructure;

internal sealed record AgentGatewayConfiguration(int WebPort, int AgentPort);

internal static class AgentGatewayStartup
{
    public static AgentGatewayConfiguration? Configure(
        WebApplicationBuilder builder,
        ISecretProvider? secrets)
    {
        if (!builder.Configuration.GetValue<bool>("Fleetory:AgentGateway:Enabled"))
        {
            return null;
        }

        if (secrets is null)
        {
            throw new InvalidOperationException("Agent Gateway requires Fleetory:Secrets:Directory.");
        }

        var webPort = ReadPort(builder.Configuration["Fleetory:Web:Port"], "Fleetory:Web:Port");
        var agentPort = ReadPort(builder.Configuration["Fleetory:AgentGateway:Port"],
            "Fleetory:AgentGateway:Port");
        if (webPort == agentPort)
        {
            throw new InvalidOperationException("Web and Agent Gateway ports must differ.");
        }

        var tls = AgentGatewayTls.Load(secrets);
        builder.Services.AddSingleton(tls);
        builder.WebHost.ConfigureKestrel(options =>
        {
            options.Listen(IPAddress.Any, webPort);
            options.Listen(IPAddress.Any, agentPort, listen => listen.UseHttps(https =>
            {
                https.ServerCertificate = tls.ServerCertificate;
                https.ClientCertificateMode = ClientCertificateMode.RequireCertificate;
                https.ClientCertificateValidation = tls.ValidateClientCertificate;
            }));
        });

        return new AgentGatewayConfiguration(webPort, agentPort);
    }

    private static int ReadPort(string? value, string key)
    {
        if (!int.TryParse(value, out var port) || port is < 1 or > 65535)
        {
            throw new InvalidOperationException($"{key} must be a TCP port from 1 to 65535.");
        }

        return port;
    }
}
