using System.Net;
using Fleetory.Platform.Contracts.Secrets;
using Microsoft.AspNetCore.Server.Kestrel.Https;

namespace Fleetory.Server.Infrastructure;

internal sealed record GatewayConfiguration(int WebPort, int? AgentPort, int? AdminPort);

internal static class GatewayStartup
{
    public static GatewayConfiguration? Configure(
        WebApplicationBuilder builder,
        ISecretProvider? secrets)
    {
        var agentEnabled = builder.Configuration.GetValue<bool>("Fleetory:AgentGateway:Enabled");
        var adminEnabled = builder.Configuration.GetValue<bool>("Fleetory:AdminGateway:Enabled");
        if (!agentEnabled && !adminEnabled)
        {
            return null;
        }

        if (secrets is null)
        {
            throw new InvalidOperationException("Gateways require Fleetory:Secrets:Directory.");
        }

        var webPort = ReadPort(builder.Configuration["Fleetory:Web:Port"], "Fleetory:Web:Port");
        var agentPort = agentEnabled
            ? ReadPort(builder.Configuration["Fleetory:AgentGateway:Port"], "Fleetory:AgentGateway:Port")
            : (int?)null;
        var adminPort = adminEnabled
            ? ReadPort(builder.Configuration["Fleetory:AdminGateway:Port"], "Fleetory:AdminGateway:Port")
            : (int?)null;
        var adminBindAddress = adminEnabled
            ? ReadAdminBindAddress(builder.Configuration["Fleetory:AdminGateway:BindAddress"])
            : IPAddress.Loopback;
        if (agentPort == webPort || adminPort == webPort ||
            (agentPort is not null && agentPort == adminPort))
        {
            throw new InvalidOperationException("Web, Agent and Admin Gateway ports must differ.");
        }

        MutualTlsMaterial? agentTls = null;
        MutualTlsMaterial? adminTls = null;
        try
        {
            if (agentEnabled)
            {
                agentTls = MutualTlsMaterial.Load(secrets,
                    FleetorySecretNames.AgentGatewayRootCa,
                    FleetorySecretNames.AgentGatewayServerCertificate,
                    FleetorySecretNames.AgentGatewayServerPrivateKey);
            }

            if (adminEnabled)
            {
                adminTls = MutualTlsMaterial.Load(secrets,
                    FleetorySecretNames.AdminGatewayRootCa,
                    FleetorySecretNames.AdminGatewayServerCertificate,
                    FleetorySecretNames.AdminGatewayServerPrivateKey);
            }

            if (agentTls is not null && adminTls is not null && agentTls.SharesRootWith(adminTls))
            {
                throw new InvalidOperationException("Agent and Admin gateways require separate root CAs.");
            }
        }
        catch
        {
            agentTls?.Dispose();
            adminTls?.Dispose();
            throw;
        }

        if (agentTls is not null)
        {
            builder.Services.AddSingleton(agentTls);
        }

        if (adminTls is not null)
        {
            builder.Services.AddSingleton(adminTls);
        }

        builder.WebHost.ConfigureKestrel(options =>
        {
            options.ListenAnyIP(webPort);
            if (agentPort is not null && agentTls is not null)
            {
                options.ListenAnyIP(agentPort.Value, listen => listen.UseHttps(https =>
                {
                    https.ServerCertificate = agentTls.ServerCertificate;
                    https.ServerCertificateChain = agentTls.ServerCertificateChain;
                    https.ClientCertificateMode = ClientCertificateMode.RequireCertificate;
                    https.ClientCertificateValidation = agentTls.ValidateClientCertificate;
                }));
            }

            if (adminPort is not null && adminTls is not null)
            {
                options.Listen(adminBindAddress, adminPort.Value, listen => listen.UseHttps(https =>
                {
                    https.ServerCertificate = adminTls.ServerCertificate;
                    https.ServerCertificateChain = adminTls.ServerCertificateChain;
                    https.ClientCertificateMode = ClientCertificateMode.RequireCertificate;
                    https.ClientCertificateValidation = adminTls.ValidateClientCertificate;
                }));
            }
        });

        return new GatewayConfiguration(webPort, agentPort, adminPort);
    }

    private static int ReadPort(string? value, string key)
    {
        if (!int.TryParse(value, out var port) || port is < 1 or > 65535)
        {
            throw new InvalidOperationException($"{key} must be a TCP port from 1 to 65535.");
        }

        return port;
    }

    private static IPAddress ReadAdminBindAddress(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return IPAddress.Loopback;
        }

        if (!IPAddress.TryParse(value, out var address) ||
            address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any) ||
            (address.IsIPv4MappedToIPv6 && address.MapToIPv4().Equals(IPAddress.Any)))
        {
            throw new InvalidOperationException(
                "Fleetory:AdminGateway:BindAddress must be a specific IP address.");
        }

        return address;
    }
}
