namespace Fleetory.Platform.Contracts.Secrets;

public interface ISecretProvider
{
    string GetRequiredSecret(string name);
}

public static class FleetorySecretNames
{
    public const string PostgreSqlConnectionString = "fleetory-postgresql";
    public const string AgentGatewayRootCa = "agent-gateway-root-ca";
    public const string AgentGatewayServerCertificate = "agent-gateway-server-cert";
    public const string AgentGatewayServerPrivateKey = "agent-gateway-server-key";
}
