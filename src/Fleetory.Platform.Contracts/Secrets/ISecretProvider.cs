namespace Fleetory.Platform.Contracts.Secrets;

public interface ISecretProvider
{
    string GetRequiredSecret(string name);
}

public static class FleetorySecretNames
{
    public const string PostgreSqlConnectionString = "fleetory-postgresql";
}
