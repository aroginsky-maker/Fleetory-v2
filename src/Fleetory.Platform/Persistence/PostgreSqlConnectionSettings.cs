namespace Fleetory.Platform.Persistence;

internal sealed class PostgreSqlConnectionSettings
{
    public PostgreSqlConnectionSettings(string connectionString)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(connectionString);
        ConnectionString = connectionString;
    }

    public string ConnectionString { get; }

    public override string ToString() => nameof(PostgreSqlConnectionSettings);
}
