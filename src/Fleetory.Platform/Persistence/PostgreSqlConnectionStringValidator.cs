using Npgsql;

namespace Fleetory.Platform.Persistence;

public static class PostgreSqlConnectionStringValidator
{
    public static void Validate(string connectionString)
    {
        NpgsqlConnectionStringBuilder builder;
        try
        {
            builder = new NpgsqlConnectionStringBuilder(connectionString);
        }
        catch (ArgumentException)
        {
            throw new InvalidOperationException("PostgreSQL connection string is invalid.");
        }

        if (string.IsNullOrWhiteSpace(builder.Host) || string.IsNullOrWhiteSpace(builder.Database))
        {
            throw new InvalidOperationException("PostgreSQL connection string must define Host and Database.");
        }
    }
}
