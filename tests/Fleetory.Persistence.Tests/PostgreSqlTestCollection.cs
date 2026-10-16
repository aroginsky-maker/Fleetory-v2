namespace Fleetory.Persistence.Tests;

[CollectionDefinition("Fleetory PostgreSQL", DisableParallelization = true)]
public sealed class PostgreSqlTestCollection : ICollectionFixture<PostgreSqlTestFixture>
{
    public const string Name = "Fleetory PostgreSQL";
}
