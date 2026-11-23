using System.Data;
using Fleetory.Core.Persistence;
using Fleetory.Platform.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace ServerBackendProbe;

internal static class RestoreSchema
{
    private static DbContextOptions<T> Options<T>(string schema) where T : DbContext =>
        new DbContextOptionsBuilder<T>().UseNpgsql(
            "Host=127.0.0.1;Database=fleetory;Username=fixture;Pooling=false;Timeout=1",
            postgres => postgres.MigrationsHistoryTable("__EFMigrationsHistory", schema)).Options;

    internal static string Generate()
    {
        using var platform = new PlatformDbContext(Options<PlatformDbContext>(PlatformDbContext.SchemaName));
        using var core = new CoreDbContext(Options<CoreDbContext>(CoreDbContext.SchemaName));
        var sql = platform.GetService<IMigrator>().GenerateScript() + core.GetService<IMigrator>().GenerateScript();
        if (sql.Length is < 1 or > 131072 || platform.Database.GetDbConnection().State != ConnectionState.Closed ||
            core.Database.GetDbConnection().State != ConnectionState.Closed)
        { throw new InvalidOperationException("Offline recovery schema contract failed."); }
        return sql;
    }
}
