using Fleetory.Security.Infrastructure;
using Npgsql;

namespace ServerBackendProbe;

internal static class RetainedRuntimeControl
{
    internal static async Task<object> ExecuteAsync(CancellationToken cancellation)
    {
        var files = new FileSecretProvider(Program.PrivateDirectory);
        foreach (var item in new[] { ("fleetory-postgresql", "fleetory", "fleetory_server"),
                                    ("fleetory-signer-postgresql", "fleetory_signer", "fleetory_signer") })
        {
            var binding = new NpgsqlConnectionStringBuilder(files.GetRequiredSecret(item.Item1));
            AuditExpectationSnapshot.Require(binding.Host == "127.0.0.1" && binding.Port == 5432 && binding.Database == item.Item2 &&
                binding.Username == item.Item3 && binding.SslMode == SslMode.VerifyFull && binding.GssEncryptionMode == GssEncryptionMode.Disable &&
                binding.RootCertificate == Program.PrivateDirectory + "/infrastructure-ca" && !string.IsNullOrEmpty(binding.Password) &&
                string.IsNullOrEmpty(binding.Options) && !binding.Pooling && binding.Timeout == 5 && binding.CommandTimeout == 5);
            await using (var connection = new NpgsqlConnection(binding.ConnectionString))
            {
                await connection.OpenAsync(cancellation);
                await using var command = connection.CreateCommand();
                command.CommandText = "SELECT current_user=@role AND rolcanlogin AND NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolreplication AND NOT rolbypassrls " +
                    "AND NOT EXISTS(SELECT 1 FROM pg_auth_members WHERE member=pg_roles.oid) " +
                    "AND NOT has_database_privilege(current_user,current_database(),'CREATE') AND NOT has_database_privilege(current_user,current_database(),'TEMP') " +
                    "AND NOT has_schema_privilege(current_user,'public','CREATE') " +
                    "AND EXISTS(SELECT 1 FROM pg_stat_ssl WHERE pid=pg_backend_pid() AND ssl AND version IN ('TLSv1.2','TLSv1.3')) " +
                    "FROM pg_roles WHERE rolname=current_user;";
                command.Parameters.AddWithValue("role", item.Item3);
                AuditExpectationSnapshot.Require(await command.ExecuteScalarAsync(cancellation) is true);
            }
            var wrong = new NpgsqlConnectionStringBuilder(binding.ConnectionString) { Password = "wrong-" + Guid.NewGuid().ToString("N") };
            await RefuseAsync(wrong, "28P01", cancellation);
            var plain = new NpgsqlConnectionStringBuilder(binding.ConnectionString) { SslMode = SslMode.Disable };
            await RefuseAsync(plain, "28000", cancellation);
        }
        return new { category = "retained-runtime", runtimeTlsLogins = 2, wrongPasswordRefusals = 2, plaintextRefusals = 2,
            boundedRuntimePrivilegesVerified = true, httpHostStarted = false, issuerActivated = false,
            originalCredentialsUsed = false, fullSystemRecoveryVerified = false, phase7Complete = false };
    }

    private static async Task RefuseAsync(NpgsqlConnectionStringBuilder binding, string state, CancellationToken cancellation)
    {
        await using var connection = new NpgsqlConnection(binding.ConnectionString);
        try { await connection.OpenAsync(cancellation); }
        catch (PostgresException error) when (error.SqlState == state) { return; }
        throw new InvalidOperationException("Retained runtime authentication refusal drift.");
    }
}
