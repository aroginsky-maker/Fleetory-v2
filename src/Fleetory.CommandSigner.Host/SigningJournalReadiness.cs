using Npgsql;

namespace Fleetory.CommandSigner.Host;

internal sealed class SigningJournalReadiness(NpgsqlDataSource source) : IHostedService
{
    public async Task<bool> IsReadyAsync(CancellationToken cancellationToken)
    {
        try
        {
            await using var command = source.CreateCommand("""
                SELECT current_user = session_user
                    AND NOT (SELECT rolsuper OR rolcreaterole OR rolcreatedb OR rolbypassrls OR rolreplication
                             FROM pg_roles WHERE rolname = current_user)
                    AND NOT EXISTS (SELECT 1 FROM pg_auth_members
                                    WHERE member = (SELECT oid FROM pg_roles WHERE rolname = current_user))
                    AND NOT has_schema_privilege(current_user, 'signer', 'CREATE')
                    AND has_table_privilege(current_user, 'signer.client_certificate_revocations', 'SELECT')
                    AND NOT has_table_privilege(current_user, 'signer.client_certificate_revocations', 'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
                    AND bool_and(has_table_privilege(current_user, relation, 'SELECT')
                        AND has_table_privilege(current_user, relation, 'INSERT')
                        AND NOT has_table_privilege(current_user, relation, 'UPDATE')
                        AND NOT has_table_privilege(current_user, relation, 'DELETE')
                        AND NOT has_table_privilege(current_user, relation, 'TRUNCATE'))
                FROM unnest(ARRAY['signer.signing_requests', 'signer.signing_results',
                                 'signer.signing_rejections']) AS relation;
                """);
            return await command.ExecuteScalarAsync(cancellationToken) is true;
        }
        catch (NpgsqlException) { return false; }
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        if (!await IsReadyAsync(cancellationToken))
        {
            throw new InvalidOperationException("Signer journal is unavailable or its runtime permissions are unsafe.");
        }
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
