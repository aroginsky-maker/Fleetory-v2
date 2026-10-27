using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using Fleetory.CommandSigner.Host;
using Fleetory.CommandSigning;
using Npgsql;

namespace Fleetory.Persistence.Tests;

public sealed partial class SigningHostTlsTests
{
    [Fact]
    public async Task Revocation_blocks_an_existing_tls_connection_without_restart_but_preserves_another_leaf()
    {
        await using var lab = await HostLab.CreateAsync(fixture, replacement: true);
        using var client = lab.Pki.CreateClient(lab.Pki.Client);
        using var warmup = await client.GetAsync(lab.Url + "/health/live");
        Assert.Equal(HttpStatusCode.NoContent, warmup.StatusCode);
        await lab.RevokeAsync();
        using var denied = await client.PostAsJsonAsync(lab.Url + "/signing/inventory-refresh",
            new { requestId = Guid.NewGuid(), deviceId = lab.Device.Value });
        Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);
        Assert.True(denied.Headers.Contains("X-Fleetory-Audit-Id"));
        Assert.Equal("", await denied.Content.ReadAsStringAsync());
        Assert.Equal(0, lab.TransitCalls);
        Assert.Equal(0L, await lab.CountAsync("signing_requests"));
        using var replacement = lab.Pki.CreateClient(lab.Pki.UnregisteredClient);
        using var accepted = await replacement.PostAsJsonAsync(lab.Url + "/signing/inventory-refresh",
            new { requestId = Guid.NewGuid(), deviceId = lab.Device.Value });
        Assert.Equal(HttpStatusCode.OK, accepted.StatusCode);
        Assert.Equal(1, lab.TransitCalls);
        await using var source = NpgsqlDataSource.Create(fixture.ConnectionString);
        await using var record = source.CreateCommand("""
            SELECT event_id, incident_reference, operator_reference, approver_reference,
                   evidence_sha256, database_operator, revoked_at
            FROM signer.client_certificate_revocations WHERE certificate_sha256 = $1;
            """);
        record.Parameters.AddWithValue(lab.Pki.Client.GetCertHashString(HashAlgorithmName.SHA256));
        await using var reader = await record.ExecuteReaderAsync();
        Assert.True(await reader.ReadAsync());
        Assert.NotEqual(Guid.Empty, reader.GetGuid(0));
        Assert.Equal("INC-signer-test", reader.GetString(1));
        Assert.Equal("operator", reader.GetString(2));
        Assert.Equal("approver", reader.GetString(3));
        Assert.Equal(new string('A', 64), reader.GetString(4));
        Assert.Equal(lab.OperatorRole, reader.GetString(5));
        Assert.True(reader.GetDateTime(6) <= DateTime.UtcNow);
    }

    [Theory]
    [InlineData(false, HttpStatusCode.Forbidden)]
    [InlineData(true, HttpStatusCode.ServiceUnavailable)]
    public async Task Revocation_or_read_failure_during_transit_withholds_the_signature(bool losePermission, HttpStatusCode expected)
    {
        await using var lab = await HostLab.CreateAsync(fixture);
        lab.TransitRelease = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var client = lab.Pki.CreateClient(lab.Pki.Client);
        var signing = client.PostAsJsonAsync(lab.Url + "/signing/inventory-refresh",
            new { requestId = Guid.NewGuid(), deviceId = lab.Device.Value });
        try
        {
            await lab.FirstTransitCall.Task.WaitAsync(TimeSpan.FromSeconds(10));
            if (losePermission) { await lab.ExecuteOwnerAsync($"REVOKE SELECT ON signer.client_certificate_revocations FROM {lab.Role}"); }
            else { await lab.RevokeAsync(); }
        }
        finally { lab.TransitRelease.TrySetResult(); }
        using var response = await signing;
        Assert.Equal(expected, response.StatusCode);
        Assert.Equal("", await response.Content.ReadAsStringAsync());
        Assert.Equal(1, lab.TransitCalls);
        Assert.Equal(1L, await lab.CountAsync("signing_requests"));
        Assert.Equal(0L, await lab.CountAsync("signing_results"));
        Assert.Equal(1L, await lab.CountAsync("signing_rejections"));
    }

    [Fact]
    public async Task Read_permission_loss_fails_closed_before_signing_and_restored_permission_recovers()
    {
        await using var lab = await HostLab.CreateAsync(fixture);
        using var client = lab.Pki.CreateClient(lab.Pki.Client);
        await lab.ExecuteOwnerAsync($"REVOKE SELECT ON signer.client_certificate_revocations FROM {lab.Role}");
        using var unavailable = await client.PostAsJsonAsync(lab.Url + "/signing/inventory-refresh",
            new { requestId = Guid.NewGuid(), deviceId = lab.Device.Value });
        Assert.Equal(HttpStatusCode.ServiceUnavailable, unavailable.StatusCode);
        Assert.Equal(0, lab.TransitCalls);
        Assert.Equal(0L, await lab.CountAsync("signing_requests"));
        await lab.ExecuteOwnerAsync($"GRANT SELECT ON signer.client_certificate_revocations TO {lab.Role}");
        using var recovered = await client.GetAsync(lab.Url + "/health/ready");
        Assert.Equal(HttpStatusCode.NoContent, recovered.StatusCode);
    }

    [Theory]
    [InlineData("missing-read")]
    [InlineData("runtime-write")]
    [InlineData("column-write")]
    [InlineData("journal-column-update")]
    public async Task Startup_rejects_missing_or_excessive_runtime_permissions(string kind)
    {
        await using var lab = await HostLab.CreateAsync(fixture);
        await lab.ExecuteOwnerAsync(kind switch
        {
            "missing-read" => $"REVOKE SELECT ON signer.client_certificate_revocations FROM {lab.Role}",
            "column-write" => $"GRANT INSERT (certificate_sha256) ON signer.client_certificate_revocations TO {lab.Role}",
            "journal-column-update" => $"GRANT UPDATE (caller_id) ON signer.signing_requests TO {lab.Role}",
            _ => $"GRANT INSERT ON signer.client_certificate_revocations TO {lab.Role}"
        });
        await using var app = SigningHostApplication.Build(lab.Arguments());
        await Assert.ThrowsAsync<InvalidOperationException>(() => app.StartAsync());
    }

    [Theory]
    [InlineData("INSERT INTO signer.client_certificate_revocations (certificate_sha256) VALUES (repeat('A', 64))")]
    [InlineData("UPDATE signer.client_certificate_revocations SET incident_reference = 'changed'")]
    [InlineData("DELETE FROM signer.client_certificate_revocations")]
    [InlineData("TRUNCATE signer.client_certificate_revocations")]
    public async Task Signer_runtime_cannot_change_revocations(string sql)
    {
        await using var lab = await HostLab.CreateAsync(fixture);
        var error = await Assert.ThrowsAsync<PostgresException>(() => lab.ExecuteRuntimeAsync(sql));
        Assert.Equal(PostgresErrorCodes.InsufficientPrivilege, error.SqlState);
    }

    [Theory]
    [InlineData("fingerprint")]
    [InlineData("evidence")]
    [InlineData("incident")]
    [InlineData("operator")]
    [InlineData("approver")]
    [InlineData("same-actor")]
    [InlineData("oversized")]
    [InlineData("control")]
    public async Task Operator_procedure_rejects_invalid_evidence_without_revoking(string invalid)
    {
        await using var lab = await HostLab.CreateAsync(fixture);
        var error = await Assert.ThrowsAsync<PostgresException>(() => lab.RevokeAsync(invalid));
        Assert.Equal(PostgresErrorCodes.RaiseException, error.SqlState);
        await using var source = NpgsqlDataSource.Create(fixture.ConnectionString);
        await new PostgreSqlSigningClientRevocations(source).EnsureNotRevokedAsync(
            lab.Pki.Client.GetCertHashString(HashAlgorithmName.SHA256));
    }

    [Fact]
    public async Task Committed_revocation_survives_reopen_and_duplicate_evidence_cannot_replace_it()
    {
        await using var lab = await HostLab.CreateAsync(fixture);
        await lab.RevokeAsync();
        var conflict = await Assert.ThrowsAsync<PostgresException>(() => lab.RevokeAsync());
        Assert.Equal(PostgresErrorCodes.UniqueViolation, conflict.SqlState);
        await using var reopened = NpgsqlDataSource.Create(fixture.ConnectionString);
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => new PostgreSqlSigningClientRevocations(reopened)
            .EnsureNotRevokedAsync(lab.Pki.Client.GetCertHashString(HashAlgorithmName.SHA256).ToLowerInvariant()));
    }

    [Theory]
    [InlineData("database_operator", "'forged'")]
    [InlineData("event_id", "gen_random_uuid()")]
    [InlineData("revoked_at", "clock_timestamp() - interval '1 year'")]
    public async Task Operator_cannot_override_database_audit_metadata(string column, string expression)
    {
        await using var lab = await HostLab.CreateAsync(fixture);
        await lab.RevokeAsync();
        // Both SQL fragments are fixed test cases, never operator/request input.
        var error = await Assert.ThrowsAsync<PostgresException>(() => lab.ExecuteOperatorAsync($"""
            INSERT INTO signer.client_certificate_revocations
                (certificate_sha256, incident_reference, operator_reference, approver_reference, evidence_sha256, {column})
            VALUES (repeat('B', 64), 'INC-test', 'operator', 'approver', repeat('A', 64), {expression});
            """));
        Assert.Equal(PostgresErrorCodes.InsufficientPrivilege, error.SqlState);
    }

    [Theory]
    [InlineData("")]
    [InlineData("invalid")]
    public async Task Revocation_reader_rejects_malformed_fingerprints(string fingerprint)
    {
        await using var source = NpgsqlDataSource.Create(fixture.ConnectionString);
        await Assert.ThrowsAsync<ArgumentException>(() =>
            new PostgreSqlSigningClientRevocations(source).EnsureNotRevokedAsync(fingerprint));
    }
}
