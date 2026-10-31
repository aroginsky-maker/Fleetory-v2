using Fleetory.Core.Contracts;
using Microsoft.EntityFrameworkCore;

namespace Fleetory.Core.Persistence;

internal sealed class PostgreSqlAgentCertificateBindingStore(CoreDbContext database)
    : IAgentCertificateBindingStore
{
    public async ValueTask<AgentCertificateBinding?> FindBySha256Async(
        string certificateSha256,
        CancellationToken cancellationToken = default)
    {
        var record = await database.AgentCertificates
            .AsNoTracking()
            .SingleOrDefaultAsync(row => row.CertificateSha256 == certificateSha256, cancellationToken);

        return record is null ? null : new AgentCertificateBinding(
            record.DeviceId,
            record.CertificateSha256,
            record.NotBefore,
            record.NotAfter,
            record.RevokedAt);
    }
}
