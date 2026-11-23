using Fleetory.Core.Contracts;
using Microsoft.EntityFrameworkCore;

namespace Fleetory.Core.Persistence;

internal static class CoreDeviceRowLock
{
    public static async ValueTask<bool> TryLockAsync(
        CoreDbContext database, DeviceId deviceId,
        CancellationToken cancellationToken)
    {
        var device = await database.Devices.FromSqlInterpolated(
                $"SELECT * FROM core.devices WHERE device_id = {deviceId.Value} FOR UPDATE")
            .AsNoTracking().SingleOrDefaultAsync(cancellationToken);
        return device is not null;
    }
}
