using System.Security.Cryptography.X509Certificates;
using Fleetory.Platform.Contracts;
using Fleetory.Core.Contracts;

namespace Fleetory.Core.Security;

public static class AgentCertificateIdentity
{
    private const string DeviceUriPrefix = "urn:fleetory:device:";

    public static bool TryReadDeviceId(X509Certificate2 certificate, out DeviceId deviceId)
    {
        deviceId = default;
        if (!CertificateSanIdentity.TryReadGuid(certificate, DeviceUriPrefix, out var id))
        {
            return false;
        }

        deviceId = new DeviceId(id);
        return true;
    }
}
