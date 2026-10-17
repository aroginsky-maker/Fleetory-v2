using System.Security.Cryptography.X509Certificates;
using Fleetory.Platform.Contracts;

namespace Fleetory.Core.Security;

public static class AdminCertificateIdentity
{
    private const string AdminUriPrefix = "urn:fleetory:admin:";

    public static bool TryReadActor(X509Certificate2 certificate, out ActorReference? actor)
    {
        actor = null;
        if (!CertificateSanIdentity.TryReadGuid(certificate, AdminUriPrefix, out var id))
        {
            return false;
        }

        actor = new ActorReference($"person:{id:N}", ActorKind.Person);
        return true;
    }
}
