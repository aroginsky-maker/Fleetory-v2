using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;
using Fleetory.Platform.Contracts;

namespace Fleetory.Core.Security;

internal static class AdminCertificateIdentity
{
    private const string AdminUriPrefix = "urn:fleetory:admin:";

    public static bool TryReadActor(X509Certificate2 certificate, out ActorReference? actor)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        actor = null;

        try
        {
            var san = certificate.Extensions.Cast<X509Extension>()
                .SingleOrDefault(extension => extension.Oid?.Value == "2.5.29.17");
            if (san is null)
            {
                return false;
            }

            var reader = new AsnReader(san.RawData, AsnEncodingRules.DER);
            var names = reader.ReadSequence();
            var found = false;
            while (names.HasData)
            {
                var tag = names.PeekTag();
                if (tag.TagClass != TagClass.ContextSpecific || tag.TagValue != 6)
                {
                    names.ReadEncodedValue();
                    continue;
                }

                var uri = names.ReadCharacterString(
                    UniversalTagNumber.IA5String, new Asn1Tag(TagClass.ContextSpecific, 6));
                if (!uri.StartsWith(AdminUriPrefix, StringComparison.Ordinal))
                {
                    continue;
                }

                if (found ||
                    !Guid.TryParseExact(uri.AsSpan(AdminUriPrefix.Length), "D", out var id) ||
                    id == Guid.Empty)
                {
                    return false;
                }

                actor = new ActorReference($"person:{id:N}", ActorKind.Person);
                found = true;
            }

            reader.ThrowIfNotEmpty();
            return found;
        }
        catch (Exception exception) when (exception is AsnContentException or InvalidOperationException)
        {
            return false;
        }
    }
}
