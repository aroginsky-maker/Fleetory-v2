using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;

namespace Fleetory.Platform.Contracts;

public static class CertificateSanIdentity
{
    public static bool TryReadGuid(X509Certificate2 certificate, string uriPrefix, out Guid identity)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        identity = default;

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
                if (!uri.StartsWith(uriPrefix, StringComparison.Ordinal))
                {
                    continue;
                }

                if (found ||
                    !Guid.TryParseExact(uri.AsSpan(uriPrefix.Length), "D", out var parsed) ||
                    parsed == Guid.Empty)
                {
                    return false;
                }

                identity = parsed;
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
