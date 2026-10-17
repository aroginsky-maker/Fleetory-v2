using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;
using Fleetory.Core.Contracts;

namespace Fleetory.Server.Infrastructure;

internal static class AgentGatewayIdentity
{
    private const string DeviceUriPrefix = "urn:fleetory:device:";

    public static bool TryReadDeviceId(X509Certificate2 certificate, out DeviceId deviceId)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        deviceId = default;

        try
        {
            var san = certificate.Extensions
                .Cast<X509Extension>()
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
                if (!uri.StartsWith(DeviceUriPrefix, StringComparison.Ordinal))
                {
                    continue;
                }

                if (found ||
                    !Guid.TryParseExact(uri.AsSpan(DeviceUriPrefix.Length), "D", out var parsed) ||
                    parsed == Guid.Empty)
                {
                    return false;
                }

                deviceId = new DeviceId(parsed);
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
