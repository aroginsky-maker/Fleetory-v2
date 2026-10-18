namespace Fleetory.Core.Persistence;

internal static class AgentCertificateFingerprint
{
    public static bool IsValid(string? value) =>
        value is { Length: 64 } &&
        value.All(character => character is >= '0' and <= '9' or >= 'A' and <= 'F');
}
