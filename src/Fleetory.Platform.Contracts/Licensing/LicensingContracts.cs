namespace Fleetory.Platform.Contracts;

public enum LicenseRuntimeState
{
    Unknown = 0,
    Valid = 1,
    Grace = 2,
    Restricted = 3
}

public sealed record LicenseSnapshot(
    LicenseRuntimeState State,
    IReadOnlyCollection<string> Entitlements);

public interface ILicenseStateProvider
{
    ValueTask<LicenseSnapshot> GetCurrentAsync(
        CancellationToken cancellationToken = default);
}
