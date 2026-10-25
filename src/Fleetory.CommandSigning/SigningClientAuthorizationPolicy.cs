using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Fleetory.Core.Contracts;

namespace Fleetory.CommandSigning;

public sealed record SigningClientGrant(
    string CallerId,
    string CertificateSha256,
    IReadOnlyCollection<DeviceId> AllowedDevices,
    DateTimeOffset NotBefore,
    DateTimeOffset ExpiresAt);

/// <summary>Authorizes a client certificate after the host has proved possession through mTLS.</summary>
public sealed class SigningClientAuthorizationPolicy : IDisposable
{
    private const string ClientAuthenticationOid = "1.3.6.1.5.5.7.3.2";
    private readonly X509Certificate2Collection _roots = [];
    private readonly X509Certificate2Collection _intermediates = [];
    private readonly Dictionary<string, GrantSnapshot> _grants = new(StringComparer.OrdinalIgnoreCase);
    private readonly TimeProvider _time;
    private bool _disposed;

    public SigningClientAuthorizationPolicy(
        IReadOnlyCollection<X509Certificate2> roots,
        IReadOnlyCollection<X509Certificate2> intermediates,
        IReadOnlyCollection<SigningClientGrant> grants,
        TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(roots);
        ArgumentNullException.ThrowIfNull(intermediates);
        ArgumentNullException.ThrowIfNull(grants);
        if (roots.Count is < 1 or > 2 || intermediates.Count > 3 || grants.Count is < 1 or > 64)
        {
            throw new ArgumentException("Signing trust and caller grants must have bounded, nonempty roots and callers.");
        }
        _time = timeProvider ?? TimeProvider.System;
        try
        {
            CopyAuthorities(roots, _roots);
            CopyAuthorities(intermediates, _intermediates);
            foreach (var grant in grants)
            {
                AddGrant(grant);
            }
        }
        catch
        {
            Dispose();
            throw;
        }
    }

    /// <summary>Returns the configured caller identity, or null. No request-supplied identity is trusted.</summary>
    public string? GetAuthorizedInventoryRefreshCaller(X509Certificate2? certificate, DeviceId targetDeviceId)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (certificate is null || targetDeviceId.Value == Guid.Empty)
        {
            return null;
        }
        try
        {
            var fingerprint = certificate.GetCertHashString(HashAlgorithmName.SHA256);
            var now = _time.GetUtcNow();
            if (!_grants.TryGetValue(fingerprint, out var grant) ||
                now < grant.NotBefore || now >= grant.ExpiresAt || !grant.Devices.Contains(targetDeviceId) ||
                !HasClientPurpose(certificate))
            {
                return null;
            }

            return BuildTrustedChain(certificate, now) ? grant.CallerId : null;
        }
        catch (Exception exception) when (exception is CryptographicException or ArgumentException or InvalidOperationException)
        {
            return null;
        }
    }

    private static bool HasClientPurpose(X509Certificate2 certificate) =>
        X509EndEntityPolicy.HasDigitalSignatureUsage(certificate) &&
        certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>().SingleOrDefault()
            ?.EnhancedKeyUsages.Cast<Oid>().Any(oid => oid.Value == ClientAuthenticationOid) == true;

    private bool BuildTrustedChain(X509Certificate2 certificate, DateTimeOffset now)
    {
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.AddRange(_roots);
        chain.ChainPolicy.ExtraStore.AddRange(_intermediates);
        chain.ChainPolicy.DisableCertificateDownloads = true;
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
        chain.ChainPolicy.VerificationTime = now.UtcDateTime;
        chain.ChainPolicy.ApplicationPolicy.Add(new Oid(ClientAuthenticationOid));
        return chain.Build(certificate) && chain.ChainElements.Count is >= 2 and <= 5 &&
            _roots.Cast<X509Certificate2>().Any(root => root.RawData.AsSpan().SequenceEqual(
                chain.ChainElements[^1].Certificate.RawData));
    }

    public void Dispose()
    {
        foreach (var certificate in _roots) { certificate.Dispose(); }
        foreach (var certificate in _intermediates) { certificate.Dispose(); }
        _roots.Clear();
        _intermediates.Clear();
        _disposed = true;
    }

    private void AddGrant(SigningClientGrant grant)
    {
        ArgumentNullException.ThrowIfNull(grant);
        if (string.IsNullOrEmpty(grant.CallerId) || grant.CallerId.Length > 96 ||
            !grant.CallerId.All(character => character is >= 'a' and <= 'z' or >= '0' and <= '9' or '-' or '_') ||
            grant.CertificateSha256 is not { Length: 64 } || !grant.CertificateSha256.All(Uri.IsHexDigit) ||
            grant.AllowedDevices is null || grant.AllowedDevices.Count is < 1 or > 1024 ||
            grant.NotBefore.Offset != TimeSpan.Zero || grant.ExpiresAt.Offset != TimeSpan.Zero ||
            grant.ExpiresAt <= grant.NotBefore || grant.ExpiresAt - grant.NotBefore > TimeSpan.FromHours(24))
        {
            throw new ArgumentException("Signing caller grant is invalid.", nameof(grant));
        }
        var devices = grant.AllowedDevices.ToHashSet();
        if (devices.Count != grant.AllowedDevices.Count || devices.Any(device => device.Value == Guid.Empty) ||
            !_grants.TryAdd(grant.CertificateSha256, new GrantSnapshot(
                grant.CallerId, devices, grant.NotBefore, grant.ExpiresAt)))
        {
            throw new ArgumentException("Signing caller grant contains duplicate or invalid identities.", nameof(grant));
        }
    }

    private static void CopyAuthorities(IEnumerable<X509Certificate2> source, X509Certificate2Collection destination)
    {
        foreach (var certificate in source)
        {
            if (certificate is null ||
                certificate.Extensions.OfType<X509BasicConstraintsExtension>().SingleOrDefault()?.CertificateAuthority != true ||
                (certificate.Extensions.OfType<X509KeyUsageExtension>().SingleOrDefault()?.KeyUsages &
                    X509KeyUsageFlags.KeyCertSign) != X509KeyUsageFlags.KeyCertSign)
            {
                throw new ArgumentException("Signing trust must contain certificate authorities.", nameof(source));
            }
            destination.Add(X509CertificateLoader.LoadCertificate(certificate.RawData));
        }
    }

    private sealed record GrantSnapshot(
        string CallerId, HashSet<DeviceId> Devices, DateTimeOffset NotBefore, DateTimeOffset ExpiresAt);
}
