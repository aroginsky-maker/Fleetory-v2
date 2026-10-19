using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

namespace Fleetory.Agent.Security;

/// <summary>Rejects Agent state that can be changed by another Windows principal.</summary>
internal static class WindowsAgentStorageAcl
{
    [SupportedOSPlatform("windows")]
    public static void ValidateDirectory(string path, string description)
    {
        var security = new DirectoryInfo(path).GetAccessControl(
            AccessControlSections.Access | AccessControlSections.Owner);
        if (!security.AreAccessRulesProtected)
        {
            throw new InvalidOperationException($"{description} must have a protected Windows ACL.");
        }

        ValidateRules(security, description);
    }

    [SupportedOSPlatform("windows")]
    public static void ValidateFile(string path, string description)
    {
        var security = new FileInfo(path).GetAccessControl(
            AccessControlSections.Access | AccessControlSections.Owner);
        ValidateRules(security, description);
    }

    [SupportedOSPlatform("windows")]
    private static void ValidateRules(FileSystemSecurity security, string description)
    {
        var currentUser = WindowsIdentity.GetCurrent().User ??
            throw new InvalidOperationException("Agent process identity is unavailable.");
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);

        static bool IsTrusted(SecurityIdentifier sid, SecurityIdentifier user,
            SecurityIdentifier systemSid, SecurityIdentifier administratorsSid) =>
            sid.Equals(user) || sid.Equals(systemSid) || sid.Equals(administratorsSid);

        var owner = security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier ??
            throw new InvalidOperationException($"{description} has no Windows owner.");
        if (!IsTrusted(owner, currentUser, system, administrators))
        {
            throw new InvalidOperationException($"{description} has an untrusted Windows owner.");
        }

        foreach (FileSystemAccessRule rule in security.GetAccessRules(
                     includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier)))
        {
            if (rule.AccessControlType == AccessControlType.Allow &&
                !IsTrusted((SecurityIdentifier)rule.IdentityReference,
                    currentUser, system, administrators))
            {
                throw new InvalidOperationException($"{description} grants access to another Windows principal.");
            }
        }
    }
}
