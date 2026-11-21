using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

namespace Fleetory.AgentTestSupport;

[SupportedOSPlatform("windows")]
internal static class WindowsAgentAclTestHelper
{
    public static void ProtectDirectory(string path)
    {
        var directory = new DirectoryInfo(path);
        var security = directory.GetAccessControl();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        foreach (FileSystemAccessRule rule in security.GetAccessRules(
                     includeExplicit: true, includeInherited: false, typeof(SecurityIdentifier)))
        {
            security.RemoveAccessRuleSpecific(rule);
        }

        var user = WindowsIdentity.GetCurrent().User!;
        security.AddAccessRule(new FileSystemAccessRule(user, FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None, AccessControlType.Allow));
        directory.SetAccessControl(security);
    }

    public static void GrantEveryoneWrite(string path, bool directory)
    {
        var everyone = new SecurityIdentifier(WellKnownSidType.WorldSid, null);
        if (directory)
        {
            var info = new DirectoryInfo(path);
            var security = info.GetAccessControl();
            security.AddAccessRule(new FileSystemAccessRule(everyone,
                FileSystemRights.Write, AccessControlType.Allow));
            info.SetAccessControl(security);
        }
        else
        {
            var info = new FileInfo(path);
            var security = info.GetAccessControl();
            security.AddAccessRule(new FileSystemAccessRule(everyone,
                FileSystemRights.Write, AccessControlType.Allow));
            info.SetAccessControl(security);
        }
    }
}
