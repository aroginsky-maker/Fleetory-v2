using System.Security.AccessControl;
using System.Security.Principal;
using Fleetory.Security.Infrastructure;
namespace Fleetory.AdminLogin;

public static class OperatorFiles
{
    public static string Read(string path)
    {
        if (!Path.IsPathFullyQualified(path)) throw new InvalidOperationException("Invalid operator file.");
        var full = Path.GetFullPath(path);
        var parent = Path.GetDirectoryName(full)!;
        foreach (var item in new[] { full, parent })
        {
            if ((File.GetAttributes(item) & FileAttributes.ReparsePoint) != 0)
                throw new InvalidOperationException("Linked operator material is not supported.");
            if (OperatingSystem.IsWindows())
            {
                var allowed = new HashSet<string>(StringComparer.Ordinal)
                {
                    WindowsIdentity.GetCurrent().User!.Value, "S-1-5-18", "S-1-5-32-544"
                };
                FileSystemSecurity security = Directory.Exists(item)
                    ? new DirectoryInfo(item).GetAccessControl() : new FileInfo(item).GetAccessControl();
                foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
                    if (rule.AccessControlType == AccessControlType.Allow && !allowed.Contains(rule.IdentityReference.Value))
                        throw new InvalidOperationException("Operator material permissions are too broad.");
            }
            else if ((File.GetUnixFileMode(item) & (Directory.Exists(item)
                ? UnixFileMode.GroupWrite | UnixFileMode.OtherWrite
                : UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute |
                  UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute)) != 0)
                throw new InvalidOperationException("Operator material permissions are too broad.");
        }
        return new FileSecretProvider(parent).GetRequiredSecret(Path.GetFileName(full));
    }
}
