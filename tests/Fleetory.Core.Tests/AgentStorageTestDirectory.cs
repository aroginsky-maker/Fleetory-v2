using Fleetory.AgentTestSupport;

namespace Fleetory.Core.Tests;

internal static class AgentStorageTestDirectory
{
    public static string Create()
    {
        var directory = Path.Combine(Path.GetTempPath(), "fleetory-agent-replay-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        if (OperatingSystem.IsWindows())
        {
            WindowsAgentAclTestHelper.ProtectDirectory(directory);
        }
        else
        {
            File.SetUnixFileMode(directory,
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }
        return directory;
    }
}
