using System.Diagnostics;
using System.Security.AccessControl;
using System.Security.Principal;
using Fleetory.AdminLogin;

namespace Fleetory.Server.Tests;

public sealed class AdminLoginFileTests
{
    private const string PublicProfile = "{\"schema\":\"fleetory.admin-login.v1\"}";

    [Fact]
    public void Reads_private_lowercase_json_and_certificate_files()
    {
        using var files = new OperatorFileFixture();
        var profile = files.Write("profile.json", PublicProfile);
        var certificate = files.Write("admin-server-root.crt", "PUBLIC TEST CERTIFICATE");

        Assert.Equal(PublicProfile, OperatorFiles.Read(profile));
        Assert.Equal("PUBLIC TEST CERTIFICATE", OperatorFiles.Read(certificate));
    }

    [Fact]
    public void Rejects_relative_paths()
    {
        using var files = new OperatorFileFixture();
        files.Write("profile.json", PublicProfile);

        Assert.Throws<InvalidOperationException>(() => OperatorFiles.Read("profile.json"));
    }

    [Fact]
    public void Rejects_files_larger_than_the_secret_provider_limit()
    {
        using var files = new OperatorFileFixture();
        var path = files.Write("profile.json", new string('x', 16 * 1024 + 1));

        Assert.Throws<InvalidOperationException>(() => OperatorFiles.Read(path));
    }

    [Fact]
    public void Rejects_malformed_utf8_without_echoing_file_content()
    {
        using var files = new OperatorFileFixture();
        var path = files.WriteBytes("profile.json", [0xff]);

        var exception = Assert.Throws<InvalidOperationException>(() => OperatorFiles.Read(path));

        Assert.DoesNotContain("\ufffd", exception.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void Rejects_a_linked_material_directory()
    {
        using var files = new OperatorFileFixture();
        var target = files.CreateDirectory("target");
        OperatorFileFixture.WriteIn(target, "profile.json", PublicProfile);
        var linked = files.CreateDirectoryLink("linked", target);

        Assert.Throws<InvalidOperationException>(() =>
            OperatorFiles.Read(Path.Combine(linked, "profile.json")));
    }

    [Fact]
    public void Rejects_broad_file_permissions()
    {
        using var files = new OperatorFileFixture();
        var path = files.Write("profile.json", PublicProfile);
        OperatorFileFixture.MakeFileReadableByOthers(path);

        Assert.Throws<InvalidOperationException>(() => OperatorFiles.Read(path));
    }

    [Fact]
    public void Rejects_broad_parent_permissions()
    {
        using var files = new OperatorFileFixture();
        var path = files.Write("profile.json", PublicProfile);
        files.MakeParentWritableByOthers();

        Assert.Throws<InvalidOperationException>(() => OperatorFiles.Read(path));
    }

    private sealed class OperatorFileFixture : IDisposable
    {
        private readonly string _root = Path.Combine(Path.GetTempPath(),
            "fleetory-admin-login-files-" + Guid.NewGuid().ToString("N"));
        private readonly string _directory;

        public OperatorFileFixture()
        {
            Directory.CreateDirectory(_root);
            _directory = Path.Combine(_root, "private");
            Directory.CreateDirectory(_directory);
            SetPrivateDirectory(_directory);
        }

        public string Write(string name, string contents) =>
            WriteIn(_directory, name, contents);

        public static string WriteIn(string directory, string name, string contents)
        {
            var path = Path.Combine(directory, name);
            File.WriteAllText(path, contents, new System.Text.UTF8Encoding(false));
            SetPrivateFile(path);
            return path;
        }

        public string WriteBytes(string name, byte[] contents)
        {
            var path = Path.Combine(_directory, name);
            File.WriteAllBytes(path, contents);
            SetPrivateFile(path);
            return path;
        }

        public string CreateDirectory(string name)
        {
            var path = Path.Combine(_root, name);
            Directory.CreateDirectory(path);
            SetPrivateDirectory(path);
            return path;
        }

        public string CreateDirectoryLink(string name, string target)
        {
            var link = Path.Combine(_root, name);
            if (OperatingSystem.IsWindows())
            {
                var start = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "cmd.exe"))
                {
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };
                foreach (var argument in new[] { "/d", "/c", "mklink", "/J", link, target })
                {
                    start.ArgumentList.Add(argument);
                }

                using var process = Process.Start(start) ??
                    throw new InvalidOperationException("Could not create the isolated directory junction.");
                using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                process.WaitForExitAsync(deadline.Token).GetAwaiter().GetResult();
                if (process.ExitCode != 0)
                {
                    throw new InvalidOperationException("Could not create the isolated directory junction.");
                }
            }
            else
            {
                Directory.CreateSymbolicLink(link, target);
            }

            Assert.NotEqual((FileAttributes)0, File.GetAttributes(link) & FileAttributes.ReparsePoint);
            return link;
        }

        public static void MakeFileReadableByOthers(string path)
        {
            if (OperatingSystem.IsWindows())
            {
                var security = new FileInfo(path).GetAccessControl();
                security.AddAccessRule(new FileSystemAccessRule(
                    new SecurityIdentifier("S-1-1-0"), FileSystemRights.Read,
                    AccessControlType.Allow));
                new FileInfo(path).SetAccessControl(security);
            }
            else
            {
                File.SetUnixFileMode(path,
                    File.GetUnixFileMode(path) | UnixFileMode.GroupRead);
            }
        }

        public void MakeParentWritableByOthers()
        {
            if (OperatingSystem.IsWindows())
            {
                var security = new DirectoryInfo(_directory).GetAccessControl();
                security.AddAccessRule(new FileSystemAccessRule(
                    new SecurityIdentifier("S-1-1-0"), FileSystemRights.Write,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                    PropagationFlags.None, AccessControlType.Allow));
                new DirectoryInfo(_directory).SetAccessControl(security);
            }
            else
            {
                File.SetUnixFileMode(_directory,
                    File.GetUnixFileMode(_directory) | UnixFileMode.GroupWrite);
            }
        }

        private static void SetPrivateDirectory(string path)
        {
            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(path,
                    UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
                return;
            }

            var security = new DirectoryInfo(path).GetAccessControl();
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            security.SetOwner(WindowsIdentity.GetCurrent().User!);
            security.SetAccessRule(new FileSystemAccessRule(
                WindowsIdentity.GetCurrent().User!, FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None, AccessControlType.Allow));
            security.AddAccessRule(new FileSystemAccessRule(
                new SecurityIdentifier("S-1-5-18"), FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None, AccessControlType.Allow));
            security.AddAccessRule(new FileSystemAccessRule(
                new SecurityIdentifier("S-1-5-32-544"), FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None, AccessControlType.Allow));
            new DirectoryInfo(path).SetAccessControl(security);
        }

        private static void SetPrivateFile(string path)
        {
            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
                return;
            }

            var security = new FileInfo(path).GetAccessControl();
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            security.SetOwner(WindowsIdentity.GetCurrent().User!);
            security.SetAccessRule(new FileSystemAccessRule(
                WindowsIdentity.GetCurrent().User!, FileSystemRights.FullControl,
                AccessControlType.Allow));
            security.AddAccessRule(new FileSystemAccessRule(
                new SecurityIdentifier("S-1-5-18"), FileSystemRights.FullControl,
                AccessControlType.Allow));
            security.AddAccessRule(new FileSystemAccessRule(
                new SecurityIdentifier("S-1-5-32-544"), FileSystemRights.FullControl,
                AccessControlType.Allow));
            new FileInfo(path).SetAccessControl(security);
        }

        public void Dispose()
        {
            var fullRoot = Path.GetFullPath(_root);
            var tempRoot = Path.GetFullPath(Path.GetTempPath());
            if (!fullRoot.StartsWith(tempRoot, StringComparison.OrdinalIgnoreCase) ||
                Path.GetFileName(fullRoot) is not { } name ||
                !name.StartsWith("fleetory-admin-login-files-", StringComparison.Ordinal))
            {
                throw new InvalidOperationException("Refusing to clean an unexpected test directory.");
            }

            if (Directory.Exists(_root))
            {
                foreach (var entry in Directory.EnumerateFileSystemEntries(_root))
                {
                    var attributes = File.GetAttributes(entry);
                    if ((attributes & FileAttributes.ReparsePoint) != 0)
                    {
                        if ((attributes & FileAttributes.Directory) != 0) Directory.Delete(entry);
                        else File.Delete(entry);
                    }
                    else if ((attributes & FileAttributes.Directory) != 0)
                    {
                        foreach (var file in Directory.EnumerateFiles(entry)) File.Delete(file);
                        Directory.Delete(entry);
                    }
                    else File.Delete(entry);
                }

                Directory.Delete(_root);
            }
        }
    }
}
