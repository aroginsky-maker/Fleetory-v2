using System.Text.RegularExpressions;
using System.Xml.Linq;

namespace Fleetory.Architecture.Tests;

public sealed class ArchitectureBoundaryTests
{
    private static readonly string[] ImplementationProjects =
    [
        "Fleetory.Platform",
        "Fleetory.Core",
        "Fleetory.Assets",
        "Fleetory.ITSM",
        "Fleetory.CMDB",
        "Fleetory.Monitoring",
        "Fleetory.Integrations"
    ];

    private static readonly string[] ContractProjects =
    [
        "Fleetory.Platform.Contracts",
        "Fleetory.Core.Contracts",
        "Fleetory.Assets.Contracts",
        "Fleetory.ITSM.Contracts",
        "Fleetory.CMDB.Contracts",
        "Fleetory.Monitoring.Contracts",
        "Fleetory.Integrations.Contracts"
    ];

    private static readonly string[] OsNeutralServerSideProjects =
    [
        "Fleetory.Server",
        "Fleetory.Platform",
        "Fleetory.Platform.Contracts",
        "Fleetory.Core",
        "Fleetory.Core.Contracts",
        "Fleetory.Assets",
        "Fleetory.Assets.Contracts",
        "Fleetory.ITSM",
        "Fleetory.ITSM.Contracts",
        "Fleetory.CMDB",
        "Fleetory.CMDB.Contracts",
        "Fleetory.Monitoring",
        "Fleetory.Monitoring.Contracts",
        "Fleetory.Integrations",
        "Fleetory.Integrations.Contracts",
        "Fleetory.ModuleAbstractions",
        "Fleetory.SharedKernel"
    ];

    [Fact]
    public void Bounded_context_implementations_must_not_reference_other_implementation_projects()
    {
        var root = FindSolutionRoot();
        var implementations = ImplementationProjects.ToHashSet(StringComparer.OrdinalIgnoreCase);

        foreach (var projectName in ImplementationProjects)
        {
            var references = GetProjectReferences(ProjectPath(root, projectName));
            Assert.DoesNotContain(references, implementations.Contains);
        }
    }

    [Fact]
    public void Contracts_projects_must_not_reference_bounded_context_implementations()
    {
        var root = FindSolutionRoot();
        var implementations = ImplementationProjects.ToHashSet(StringComparer.OrdinalIgnoreCase);

        foreach (var contractName in ContractProjects)
        {
            var references = GetProjectReferences(ProjectPath(root, contractName));
            Assert.DoesNotContain(references, implementations.Contains);
        }
    }

    [Fact]
    public void Contracts_projects_must_not_reference_other_bounded_context_contracts()
    {
        var root = FindSolutionRoot();
        var contracts = ContractProjects.ToHashSet(StringComparer.OrdinalIgnoreCase);

        foreach (var contractName in ContractProjects)
        {
            var references = GetProjectReferences(ProjectPath(root, contractName));

            Assert.DoesNotContain(
                references,
                reference => contracts.Contains(reference) &&
                    !reference.Equals(contractName, StringComparison.OrdinalIgnoreCase));

            AssertProjectReferencesEqual(
                contractName,
                new[] { "Fleetory.SharedKernel" },
                references);
        }
    }

    [Fact]
    public void SharedKernel_must_not_reference_other_projects_or_define_domain_entities()
    {
        var root = FindSolutionRoot();
        var projectPath = ProjectPath(root, "Fleetory.SharedKernel");

        Assert.Empty(GetProjectReferences(projectPath));

        var forbiddenDomainTypes = new HashSet<string>(StringComparer.Ordinal)
        {
            "Device", "Asset", "Ticket", "CI", "Alert", "Person", "Service"
        };

        var typeDeclarationPattern = new Regex(
            @"\b(?:class|record|struct|interface|enum)\s+(?<name>[A-Za-z_][A-Za-z0-9_]*)\b",
            RegexOptions.Compiled | RegexOptions.CultureInvariant);

        foreach (var sourceFile in projectPath.Directory!.EnumerateFiles("*.cs", SearchOption.AllDirectories))
        {
            var source = File.ReadAllText(sourceFile.FullName);
            foreach (Match match in typeDeclarationPattern.Matches(source))
            {
                Assert.DoesNotContain(match.Groups["name"].Value, forbiddenDomainTypes);
            }
        }
    }

    [Fact]
    public void Module_implementation_dependencies_must_match_the_phase2_dependency_policy()
    {
        var root = FindSolutionRoot();

        foreach (var projectName in ImplementationProjects)
        {
            var references = GetProjectReferences(ProjectPath(root, projectName));
            var expected = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                $"{projectName}.Contracts",
                "Fleetory.ModuleAbstractions"
            };

            if (!projectName.Equals("Fleetory.Platform", StringComparison.OrdinalIgnoreCase))
            {
                expected.Add("Fleetory.Platform.Contracts");
            }

            AssertProjectReferencesEqual(projectName, expected, references);
        }
    }

    [Fact]
    public void Server_must_be_the_only_composition_root_and_reference_exactly_the_approved_modules()
    {
        var root = FindSolutionRoot();
        var references = GetProjectReferences(ProjectPath(root, "Fleetory.Server"));
        var expected = new HashSet<string>(ImplementationProjects, StringComparer.OrdinalIgnoreCase)
        {
            "Fleetory.ModuleAbstractions"
        };

        AssertProjectReferencesEqual("Fleetory.Server", expected, references);

        foreach (var projectName in ImplementationProjects.Concat(ContractProjects).Append("Fleetory.SharedKernel").Append("Fleetory.ModuleAbstractions"))
        {
            var projectReferences = GetProjectReferences(ProjectPath(root, projectName));
            Assert.DoesNotContain(
                projectReferences,
                reference => reference.Equals("Fleetory.Server", StringComparison.OrdinalIgnoreCase));
        }
    }

    [Fact]
    public void ModuleAbstractions_must_remain_free_of_bounded_context_project_dependencies()
    {
        var root = FindSolutionRoot();
        Assert.Empty(GetProjectReferences(ProjectPath(root, "Fleetory.ModuleAbstractions")));
    }

    [Fact]
    public void Server_side_runtime_must_remain_os_neutral()
    {
        var root = FindSolutionRoot();
        var forbiddenSourceTokens = new[]
        {
            "Microsoft.Win32",
            "System.Management",
            "System.ServiceProcess",
            "WindowsIdentity",
            "WindowsPrincipal",
            "WindowsBuiltInRole",
            "OperatingSystem.IsWindows()",
            "OSPlatform.Windows"
        };
        var forbiddenProjectTokens = new[]
        {
            "-windows",
            "win-x64",
            "win-x86",
            "win-arm64",
            "Microsoft.Extensions.Hosting.WindowsServices",
            "System.Management",
            "System.ServiceProcess.ServiceController",
            "System.Security.Principal.Windows",
            "Microsoft.Win32.Registry"
        };

        foreach (var projectName in OsNeutralServerSideProjects)
        {
            var projectPath = ProjectPath(root, projectName);
            var projectText = File.ReadAllText(projectPath.FullName);

            foreach (var token in forbiddenProjectTokens)
            {
                Assert.DoesNotContain(token, projectText, StringComparison.OrdinalIgnoreCase);
            }

            foreach (var sourceFile in projectPath.Directory!.EnumerateFiles("*.cs", SearchOption.AllDirectories))
            {
                var source = File.ReadAllText(sourceFile.FullName);
                foreach (var token in forbiddenSourceTokens)
                {
                    Assert.DoesNotContain(token, source, StringComparison.Ordinal);
                }
            }
        }
    }

    [Fact]
    public void Module_registration_must_own_service_and_endpoint_registration()
    {
        var root = FindSolutionRoot();
        var abstractionSource = File.ReadAllText(
            Path.Combine(root.FullName, "src", "Fleetory.ModuleAbstractions", "IFleetoryModule.cs"));
        var applicationSource = File.ReadAllText(
            Path.Combine(root.FullName, "src", "Fleetory.Server", "FleetoryApplication.cs"));

        Assert.Contains("void RegisterServices(IServiceCollection services, IConfiguration configuration);", abstractionSource, StringComparison.Ordinal);
        Assert.Contains("void MapEndpoints(IEndpointRouteBuilder endpoints);", abstractionSource, StringComparison.Ordinal);
        Assert.Contains("module.RegisterServices(builder.Services, builder.Configuration);", applicationSource, StringComparison.Ordinal);
        Assert.Contains("module.MapEndpoints(app);", applicationSource, StringComparison.Ordinal);

        var moduleEndpointPattern = new Regex(
            @"\.\s*Map(?:Get|Post|Put|Patch|Delete|Methods|Group)\s*\(",
            RegexOptions.Compiled | RegexOptions.CultureInvariant);

        var serverDirectory = new DirectoryInfo(Path.Combine(root.FullName, "src", "Fleetory.Server"));
        foreach (var sourceFile in serverDirectory.EnumerateFiles("*.cs", SearchOption.AllDirectories))
        {
            var source = File.ReadAllText(sourceFile.FullName);
            Assert.False(
                moduleEndpointPattern.IsMatch(source),
                $"Fleetory.Server must not own module-specific endpoint mappings. Found mapping in '{sourceFile.FullName}'.");
        }
    }

    private static FileInfo ProjectPath(DirectoryInfo root, string projectName) =>
        new(Path.Combine(root.FullName, "src", projectName, $"{projectName}.csproj"));

    private static IReadOnlyList<string> GetProjectReferences(FileInfo projectPath)
    {
        var document = XDocument.Load(projectPath.FullName);
        var projectDirectory = projectPath.Directory!;

        return document
            .Descendants()
            .Where(element => element.Name.LocalName == "ProjectReference")
            .Select(element => element.Attribute("Include")?.Value)
            .Where(include => !string.IsNullOrWhiteSpace(include))
            .Select(include => Path.GetFullPath(Path.Combine(projectDirectory.FullName, include!)))
            .Select(path =>
                Path.GetFileNameWithoutExtension(path)
                ?? throw new InvalidOperationException(
                    $"Cannot resolve project name from '{path}'."))
            .ToArray();
    }

    private static void AssertProjectReferencesEqual(
        string projectName,
        IEnumerable<string> expectedReferences,
        IEnumerable<string> actualReferences)
    {
        var expected = expectedReferences
            .OrderBy(reference => reference, StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var actual = actualReferences
            .OrderBy(reference => reference, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        Assert.True(
            expected.SequenceEqual(actual, StringComparer.OrdinalIgnoreCase),
            $"Project '{projectName}' references [{string.Join(", ", actual)}], expected [{string.Join(", ", expected)}].");
    }

    private static DirectoryInfo FindSolutionRoot()
    {
        DirectoryInfo? current = new(AppContext.BaseDirectory);

        while (current is not null)
        {
            if (File.Exists(Path.Combine(current.FullName, "Fleetory.sln")))
            {
                return current;
            }

            current = current.Parent;
        }

        throw new DirectoryNotFoundException("Could not locate Fleetory.sln from the test output directory.");
    }
}
