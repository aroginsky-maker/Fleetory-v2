using System.Text.RegularExpressions;
using System.Xml.Linq;

namespace Fleetory.Architecture.Tests;

public sealed partial class ArchitectureBoundaryTests
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

    private static readonly string[] SharedKernelOnly =
    [
        "Fleetory.SharedKernel"
    ];

    private static readonly string[] Phase4PlatformContractTypes =
    [
        "ModuleRegistration",
        "IModuleRegistry",
        "ActorKind",
        "ActorReference",
        "ICurrentActorAccessor",
        "AuthorizationRequest",
        "AuthorizationDecision",
        "IAuthorizationService",
        "AuditTarget",
        "AuditRecord",
        "IAuditWriter",
        "NotificationSeverity",
        "NotificationMessage",
        "INotificationPublisher",
        "LicenseRuntimeState",
        "LicenseSnapshot",
        "ILicenseStateProvider",
        "SearchRequest",
        "SearchResult",
        "ISearchProvider",
        "ISearchService"
    ];

    private static readonly string[] ForbiddenPrematureSecurityImplementationTokens =
    [
        "JwtBearer",
        "CookieAuthentication",
        "PasswordHasher",
        "LdapConnection",
        "OpenIdConnect",
        "X509Certificate2",
        "ISecretProvider"
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

    private static readonly Dictionary<string, IReadOnlyCollection<string>> AllowedCrossContextContractReferences =
        ContractProjects.ToDictionary(
            projectName => projectName,
            _ => (IReadOnlyCollection<string>)Array.Empty<string>(),
            StringComparer.OrdinalIgnoreCase);

    private static readonly Dictionary<string, (string ForbiddenNamespace, string[] ForeignSchemas)>
        Phase6ForeignPersistenceBoundaries = new(StringComparer.OrdinalIgnoreCase)
        {
            ["Fleetory.Platform"] = (
                "Fleetory.Core",
                ["core", "assets", "itsm", "cmdb", "monitoring", "integrations"]),
            ["Fleetory.Core"] = (
                "Fleetory.Platform",
                ["platform", "assets", "itsm", "cmdb", "monitoring", "integrations"])
        };

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
                SharedKernelOnly,
                references);
        }
    }

    [Fact]
    public void Cross_context_contract_dependencies_must_match_the_documented_phase3_allowlist()
    {
        var root = FindSolutionRoot();
        var contracts = ContractProjects.ToHashSet(StringComparer.OrdinalIgnoreCase);

        foreach (var contractName in ContractProjects)
        {
            var actual = GetProjectReferences(ProjectPath(root, contractName))
                .Where(reference =>
                    contracts.Contains(reference) &&
                    !reference.Equals(contractName, StringComparison.OrdinalIgnoreCase))
                .OrderBy(reference => reference, StringComparer.OrdinalIgnoreCase)
                .ToArray();

            var expected = AllowedCrossContextContractReferences[contractName]
                .OrderBy(reference => reference, StringComparer.OrdinalIgnoreCase)
                .ToArray();

            Assert.True(
                expected.SequenceEqual(actual, StringComparer.OrdinalIgnoreCase),
                $"Contract project '{contractName}' has undocumented cross-context references " +
                $"[{string.Join(", ", actual)}]; allowlist is [{string.Join(", ", expected)}].");
        }
    }

    [Fact]
    public void Fleetory_production_project_reference_graph_must_be_acyclic()
    {
        var root = FindSolutionRoot();
        var sourceRoot = new DirectoryInfo(Path.Combine(root.FullName, "src"));
        var projectNames = sourceRoot
            .EnumerateDirectories("Fleetory.*", SearchOption.TopDirectoryOnly)
            .Where(directory => File.Exists(Path.Combine(directory.FullName, $"{directory.Name}.csproj")))
            .Select(directory => directory.Name)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var graph = projectNames.ToDictionary(
            projectName => projectName,
            projectName => GetProjectReferences(ProjectPath(root, projectName))
                .Where(projectNames.Contains)
                .ToArray(),
            StringComparer.OrdinalIgnoreCase);

        var states = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var path = new List<string>();

        foreach (var projectName in projectNames)
        {
            Visit(projectName);
        }

        void Visit(string projectName)
        {
            if (states.TryGetValue(projectName, out var state))
            {
                Assert.True(
                    state != 1,
                    $"Project-reference cycle detected: {string.Join(" -> ", path.Append(projectName))}.");
                return;
            }

            states[projectName] = 1;
            path.Add(projectName);

            foreach (var reference in graph[projectName])
            {
                Visit(reference);
            }

            path.RemoveAt(path.Count - 1);
            states[projectName] = 2;
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
            "Device",
            "Asset",
            "Ticket",
            "CI",
            "ConfigurationItem",
            "Alert",
            "Observation",
            "Person",
            "Service",
            "PersonId",
            "ScopeId",
            "DeviceId",
            "AssetId",
            "TicketId",
            "ConfigurationItemId",
            "ObservationId",
            "EventId",
            "AlertId",
            "ConnectorId",
            "PersonSummary",
            "ScopeSummary",
            "DeviceSummary",
            "AssetSummary",
            "TicketSummary",
            "ConfigurationItemSummary",
            "AlertSummary",
            "ModuleRegistration",
            "ActorReference",
            "AuthorizationRequest",
            "AuthorizationDecision",
            "AuditRecord",
            "NotificationMessage",
            "LicenseSnapshot",
            "SearchRequest",
            "SearchResult",
            "GenericEntityId"
        };

        foreach (var sourceFile in projectPath.Directory!.EnumerateFiles("*.cs", SearchOption.AllDirectories))
        {
            var declaredTypes = GetDeclaredTypeNames(sourceFile);
            Assert.DoesNotContain(declaredTypes, forbiddenDomainTypes.Contains);
        }
    }

    [Fact]
    public void Phase3_public_contract_types_must_live_in_their_owning_contract_projects()
    {
        var root = FindSolutionRoot();
        var expectedTypes = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
        {
            ["Fleetory.Platform.Contracts"] = ["PersonId", "ScopeId", "PersonSummary", "ScopeSummary"],
            ["Fleetory.Core.Contracts"] = ["DeviceId", "DeviceSummary"],
            ["Fleetory.Assets.Contracts"] = ["AssetId", "AssetSummary"],
            ["Fleetory.ITSM.Contracts"] = ["TicketId", "TicketSummary"],
            ["Fleetory.CMDB.Contracts"] = ["ConfigurationItemId", "ConfigurationItemSummary"],
            ["Fleetory.Monitoring.Contracts"] = ["ObservationId", "EventId", "AlertId", "AlertSummary"],
            ["Fleetory.Integrations.Contracts"] = ["ConnectorId"]
        };

        foreach (var (ownerProject, requiredTypes) in expectedTypes)
        {
            var ownerTypes = GetDeclaredTypeNames(ProjectPath(root, ownerProject).Directory!);

            foreach (var requiredType in requiredTypes)
            {
                Assert.Contains(requiredType, ownerTypes);

                foreach (var otherProject in ContractProjects.Where(project =>
                             !project.Equals(ownerProject, StringComparison.OrdinalIgnoreCase)))
                {
                    var otherTypes = GetDeclaredTypeNames(ProjectPath(root, otherProject).Directory!);
                    Assert.DoesNotContain(requiredType, otherTypes);
                }
            }
        }
    }

    [Fact]
    public void Phase4_platform_foundation_contracts_must_remain_owned_by_platform_contracts()
    {
        var root = FindSolutionRoot();
        var platformTypes = GetDeclaredTypeNames(
            ProjectPath(root, "Fleetory.Platform.Contracts").Directory!);

        foreach (var requiredType in Phase4PlatformContractTypes)
        {
            Assert.Contains(requiredType, platformTypes);

            foreach (var otherProject in ContractProjects.Where(project =>
                         !project.Equals("Fleetory.Platform.Contracts", StringComparison.OrdinalIgnoreCase)))
            {
                var otherTypes = GetDeclaredTypeNames(ProjectPath(root, otherProject).Directory!);
                Assert.DoesNotContain(requiredType, otherTypes);
            }
        }
    }

    [Fact]
    public void Platform_implementation_must_not_introduce_premature_security_implementation()
    {
        var root = FindSolutionRoot();
        var platformProject = ProjectPath(root, "Fleetory.Platform");
        var projectText = File.ReadAllText(platformProject.FullName);

        foreach (var token in ForbiddenPrematureSecurityImplementationTokens)
        {
            Assert.DoesNotContain(token, projectText, StringComparison.OrdinalIgnoreCase);
        }

        foreach (var sourceFile in platformProject.Directory!.EnumerateFiles("*.cs", SearchOption.AllDirectories))
        {
            var source = File.ReadAllText(sourceFile.FullName);
            foreach (var token in ForbiddenPrematureSecurityImplementationTokens)
            {
                Assert.DoesNotContain(token, source, StringComparison.Ordinal);
            }
        }
    }

    [Fact]
    public void Public_contract_projects_must_remain_persistence_and_web_framework_neutral()
    {
        var root = FindSolutionRoot();
        var forbiddenProjectTokens = new[]
        {
            "Npgsql",
            "Microsoft.EntityFrameworkCore",
            "Microsoft.Data.SqlClient",
            "System.Data.SqlClient",
            "Dapper",
            "Microsoft.AspNetCore"
        };
        var forbiddenSourceTokens = new[]
        {
            "Microsoft.EntityFrameworkCore",
            "DbContext",
            "DbSet",
            "EntityTypeConfiguration",
            "Npgsql",
            "Microsoft.Data.SqlClient",
            "System.Data.SqlClient",
            "System.ComponentModel.DataAnnotations.Schema",
            "TableAttribute",
            "ColumnAttribute",
            "KeyAttribute",
            "ForeignKeyAttribute",
            "[Table(",
            "[Column(",
            "[Key]",
            "[ForeignKey(",
            "Microsoft.AspNetCore",
            "HttpContext",
            "IEndpointRouteBuilder",
            "ControllerBase"
        };

        foreach (var contractName in ContractProjects)
        {
            var projectPath = ProjectPath(root, contractName);
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
    public void Phase6_persistence_packages_must_not_leak_into_contracts_shared_kernel_or_server()
    {
        var root = FindSolutionRoot();
        var forbiddenProjectTokens = new[]
        {
            "Microsoft.EntityFrameworkCore",
            "Npgsql"
        };
        var forbiddenSourceTokens = new[]
        {
            "Microsoft.EntityFrameworkCore",
            "DbContext",
            "DbSet",
            "EntityTypeConfiguration",
            "Npgsql",
            "System.ComponentModel.DataAnnotations.Schema",
            "TableAttribute",
            "ColumnAttribute",
            "KeyAttribute",
            "ForeignKeyAttribute",
            "[Table(",
            "[Column(",
            "[Key]",
            "[ForeignKey("
        };
        var neutralProjects = ContractProjects
            .Append("Fleetory.SharedKernel")
            .Append("Fleetory.Server")
            .ToArray();

        foreach (var projectName in neutralProjects)
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
    public void Phase6_dbcontexts_and_migrations_must_remain_owned_by_their_bounded_contexts()
    {
        var root = FindSolutionRoot();
        var platformDirectory = ProjectPath(root, "Fleetory.Platform").Directory!;
        var coreDirectory = ProjectPath(root, "Fleetory.Core").Directory!;

        var platformSource = string.Join(
            Environment.NewLine,
            platformDirectory.EnumerateFiles("*.cs", SearchOption.AllDirectories)
                .Select(file => File.ReadAllText(file.FullName)));
        var coreSource = string.Join(
            Environment.NewLine,
            coreDirectory.EnumerateFiles("*.cs", SearchOption.AllDirectories)
                .Select(file => File.ReadAllText(file.FullName)));

        Assert.Contains("class PlatformDbContext", platformSource, StringComparison.Ordinal);
        Assert.Contains("namespace Fleetory.Platform.Persistence.Migrations", platformSource, StringComparison.Ordinal);
        Assert.DoesNotContain("CoreDbContext", platformSource, StringComparison.Ordinal);
        Assert.DoesNotContain("Fleetory.Core.Persistence", platformSource, StringComparison.Ordinal);

        Assert.Contains("class CoreDbContext", coreSource, StringComparison.Ordinal);
        Assert.Contains("namespace Fleetory.Core.Persistence.Migrations", coreSource, StringComparison.Ordinal);
        Assert.DoesNotContain("PlatformDbContext", coreSource, StringComparison.Ordinal);
        Assert.DoesNotContain("Fleetory.Platform.Persistence", coreSource, StringComparison.Ordinal);

        foreach (var projectName in ImplementationProjects.Where(project =>
                     !project.Equals("Fleetory.Platform", StringComparison.OrdinalIgnoreCase) &&
                     !project.Equals("Fleetory.Core", StringComparison.OrdinalIgnoreCase)))
        {
            var projectDirectory = ProjectPath(root, projectName).Directory!;
            foreach (var sourceFile in projectDirectory.EnumerateFiles("*.cs", SearchOption.AllDirectories))
            {
                var source = File.ReadAllText(sourceFile.FullName);
                Assert.DoesNotContain("DbContext", source, StringComparison.Ordinal);
                Assert.DoesNotContain("Fleetory.Platform.Persistence", source, StringComparison.Ordinal);
                Assert.DoesNotContain("Fleetory.Core.Persistence", source, StringComparison.Ordinal);
            }
        }
    }

    [Fact]
    public void Phase6_persistence_models_must_not_create_cross_context_database_coupling()
    {
        var root = FindSolutionRoot();
        foreach (var (projectName, boundary) in Phase6ForeignPersistenceBoundaries)
        {
            var persistenceDirectory = new DirectoryInfo(Path.Combine(
                ProjectPath(root, projectName).Directory!.FullName,
                "Persistence"));

            Assert.True(
                persistenceDirectory.Exists,
                $"Expected PHASE 6 persistence directory for '{projectName}'.");

            foreach (var sourceFile in persistenceDirectory.EnumerateFiles("*.cs", SearchOption.AllDirectories))
            {
                var source = File.ReadAllText(sourceFile.FullName);
                Assert.DoesNotContain(boundary.ForbiddenNamespace, source, StringComparison.Ordinal);

                foreach (var foreignSchema in boundary.ForeignSchemas)
                {
                    Assert.DoesNotContain($"\"{foreignSchema}.", source, StringComparison.OrdinalIgnoreCase);
                    Assert.DoesNotContain($"'{foreignSchema}.", source, StringComparison.OrdinalIgnoreCase);
                    Assert.DoesNotContain($"schema: \"{foreignSchema}\"", source, StringComparison.OrdinalIgnoreCase);
                    Assert.DoesNotContain($"principalSchema: \"{foreignSchema}\"", source, StringComparison.OrdinalIgnoreCase);
                    Assert.DoesNotContain($"HasDefaultSchema(\"{foreignSchema}\")", source, StringComparison.OrdinalIgnoreCase);
                }
            }
        }
    }

    [Fact]
    public void Phase6_only_platform_and_core_receive_executable_persistence_foundations()
    {
        var root = FindSolutionRoot();
        var persistenceProjects = new[] { "Fleetory.Platform", "Fleetory.Core" };

        foreach (var projectName in persistenceProjects)
        {
            var projectPath = ProjectPath(root, projectName);
            var projectText = File.ReadAllText(projectPath.FullName);
            Assert.Contains("Npgsql.EntityFrameworkCore.PostgreSQL", projectText, StringComparison.Ordinal);
            Assert.Contains("Microsoft.EntityFrameworkCore.Design", projectText, StringComparison.Ordinal);
        }

        foreach (var projectName in ImplementationProjects.Except(
                     persistenceProjects,
                     StringComparer.OrdinalIgnoreCase))
        {
            var projectText = File.ReadAllText(ProjectPath(root, projectName).FullName);
            Assert.DoesNotContain("Npgsql.EntityFrameworkCore.PostgreSQL", projectText, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("Microsoft.EntityFrameworkCore.Design", projectText, StringComparison.OrdinalIgnoreCase);
        }
    }


    [Fact]
    public void Phase6_testcontainers_dependency_must_remain_test_only()
    {
        var root = FindSolutionRoot();
        var sourceRoot = new DirectoryInfo(Path.Combine(root.FullName, "src"));

        foreach (var projectFile in sourceRoot.EnumerateFiles("*.csproj", SearchOption.AllDirectories))
        {
            var projectText = File.ReadAllText(projectFile.FullName);
            Assert.DoesNotContain("Testcontainers", projectText, StringComparison.OrdinalIgnoreCase);
        }

        var persistenceTestProject = File.ReadAllText(Path.Combine(
            root.FullName,
            "tests",
            "Fleetory.Persistence.Tests",
            "Fleetory.Persistence.Tests.csproj"));
        Assert.Contains("Testcontainers.PostgreSql", persistenceTestProject, StringComparison.Ordinal);
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
            "OperatingSystem.IsLinux()",
            "OSPlatform.Windows",
            "OSPlatform.Linux",
            "UseWindowsService(",
            "UseSystemd("
        };
        var forbiddenProjectTokens = new[]
        {
            "-windows",
            "win-x64",
            "win-x86",
            "win-arm64",
            "linux-x64",
            "linux-arm64",
            "<RuntimeIdentifier",
            "Microsoft.Extensions.Hosting.WindowsServices",
            "Microsoft.Extensions.Hosting.Systemd",
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

        var moduleEndpointPattern = ModuleEndpointPattern();

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

    private static string[] GetProjectReferences(FileInfo projectPath)
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

    private static HashSet<string> GetDeclaredTypeNames(DirectoryInfo projectDirectory)
    {
        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (var sourceFile in projectDirectory.EnumerateFiles("*.cs", SearchOption.AllDirectories))
        {
            names.UnionWith(GetDeclaredTypeNames(sourceFile));
        }

        return names;
    }

    private static string[] GetDeclaredTypeNames(FileInfo sourceFile)
    {
        var typeDeclarationPattern = TypeDeclarationPattern();
        var source = File.ReadAllText(sourceFile.FullName);

        return typeDeclarationPattern
            .Matches(source)
            .Select(match => match.Groups["name"].Value)
            .ToArray();
    }

    [GeneratedRegex(
        @"\.\s*Map(?:Get|Post|Put|Patch|Delete|Methods|Group)\s*\(",
        RegexOptions.CultureInvariant)]
    private static partial Regex ModuleEndpointPattern();

    [GeneratedRegex(
        @"\b(?:class|record|struct|interface|enum)\s+(?<modifier>class|struct)?\s*(?<name>[A-Za-z_][A-Za-z0-9_]*)\b",
        RegexOptions.CultureInvariant)]
    private static partial Regex TypeDeclarationPattern();

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
