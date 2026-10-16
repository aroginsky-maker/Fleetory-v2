using Fleetory.ModuleAbstractions;
using Fleetory.Platform.Contracts;
using Fleetory.SharedKernel;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Fleetory.Platform.Tests;

public sealed class PlatformFoundationTests
{
    private static readonly string[] ExpectedRegisteredModuleIds =
    [
        "Assets",
        "Core",
        "Platform"
    ];

    private static readonly SearchResult[] CoreSearchResults =
    [
        new("Core", "Device", "device-1", "NB-0001")
    ];

    private static readonly SearchResult[] AssetSearchResults =
    [
        new("Assets", "Asset", "asset-1", "Laptop 1")
    ];

    private static readonly SearchResult[] LimitedCoreSearchResults =
    [
        new("Core", "Device", "device-1", "NB-0001"),
        new("Core", "Device", "device-2", "NB-0002")
    ];

    [Fact]
    public void Platform_module_registers_module_registry_and_search_service()
    {
        var modules = CreateModules("Platform", "Core", "Assets");
        using var provider = BuildServices(modules);

        Assert.NotNull(provider.GetRequiredService<IModuleRegistry>());
        Assert.NotNull(provider.GetRequiredService<ISearchService>());
        Assert.NotNull(provider.GetRequiredService<IAuditWriter>());
    }

    [Fact]
    public void Module_registry_returns_stable_registered_module_metadata()
    {
        var modules = CreateModules("Platform", "Core", "Assets");
        using var provider = BuildServices(modules);
        var registry = provider.GetRequiredService<IModuleRegistry>();

        var firstRead = registry.GetModules();
        var secondRead = registry.GetModules();

        Assert.Equal(
            ExpectedRegisteredModuleIds,
            firstRead.Select(module => module.ModuleId).ToArray());
        Assert.All(firstRead, module => Assert.True(module.IsRegistered));
        Assert.Equal(firstRead, secondRead);
        Assert.Equal("Core", registry.Find("Core")?.DisplayName);
        Assert.Null(registry.Find("Monitoring"));
    }

    [Fact]
    public void Module_registry_rejects_duplicate_module_identifiers()
    {
        var modules = CreateModules("Platform", "Core", "Core");
        using var provider = BuildServices(modules);

        var exception = Assert.Throws<InvalidOperationException>(
            () => provider.GetRequiredService<IModuleRegistry>());

        Assert.Contains("Duplicate Fleetory module name: Core.", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Search_service_aggregates_registered_providers_without_module_coupling()
    {
        var services = CreateServiceCollection(CreateModules("Platform"));
        services.AddSingleton<ISearchProvider>(new StubSearchProvider(
            "Core",
            CoreSearchResults));
        services.AddSingleton<ISearchProvider>(new StubSearchProvider(
            "Assets",
            AssetSearchResults));

        using var provider = services.BuildServiceProvider();
        var search = provider.GetRequiredService<ISearchService>();

        var results = await search.SearchAsync(new SearchRequest("lap", Limit: 10));

        Assert.Equal(2, results.Count);
        Assert.Contains(results, result => result.SourceModule == "Core" && result.ResultId == "device-1");
        Assert.Contains(results, result => result.SourceModule == "Assets" && result.ResultId == "asset-1");
    }

    [Fact]
    public async Task Search_service_honors_global_result_limit()
    {
        var services = CreateServiceCollection(CreateModules("Platform"));
        services.AddSingleton<ISearchProvider>(new StubSearchProvider(
            "Core",
            LimitedCoreSearchResults));

        using var provider = services.BuildServiceProvider();
        var search = provider.GetRequiredService<ISearchService>();

        var results = await search.SearchAsync(new SearchRequest("NB", Limit: 1));

        Assert.Single(results);
        Assert.Equal("device-1", results[0].ResultId);
    }

    [Fact]
    public void Authorization_contract_supports_explicit_allow_and_deny_decisions()
    {
        var allowed = AuthorizationDecision.Allow();
        var denied = AuthorizationDecision.Deny("Permission not granted.");

        Assert.True(allowed.IsAllowed);
        Assert.Null(allowed.Reason);
        Assert.False(denied.IsAllowed);
        Assert.Equal("Permission not granted.", denied.Reason);
    }

    [Fact]
    public void Audit_contract_preserves_actor_target_correlation_and_time()
    {
        var actor = new ActorReference("system:phase4", ActorKind.System, "Fleetory Server");
        var target = new AuditTarget("Module", "Core");
        var correlationId = new CorrelationId("phase4-audit");
        var clock = new SystemClock();
        var occurredAt = clock.UtcNow;
        var record = new AuditRecord(
            actor,
            "Platform.Module.Read",
            target,
            correlationId,
            occurredAt,
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["Source"] = "PlatformFoundationTests"
            });

        Assert.Equal(actor, record.Actor);
        Assert.Equal(target, record.Target);
        Assert.Equal(correlationId, record.CorrelationId);
        Assert.Equal(occurredAt, record.OccurredAt);
        Assert.Equal("PlatformFoundationTests", record.Context?["Source"]);
    }

    [Fact]
    public void Notification_and_licensing_contracts_remain_transport_and_crypto_neutral()
    {
        var notification = new NotificationMessage(
            "Platform.Health",
            "Fleetory health",
            "Platform foundation is available.");
        var license = new LicenseSnapshot(
            LicenseRuntimeState.Unknown,
            Array.Empty<string>());

        Assert.Equal(NotificationSeverity.Information, notification.Severity);
        Assert.Equal(LicenseRuntimeState.Unknown, license.State);
        Assert.Empty(license.Entitlements);
    }

    private static ServiceProvider BuildServices(IFleetoryModule[] modules) =>
        CreateServiceCollection(modules).BuildServiceProvider();

    private static ServiceCollection CreateServiceCollection(IFleetoryModule[] modules)
    {
        var services = new ServiceCollection();
        services.AddSingleton<IReadOnlyCollection<IFleetoryModule>>(modules);

        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionStrings:Fleetory"] =
                    "Host=127.0.0.1;Port=1;Database=fleetory_phase6_unit_test;Username=fleetory;Timeout=1"
            })
            .Build();
        var platformModule = new Fleetory.Platform.PlatformModule();
        platformModule.RegisterServices(services, configuration);

        return services;
    }

    private static IFleetoryModule[] CreateModules(params string[] names) =>
        names.Select(name => (IFleetoryModule)new StubModule(name)).ToArray();

    private sealed class StubModule(string name) : FleetoryModuleBase
    {
        public override string Name { get; } = name;
    }

    private sealed class StubSearchProvider(
        string sourceModule,
        SearchResult[] results) : ISearchProvider
    {
        public string SourceModule { get; } = sourceModule;

        public ValueTask<IReadOnlyList<SearchResult>> SearchAsync(
            SearchRequest request,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(request);
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult<IReadOnlyList<SearchResult>>(results);
        }
    }
}
