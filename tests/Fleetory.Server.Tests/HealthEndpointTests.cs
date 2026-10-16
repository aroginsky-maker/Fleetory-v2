using System.Net;
using Fleetory.ModuleAbstractions;
using Fleetory.Server;
using Fleetory.Server.Infrastructure;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.Extensions.DependencyInjection;

namespace Fleetory.Server.Tests;

public sealed class HealthEndpointTests
{
    private static readonly string[] ServerArguments =
    [
        "--ConnectionStrings:Fleetory=Host=127.0.0.1;Port=1;Database=fleetory_phase6_unit_test;Username=fleetory;Timeout=1;Command Timeout=1"
    ];

    [Fact]
    public async Task Liveness_stays_healthy_when_database_is_unavailable_and_readiness_is_unhealthy()
    {
        await WithRunningServerAsync(async client =>
        {
            using var liveResponse = await client.GetAsync("/health/live");
            using var readyResponse = await client.GetAsync("/health/ready");

            Assert.True(liveResponse.IsSuccessStatusCode);
            Assert.Equal(HttpStatusCode.ServiceUnavailable, readyResponse.StatusCode);
            Assert.Equal("Healthy", (await liveResponse.Content.ReadAsStringAsync()).Trim());
            Assert.Equal("Unhealthy", (await readyResponse.Content.ReadAsStringAsync()).Trim());
        });
    }

    [Fact]
    public async Task Correlation_id_is_propagated_to_the_response()
    {
        await WithRunningServerAsync(async client =>
        {
            const string correlationId = "phase2-test-correlation";
            using var response = await SendWithCorrelationIdAsync(client, correlationId);

            Assert.True(response.IsSuccessStatusCode);
            Assert.True(response.Headers.TryGetValues(CorrelationIdMiddleware.HeaderName, out var values));
            Assert.Equal(correlationId, Assert.Single(values));
        });
    }

    [Fact]
    public async Task Invalid_correlation_ids_are_replaced_by_server_generated_values()
    {
        await WithRunningServerAsync(async client =>
        {
            var invalidValues = new[]
            {
                "contains whitespace",
                new string('a', 129)
            };

            foreach (var invalidValue in invalidValues)
            {
                using var response = await SendWithCorrelationIdAsync(client, invalidValue);

                Assert.True(response.IsSuccessStatusCode);
                Assert.True(response.Headers.TryGetValues(CorrelationIdMiddleware.HeaderName, out var values));

                var actual = Assert.Single(values);
                Assert.NotEqual(invalidValue, actual);
                Assert.Equal(32, actual.Length);
                Assert.True(Guid.TryParseExact(actual, "N", out _));
            }
        });
    }

    [Fact]
    public void Approved_modules_are_registered_once()
    {
        using var app = FleetoryApplication.Build(ServerArguments);
        var modules = app.Services.GetRequiredService<IReadOnlyCollection<IFleetoryModule>>();

        var moduleNames = modules.Select(module => module.Name).ToArray();
        var expected = new[]
        {
            "Platform",
            "Core",
            "Assets",
            "ITSM",
            "CMDB",
            "Monitoring",
            "Integrations"
        };

        Assert.Equal(expected, moduleNames);
        Assert.Equal(moduleNames.Length, moduleNames.Distinct(StringComparer.Ordinal).Count());
    }

    private static async Task<HttpResponseMessage> SendWithCorrelationIdAsync(HttpClient client, string correlationId)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "/health/live");
        request.Headers.Add(CorrelationIdMiddleware.HeaderName, correlationId);
        return await client.SendAsync(request);
    }

    private static async Task WithRunningServerAsync(Func<HttpClient, Task> testBody)
    {
        await using var app = FleetoryApplication.Build(ServerArguments);
        app.Urls.Clear();
        app.Urls.Add(CreateLoopbackListenUrl());

        await app.StartAsync();

        try
        {
            var server = app.Services.GetRequiredService<IServer>();
            var addresses = server.Features.Get<IServerAddressesFeature>()?.Addresses;
            var address = Assert.Single(
                addresses ?? throw new InvalidOperationException("Server address feature is unavailable."));

            using var client = new HttpClient
            {
                BaseAddress = new Uri(address)
            };

            await testBody(client);
        }
        finally
        {
            await app.StopAsync();
        }
    }

    private static string CreateLoopbackListenUrl() =>
        new UriBuilder(Uri.UriSchemeHttp, IPAddress.Loopback.ToString(), 0)
            .Uri
            .GetLeftPart(UriPartial.Authority);
}
