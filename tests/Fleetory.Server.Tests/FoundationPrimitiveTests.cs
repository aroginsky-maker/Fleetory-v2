using Fleetory.SharedKernel;

namespace Fleetory.Server.Tests;

public sealed class FoundationPrimitiveTests
{
    [Fact]
    public void Correlation_id_factory_returns_valid_nonempty_identifier()
    {
        var correlationId = CorrelationId.New();

        Assert.False(string.IsNullOrWhiteSpace(correlationId.Value));
        Assert.True(Guid.TryParseExact(correlationId.Value, "N", out _));
        Assert.Equal(correlationId.Value, correlationId.ToString());
    }

    [Fact]
    public void System_clock_returns_current_utc_time()
    {
        IClock clock = new SystemClock();
        var before = DateTimeOffset.UtcNow.AddSeconds(-1);

        var actual = clock.UtcNow;

        var after = DateTimeOffset.UtcNow.AddSeconds(1);
        Assert.Equal(TimeSpan.Zero, actual.Offset);
        Assert.InRange(actual, before, after);
    }
}
