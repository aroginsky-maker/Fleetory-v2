namespace Fleetory.SharedKernel;

public readonly record struct CorrelationId(string Value)
{
    public static CorrelationId New() => new(Guid.NewGuid().ToString("N"));

    public override string ToString() => Value;
}
