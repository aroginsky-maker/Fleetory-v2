namespace Fleetory.Platform.Contracts;

public enum NotificationSeverity
{
    Information = 0,
    Warning = 1,
    Critical = 2
}

public sealed record NotificationMessage(
    string Kind,
    string Subject,
    string Body,
    NotificationSeverity Severity = NotificationSeverity.Information,
    IReadOnlyDictionary<string, string>? Metadata = null);

public interface INotificationPublisher
{
    ValueTask PublishAsync(
        NotificationMessage notification,
        CancellationToken cancellationToken = default);
}
