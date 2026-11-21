using Microsoft.Extensions.Logging;
using Npgsql;

namespace ServerBackendProbe;

// A categorical observation of the real worker's PostgreSQL failure; no log text is retained.
[ProviderAlias("WorkerObservation")]
internal sealed class WorkerObservation : ILoggerProvider
{
    private int _errors;
    internal int Errors => Volatile.Read(ref _errors);
    public ILogger CreateLogger(string categoryName) => new Observer(this, categoryName);
    public void Dispose() { }

    private sealed class Observer(WorkerObservation owner, string category) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => logLevel == LogLevel.Error;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state,
            Exception? exception, Func<TState, Exception?, string> formatter)
        {
            if (logLevel == LogLevel.Error && category == "Fleetory.Platform.Audit.AuditExportWorker" &&
                state is IEnumerable<KeyValuePair<string, object?>> fields &&
                fields.Any(field => field.Key == "ErrorType" && field.Value is nameof(PostgresException)))
            { Interlocked.Increment(ref owner._errors); }
        }
    }
}
