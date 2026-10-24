using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Fleetory.Platform.Audit;

internal sealed class AuditExportWorker(
    PostgreSqlAuditExportPump pump,
    ILogger<AuditExportWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var delivered = await pump.ExportNextBatchAsync(cancellationToken: stoppingToken);
                if (delivered == 0)
                {
                    await Task.Delay(TimeSpan.FromSeconds(1), stoppingToken);
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception exception)
            {
                logger.LogError(
                    "Audit export failed ({ErrorType}); pending entries remain in the outbox.",
                    exception.GetType().Name);
                await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken);
            }
        }
    }
}
