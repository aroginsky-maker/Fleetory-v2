using Fleetory.Core.Contracts;
using Microsoft.Data.Sqlite;

namespace Fleetory.Agent.Security;

/// <summary>Agent-local, durable, atomic command and nonce consumption.</summary>
public sealed class SqliteCommandReplayStore : ICommandReplayStore
{
    private readonly string _connectionString;

    public SqliteCommandReplayStore(string databasePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(databasePath);
        if (!Path.IsPathFullyQualified(databasePath) || !Directory.Exists(Path.GetDirectoryName(databasePath)))
        {
            throw new ArgumentException("Replay database requires an absolute path in an existing directory.", nameof(databasePath));
        }

        var directory = Path.GetDirectoryName(databasePath)!;
        if ((File.GetAttributes(directory) & FileAttributes.ReparsePoint) != 0 ||
            File.Exists(databasePath) && (File.GetAttributes(databasePath) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidOperationException("Replay storage must not use a symbolic link.");
        }

        if (!OperatingSystem.IsWindows())
        {
            const UnixFileMode unsafeBits = UnixFileMode.GroupRead | UnixFileMode.GroupWrite |
                UnixFileMode.GroupExecute | UnixFileMode.OtherRead | UnixFileMode.OtherWrite |
                UnixFileMode.OtherExecute;
            if ((File.GetUnixFileMode(directory) & unsafeBits) != 0)
            {
                throw new InvalidOperationException("Replay storage directory permissions are too broad.");
            }
        }

        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = databasePath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Pooling = false,
            DefaultTimeout = 10
        }.ToString();

        using var connection = OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = """
            CREATE TABLE IF NOT EXISTS consumed_commands (
                device_id TEXT NOT NULL,
                command_id TEXT NOT NULL,
                nonce TEXT NOT NULL,
                expires_at_utc_ticks INTEGER NOT NULL,
                PRIMARY KEY (device_id, command_id),
                UNIQUE (device_id, nonce)
            );
            """;
        command.ExecuteNonQuery();
    }

    public async ValueTask<bool> TryConsumeAsync(
        DeviceId targetDeviceId,
        Guid commandId,
        string nonce,
        DateTimeOffset expiresAt,
        CancellationToken cancellationToken = default)
    {
        if (targetDeviceId.Value == Guid.Empty || commandId == Guid.Empty ||
            string.IsNullOrWhiteSpace(nonce) || nonce.Length > 128)
        {
            throw new ArgumentException("Replay identity is invalid.");
        }

        await using var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync(cancellationToken);
        ConfigureDurability(connection);

        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.Transaction = (SqliteTransaction)transaction;
        command.CommandText = """
            INSERT OR IGNORE INTO consumed_commands
                (device_id, command_id, nonce, expires_at_utc_ticks)
            VALUES ($deviceId, $commandId, $nonce, $expiresAt);
            """;
        command.Parameters.AddWithValue("$deviceId", targetDeviceId.Value.ToString("N"));
        command.Parameters.AddWithValue("$commandId", commandId.ToString("N"));
        command.Parameters.AddWithValue("$nonce", nonce);
        command.Parameters.AddWithValue("$expiresAt", expiresAt.UtcTicks);
        var inserted = await command.ExecuteNonQueryAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return inserted == 1;
    }

    private SqliteConnection OpenConnection()
    {
        var connection = new SqliteConnection(_connectionString);
        try
        {
            connection.Open();
            ConfigureDurability(connection);
            return connection;
        }
        catch
        {
            connection.Dispose();
            throw;
        }
    }

    private static void ConfigureDurability(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;";
        command.ExecuteNonQuery();
    }
}
