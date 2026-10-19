using Fleetory.Core.Contracts;
using Microsoft.Data.Sqlite;

namespace Fleetory.Agent.Security;

/// <summary>Agent-local, durable, atomic command and nonce consumption.</summary>
public sealed class SqliteCommandReplayStore : ICommandReplayStore
{
    private readonly string _databasePath;
    private readonly string _directory;
    private readonly string _connectionString;

    public SqliteCommandReplayStore(string databasePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(databasePath);
        if (!Path.IsPathFullyQualified(databasePath) || !Directory.Exists(Path.GetDirectoryName(databasePath)))
        {
            throw new ArgumentException("Replay database requires an absolute path in an existing directory.", nameof(databasePath));
        }

        _databasePath = Path.GetFullPath(databasePath);
        _directory = Path.GetDirectoryName(_databasePath)!;
        ValidateDirectory();
        ValidateExistingFiles(_databasePath);

        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = _databasePath,
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
        ValidateExistingFiles(_databasePath);
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

        ValidateDirectory();
        ValidateExistingFiles(_databasePath);

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

    private void ValidateDirectory()
    {
        if ((File.GetAttributes(_directory) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidOperationException("Replay storage must not use a symbolic link.");
        }

        if (OperatingSystem.IsWindows())
        {
            WindowsAgentStorageAcl.ValidateDirectory(_directory, "Replay storage directory");
        }
        else
        {
            const UnixFileMode unsafeBits = UnixFileMode.GroupRead | UnixFileMode.GroupWrite |
                UnixFileMode.GroupExecute | UnixFileMode.OtherRead | UnixFileMode.OtherWrite |
                UnixFileMode.OtherExecute;
            if ((File.GetUnixFileMode(_directory) & unsafeBits) != 0)
            {
                throw new InvalidOperationException("Replay storage directory permissions are too broad.");
            }
        }
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

    private static void ValidateExistingFiles(string databasePath)
    {
        foreach (var path in new[] { databasePath, databasePath + "-wal", databasePath + "-shm" })
        {
            if (!File.Exists(path))
            {
                continue;
            }

            if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidOperationException("Replay storage must not use a symbolic link.");
            }

            if (OperatingSystem.IsWindows())
            {
                WindowsAgentStorageAcl.ValidateFile(path, "Replay storage file");
            }
        }
    }

    private static void ConfigureDurability(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;";
        command.ExecuteNonQuery();
    }
}
