using System.Text.Json;
using Microsoft.Data.SqlClient;
using MyCompany.Security.MiniKms.Client;
using Npgsql;

namespace MyCompany.Security.MiniKms;

internal interface IMiniKmsStateStore
{
    string ProviderName { get; }

    MiniKmsStateSnapshot Load();

    void Save(MiniKmsStateSnapshot snapshot);
}

internal sealed record MiniKmsStateSnapshot(
    string ActiveKeyVersion,
    Dictionary<string, MiniKmsKeyRecord> KeyRecords,
    List<MiniKmsAuditEntry> AuditEntries);

internal sealed record MiniKmsKeyRecord(
    byte[] MasterKey,
    DateTimeOffset CreatedAt,
    DateTimeOffset? ActivatedAt,
    DateTimeOffset? RetiredAt);

internal sealed class InMemoryMiniKmsStateStore : IMiniKmsStateStore
{
    private readonly object _sync = new();
    private MiniKmsStateSnapshot _snapshot;

    public InMemoryMiniKmsStateStore(MiniKmsStateSnapshot bootstrapSnapshot)
    {
        _snapshot = CloneSnapshot(bootstrapSnapshot);
    }

    public string ProviderName => "InMemoryDemo";

    public MiniKmsStateSnapshot Load()
    {
        lock (_sync)
        {
            return CloneSnapshot(_snapshot);
        }
    }

    public void Save(MiniKmsStateSnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);

        lock (_sync)
        {
            _snapshot = CloneSnapshot(snapshot);
        }
    }

    private static MiniKmsStateSnapshot CloneSnapshot(MiniKmsStateSnapshot snapshot)
        => MiniKmsStateSnapshotCloner.Clone(snapshot);
}

internal sealed class FileMiniKmsStateStore : IMiniKmsStateStore
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true
    };

    private readonly object _sync = new();
    private readonly string _filePath;
    private readonly MiniKmsStateSnapshot _bootstrapSnapshot;

    public FileMiniKmsStateStore(string filePath, MiniKmsStateSnapshot bootstrapSnapshot)
    {
        _filePath = string.IsNullOrWhiteSpace(filePath)
            ? throw new ArgumentException("A MiniKMS state file path is required.", nameof(filePath))
            : Path.GetFullPath(filePath);
        _bootstrapSnapshot = bootstrapSnapshot ?? throw new ArgumentNullException(nameof(bootstrapSnapshot));
    }

    public string ProviderName => "File";

    public MiniKmsStateSnapshot Load()
    {
        lock (_sync)
        {
            if (!File.Exists(_filePath))
            {
                SaveCore(_bootstrapSnapshot);
                return CloneSnapshot(_bootstrapSnapshot);
            }

            using var stream = File.OpenRead(_filePath);
            var snapshot = JsonSerializer.Deserialize<MiniKmsStateSnapshot>(stream, JsonOptions)
                ?? throw new InvalidOperationException("The MiniKMS state file is empty or invalid.");
            return CloneSnapshot(snapshot);
        }
    }

    public void Save(MiniKmsStateSnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);

        lock (_sync)
        {
            SaveCore(snapshot);
        }
    }

    private void SaveCore(MiniKmsStateSnapshot snapshot)
    {
        var directory = Path.GetDirectoryName(_filePath);
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var tempFilePath = $"{_filePath}.tmp";
        File.WriteAllText(tempFilePath, JsonSerializer.Serialize(snapshot, JsonOptions));

        if (File.Exists(_filePath))
        {
            File.Delete(_filePath);
        }

        File.Move(tempFilePath, _filePath);
    }

    private static MiniKmsStateSnapshot CloneSnapshot(MiniKmsStateSnapshot snapshot)
        => MiniKmsStateSnapshotCloner.Clone(snapshot);
}

internal sealed class SqlServerMiniKmsStateStore : IMiniKmsStateStore
{
    private const string TableName = "dbo.MiniKmsStateSnapshot";

    private readonly string _connectionString;
    private readonly MiniKmsStateSnapshot _bootstrapSnapshot;

    public SqlServerMiniKmsStateStore(string connectionString, MiniKmsStateSnapshot bootstrapSnapshot)
    {
        _connectionString = string.IsNullOrWhiteSpace(connectionString)
            ? throw new ArgumentException("A SQL Server connection string is required.", nameof(connectionString))
            : connectionString.Trim();
        _bootstrapSnapshot = bootstrapSnapshot ?? throw new ArgumentNullException(nameof(bootstrapSnapshot));
    }

    public string ProviderName => "SqlServer";

    public MiniKmsStateSnapshot Load()
    {
        using var connection = new SqlConnection(_connectionString);
        connection.Open();
        EnsureSchema(connection);

        using var command = connection.CreateCommand();
        command.CommandText = $"SELECT TOP (1) SnapshotJson FROM {TableName} WHERE SnapshotId = 1";
        var payload = command.ExecuteScalar() as string;
        if (string.IsNullOrWhiteSpace(payload))
        {
            Save(_bootstrapSnapshot);
            return MiniKmsStateSnapshotCloner.Clone(_bootstrapSnapshot);
        }

        return MiniKmsStateSnapshotSerializer.Deserialize(payload);
    }

    public void Save(MiniKmsStateSnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);

        using var connection = new SqlConnection(_connectionString);
        connection.Open();
        EnsureSchema(connection);

        using var command = connection.CreateCommand();
        command.CommandText =
            $"""
            MERGE {TableName} AS target
            USING (SELECT CAST(1 AS int) AS SnapshotId) AS source
            ON target.SnapshotId = source.SnapshotId
            WHEN MATCHED THEN
                UPDATE SET ActiveKeyVersion = @activeKeyVersion, SnapshotJson = @snapshotJson, UpdatedAt = @updatedAt
            WHEN NOT MATCHED THEN
                INSERT (SnapshotId, ActiveKeyVersion, SnapshotJson, UpdatedAt)
                VALUES (1, @activeKeyVersion, @snapshotJson, @updatedAt);
            """;
        command.Parameters.AddWithValue("@activeKeyVersion", snapshot.ActiveKeyVersion);
        command.Parameters.AddWithValue("@snapshotJson", MiniKmsStateSnapshotSerializer.Serialize(snapshot));
        command.Parameters.AddWithValue("@updatedAt", DateTimeOffset.UtcNow);
        command.ExecuteNonQuery();
    }

    private static void EnsureSchema(SqlConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText =
            $"""
            IF OBJECT_ID(N'{TableName}', N'U') IS NULL
            BEGIN
                CREATE TABLE {TableName} (
                    SnapshotId int NOT NULL PRIMARY KEY,
                    ActiveKeyVersion nvarchar(128) NOT NULL,
                    SnapshotJson nvarchar(max) NOT NULL,
                    UpdatedAt datetimeoffset NOT NULL
                );
            END;
            """;
        command.ExecuteNonQuery();
    }
}

internal sealed class PostgresMiniKmsStateStore : IMiniKmsStateStore
{
    private const string TableName = "public.minikms_state_snapshot";

    private readonly string _connectionString;
    private readonly MiniKmsStateSnapshot _bootstrapSnapshot;

    public PostgresMiniKmsStateStore(string connectionString, MiniKmsStateSnapshot bootstrapSnapshot)
    {
        _connectionString = string.IsNullOrWhiteSpace(connectionString)
            ? throw new ArgumentException("A PostgreSQL connection string is required.", nameof(connectionString))
            : connectionString.Trim();
        _bootstrapSnapshot = bootstrapSnapshot ?? throw new ArgumentNullException(nameof(bootstrapSnapshot));
    }

    public string ProviderName => "Postgres";

    public MiniKmsStateSnapshot Load()
    {
        using var connection = new NpgsqlConnection(_connectionString);
        connection.Open();
        EnsureSchema(connection);

        using var command = connection.CreateCommand();
        command.CommandText = $"SELECT snapshot_json FROM {TableName} WHERE snapshot_id = 1";
        var payload = command.ExecuteScalar() as string;
        if (string.IsNullOrWhiteSpace(payload))
        {
            Save(_bootstrapSnapshot);
            return MiniKmsStateSnapshotCloner.Clone(_bootstrapSnapshot);
        }

        return MiniKmsStateSnapshotSerializer.Deserialize(payload);
    }

    public void Save(MiniKmsStateSnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);

        using var connection = new NpgsqlConnection(_connectionString);
        connection.Open();
        EnsureSchema(connection);

        using var command = connection.CreateCommand();
        command.CommandText =
            $"""
            INSERT INTO {TableName} (snapshot_id, active_key_version, snapshot_json, updated_at)
            VALUES (1, @activeKeyVersion, @snapshotJson, @updatedAt)
            ON CONFLICT (snapshot_id)
            DO UPDATE SET
                active_key_version = EXCLUDED.active_key_version,
                snapshot_json = EXCLUDED.snapshot_json,
                updated_at = EXCLUDED.updated_at;
            """;
        command.Parameters.AddWithValue("activeKeyVersion", snapshot.ActiveKeyVersion);
        command.Parameters.AddWithValue("snapshotJson", MiniKmsStateSnapshotSerializer.Serialize(snapshot));
        command.Parameters.AddWithValue("updatedAt", DateTimeOffset.UtcNow);
        command.ExecuteNonQuery();
    }

    private static void EnsureSchema(NpgsqlConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText =
            $"""
            CREATE TABLE IF NOT EXISTS {TableName} (
                snapshot_id integer PRIMARY KEY,
                active_key_version varchar(128) NOT NULL,
                snapshot_json text NOT NULL,
                updated_at timestamptz NOT NULL
            );
            """;
        command.ExecuteNonQuery();
    }
}

internal static class MiniKmsStateSnapshotSerializer
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true
    };

    public static string Serialize(MiniKmsStateSnapshot snapshot) =>
        JsonSerializer.Serialize(snapshot, JsonOptions);

    public static MiniKmsStateSnapshot Deserialize(string payload)
    {
        var snapshot = JsonSerializer.Deserialize<MiniKmsStateSnapshot>(payload, JsonOptions)
            ?? throw new InvalidOperationException("The MiniKMS state payload is empty or invalid.");
        return MiniKmsStateSnapshotCloner.Clone(snapshot);
    }
}

internal static class MiniKmsStateSnapshotCloner
{
    public static MiniKmsStateSnapshot Clone(MiniKmsStateSnapshot snapshot)
    {
        return new MiniKmsStateSnapshot(
            snapshot.ActiveKeyVersion,
            snapshot.KeyRecords.ToDictionary(
                pair => pair.Key,
                pair => pair.Value with { MasterKey = pair.Value.MasterKey.ToArray() },
                StringComparer.Ordinal),
            snapshot.AuditEntries.Select(entry => entry with { }).ToList());
    }
}
