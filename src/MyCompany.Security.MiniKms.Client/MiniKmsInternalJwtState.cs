using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Data.SqlClient;
using Npgsql;

namespace MyCompany.Security.MiniKms.Client;

public sealed class MiniKmsInternalJwtManagedStateOptions
{
    public string Provider { get; set; } = FileProvider;

    public string StateFilePath { get; set; } = "App_Data/minikms-internal-jwt-state.json";

    public MiniKmsInternalJwtManagedSqlServerOptions SqlServer { get; set; } = new();

    public MiniKmsInternalJwtManagedPostgresOptions Postgres { get; set; } = new();

    public static string FileProvider => "File";

    public static string SqlServerProvider => "SqlServer";

    public static string PostgresProvider => "Postgres";
}

public sealed class MiniKmsInternalJwtManagedSqlServerOptions
{
    public string ConnectionString { get; set; } = string.Empty;
}

public sealed class MiniKmsInternalJwtManagedPostgresOptions
{
    public string ConnectionString { get; set; } = string.Empty;
}

public sealed record MiniKmsInternalJwtKeyRecord(
    byte[] SigningKey,
    DateTimeOffset CreatedAt,
    DateTimeOffset? ActivatedAt,
    DateTimeOffset? RetiredAt);

public sealed record MiniKmsInternalJwtKeySnapshot(
    string ActiveKeyVersion,
    Dictionary<string, MiniKmsInternalJwtKeyRecord> KeyRecords);

public sealed record MiniKmsInternalJwtKeyVersionSummary(
    string KeyVersion,
    string Status,
    bool IsActive,
    DateTimeOffset CreatedAt,
    DateTimeOffset? ActivatedAt,
    DateTimeOffset? RetiredAt);

public interface IMiniKmsInternalJwtKeyStateStore
{
    string ProviderName { get; }

    MiniKmsInternalJwtKeySnapshot Load();

    void Save(MiniKmsInternalJwtKeySnapshot snapshot);
}

public sealed class InMemoryMiniKmsInternalJwtKeyStateStore : IMiniKmsInternalJwtKeyStateStore
{
    private readonly object _sync = new();
    private MiniKmsInternalJwtKeySnapshot _snapshot;

    public InMemoryMiniKmsInternalJwtKeyStateStore(MiniKmsInternalJwtKeySnapshot bootstrapSnapshot)
    {
        _snapshot = MiniKmsInternalJwtKeySnapshotHelpers.Clone(bootstrapSnapshot);
    }

    public string ProviderName => "InMemory";

    public MiniKmsInternalJwtKeySnapshot Load()
    {
        lock (_sync)
        {
            return MiniKmsInternalJwtKeySnapshotHelpers.Clone(_snapshot);
        }
    }

    public void Save(MiniKmsInternalJwtKeySnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        lock (_sync)
        {
            _snapshot = MiniKmsInternalJwtKeySnapshotHelpers.Clone(snapshot);
        }
    }
}

public static class MiniKmsInternalJwtStateStoreFactory
{
    public static IMiniKmsInternalJwtKeyStateStore Create(
        MiniKmsInternalJwtManagedStateOptions options,
        MiniKmsInternalJwtKeySnapshot bootstrapSnapshot)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(bootstrapSnapshot);

        if (string.Equals(options.Provider, MiniKmsInternalJwtManagedStateOptions.FileProvider, StringComparison.OrdinalIgnoreCase))
        {
            return new FileMiniKmsInternalJwtKeyStateStore(options.StateFilePath, bootstrapSnapshot);
        }

        if (string.Equals(options.Provider, MiniKmsInternalJwtManagedStateOptions.SqlServerProvider, StringComparison.OrdinalIgnoreCase))
        {
            return new SqlServerMiniKmsInternalJwtKeyStateStore(options.SqlServer.ConnectionString, bootstrapSnapshot);
        }

        if (string.Equals(options.Provider, MiniKmsInternalJwtManagedStateOptions.PostgresProvider, StringComparison.OrdinalIgnoreCase))
        {
            return new PostgresMiniKmsInternalJwtKeyStateStore(options.Postgres.ConnectionString, bootstrapSnapshot);
        }

        throw new InvalidOperationException(
            $"MiniKMS internal JWT managed state provider '{options.Provider}' is not supported. " +
            $"Use '{MiniKmsInternalJwtManagedStateOptions.FileProvider}', '{MiniKmsInternalJwtManagedStateOptions.SqlServerProvider}', or '{MiniKmsInternalJwtManagedStateOptions.PostgresProvider}'.");
    }

    public static MiniKmsInternalJwtKeySnapshot CreateBootstrapSnapshot(string? activeKeyVersion, byte[]? signingKey = null)
    {
        var resolvedKeyVersion = string.IsNullOrWhiteSpace(activeKeyVersion)
            ? "svcjwt-v1"
            : activeKeyVersion.Trim();
        var resolvedSigningKey = signingKey is { Length: > 0 }
            ? signingKey.ToArray()
            : RandomNumberGenerator.GetBytes(32);

        if (resolvedSigningKey.Length != 32)
        {
            throw new InvalidOperationException("MiniKMS internal JWT signing keys must be exactly 32 bytes.");
        }

        var now = DateTimeOffset.UtcNow;
        return new MiniKmsInternalJwtKeySnapshot(
            resolvedKeyVersion,
            new Dictionary<string, MiniKmsInternalJwtKeyRecord>(StringComparer.Ordinal)
            {
                [resolvedKeyVersion] = new(resolvedSigningKey, now, now, null)
            });
    }
}

internal sealed class FileMiniKmsInternalJwtKeyStateStore : IMiniKmsInternalJwtKeyStateStore
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true
    };

    private readonly object _sync = new();
    private readonly string _filePath;
    private readonly MiniKmsInternalJwtKeySnapshot _bootstrapSnapshot;

    public FileMiniKmsInternalJwtKeyStateStore(string filePath, MiniKmsInternalJwtKeySnapshot bootstrapSnapshot)
    {
        _filePath = string.IsNullOrWhiteSpace(filePath)
            ? throw new ArgumentException("A MiniKMS internal JWT state file path is required.", nameof(filePath))
            : Path.GetFullPath(filePath);
        _bootstrapSnapshot = bootstrapSnapshot ?? throw new ArgumentNullException(nameof(bootstrapSnapshot));
    }

    public string ProviderName => "File";

    public MiniKmsInternalJwtKeySnapshot Load()
    {
        lock (_sync)
        {
            if (!File.Exists(_filePath))
            {
                SaveCore(_bootstrapSnapshot);
                return MiniKmsInternalJwtKeySnapshotHelpers.Clone(_bootstrapSnapshot);
            }

            using var stream = File.OpenRead(_filePath);
            var snapshot = JsonSerializer.Deserialize<MiniKmsInternalJwtKeySnapshot>(stream, JsonOptions)
                ?? throw new InvalidOperationException("The MiniKMS internal JWT state file is empty or invalid.");
            return MiniKmsInternalJwtKeySnapshotHelpers.Clone(snapshot);
        }
    }

    public void Save(MiniKmsInternalJwtKeySnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        lock (_sync)
        {
            SaveCore(snapshot);
        }
    }

    private void SaveCore(MiniKmsInternalJwtKeySnapshot snapshot)
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
}

internal sealed class SqlServerMiniKmsInternalJwtKeyStateStore : IMiniKmsInternalJwtKeyStateStore
{
    private const string TableName = "dbo.MiniKmsInternalJwtKeySnapshot";

    private readonly string _connectionString;
    private readonly MiniKmsInternalJwtKeySnapshot _bootstrapSnapshot;

    public SqlServerMiniKmsInternalJwtKeyStateStore(string connectionString, MiniKmsInternalJwtKeySnapshot bootstrapSnapshot)
    {
        _connectionString = string.IsNullOrWhiteSpace(connectionString)
            ? throw new ArgumentException("A SQL Server connection string is required.", nameof(connectionString))
            : connectionString.Trim();
        _bootstrapSnapshot = bootstrapSnapshot ?? throw new ArgumentNullException(nameof(bootstrapSnapshot));
    }

    public string ProviderName => "SqlServer";

    public MiniKmsInternalJwtKeySnapshot Load()
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
            return MiniKmsInternalJwtKeySnapshotHelpers.Clone(_bootstrapSnapshot);
        }

        return MiniKmsInternalJwtKeySnapshotHelpers.Deserialize(payload);
    }

    public void Save(MiniKmsInternalJwtKeySnapshot snapshot)
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
        command.Parameters.AddWithValue("@snapshotJson", MiniKmsInternalJwtKeySnapshotHelpers.Serialize(snapshot));
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

internal sealed class PostgresMiniKmsInternalJwtKeyStateStore : IMiniKmsInternalJwtKeyStateStore
{
    private const string TableName = "public.minikms_internal_jwt_key_snapshot";

    private readonly string _connectionString;
    private readonly MiniKmsInternalJwtKeySnapshot _bootstrapSnapshot;

    public PostgresMiniKmsInternalJwtKeyStateStore(string connectionString, MiniKmsInternalJwtKeySnapshot bootstrapSnapshot)
    {
        _connectionString = string.IsNullOrWhiteSpace(connectionString)
            ? throw new ArgumentException("A PostgreSQL connection string is required.", nameof(connectionString))
            : connectionString.Trim();
        _bootstrapSnapshot = bootstrapSnapshot ?? throw new ArgumentNullException(nameof(bootstrapSnapshot));
    }

    public string ProviderName => "Postgres";

    public MiniKmsInternalJwtKeySnapshot Load()
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
            return MiniKmsInternalJwtKeySnapshotHelpers.Clone(_bootstrapSnapshot);
        }

        return MiniKmsInternalJwtKeySnapshotHelpers.Deserialize(payload);
    }

    public void Save(MiniKmsInternalJwtKeySnapshot snapshot)
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
        command.Parameters.AddWithValue("snapshotJson", MiniKmsInternalJwtKeySnapshotHelpers.Serialize(snapshot));
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

internal static class MiniKmsInternalJwtKeySnapshotHelpers
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true
    };

    public static string Serialize(MiniKmsInternalJwtKeySnapshot snapshot) =>
        JsonSerializer.Serialize(snapshot, JsonOptions);

    public static MiniKmsInternalJwtKeySnapshot Deserialize(string payload)
    {
        var snapshot = JsonSerializer.Deserialize<MiniKmsInternalJwtKeySnapshot>(payload, JsonOptions)
            ?? throw new InvalidOperationException("The MiniKMS internal JWT key snapshot payload is empty or invalid.");
        return Clone(snapshot);
    }

    public static MiniKmsInternalJwtKeySnapshot Clone(MiniKmsInternalJwtKeySnapshot snapshot)
    {
        return new MiniKmsInternalJwtKeySnapshot(
            snapshot.ActiveKeyVersion,
            snapshot.KeyRecords.ToDictionary(
                pair => pair.Key,
                pair => pair.Value with { SigningKey = pair.Value.SigningKey.ToArray() },
                StringComparer.Ordinal));
    }
}
