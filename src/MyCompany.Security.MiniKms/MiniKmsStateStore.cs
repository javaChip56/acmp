using System.Text.Json;
using MyCompany.Security.MiniKms.Client;

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
