using System.Collections.Concurrent;
using MyCompany.AuthPlatform.Packaging;

namespace MyCompany.AuthPlatform.Hmac;

public sealed class ServicePackageCacheOptions
{
    public string PackageDirectory { get; set; } = string.Empty;

    public TimeSpan CacheTimeToLive { get; set; } = TimeSpan.FromMinutes(5);

    public IReadOnlyCollection<string> PreloadKeyIds { get; set; } = Array.Empty<string>();
}

public sealed class EncryptedFileServiceCredentialStore : IDisposable
{
    private readonly ServicePackageCacheOptions _options;
    private readonly IHmacCredentialPackageReader _packageReader;
    private readonly ConcurrentDictionary<string, CacheEntry> _entries = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, byte> _staleKeys = new(StringComparer.Ordinal);
    private readonly object _watcherSync = new();
    private FileSystemWatcher? _watcher;

    public EncryptedFileServiceCredentialStore(
        ServicePackageCacheOptions options,
        IHmacCredentialPackageReader packageReader)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _packageReader = packageReader ?? throw new ArgumentNullException(nameof(packageReader));
    }

    public async Task PreloadAsync(CancellationToken cancellationToken = default)
    {
        foreach (var keyId in _options.PreloadKeyIds.Distinct(StringComparer.Ordinal))
        {
            await GetByKeyIdAsync(keyId, expectedKeyVersion: null, cancellationToken);
        }
    }

    public void Invalidate(string keyId)
    {
        if (!string.IsNullOrWhiteSpace(keyId))
        {
            var normalizedKeyId = keyId.Trim();
            _entries.TryRemove(normalizedKeyId, out _);
            _staleKeys.TryRemove(normalizedKeyId, out _);
        }
    }

    public async Task<ServiceValidationCredentialPackage> GetByKeyIdAsync(
        string keyId,
        string? expectedKeyVersion = null,
        CancellationToken cancellationToken = default)
    {
        var normalizedKeyId = RequireKeyId(keyId);
        var packagePath = Path.Combine(RequireDirectory(), $"{normalizedKeyId}.service.acmppkg.json");
        EnsureWatcher();
        var now = DateTimeOffset.UtcNow;
        var observedLastWriteTimeUtc = File.Exists(packagePath)
            ? File.GetLastWriteTimeUtc(packagePath)
            : (DateTime?)null;

        var isStale = _staleKeys.ContainsKey(normalizedKeyId);
        if (_entries.TryGetValue(normalizedKeyId, out var current) &&
            !isStale &&
            current.CanServe(now, observedLastWriteTimeUtc, _options.CacheTimeToLive, expectedKeyVersion))
        {
            return current.Package;
        }

        try
        {
            var package = await _packageReader.ReadServiceValidationPackageAsync(packagePath, normalizedKeyId, expectedKeyVersion, cancellationToken);
            var entry = new CacheEntry(
                package,
                File.Exists(packagePath) ? File.GetLastWriteTimeUtc(packagePath) : DateTime.UtcNow,
                DateTimeOffset.UtcNow);
            _entries[normalizedKeyId] = entry;
            _staleKeys.TryRemove(normalizedKeyId, out _);
            return entry.Package;
        }
        catch (Exception) when (
            !cancellationToken.IsCancellationRequested &&
            current is not null &&
            current.CanServeLastKnownGood(now, _options.CacheTimeToLive))
        {
            return current.Package;
        }
    }

    private string RequireDirectory()
    {
        if (string.IsNullOrWhiteSpace(_options.PackageDirectory))
        {
            throw new InvalidOperationException("A package directory must be configured for encrypted-file validation mode.");
        }

        return _options.PackageDirectory;
    }

    private void EnsureWatcher()
    {
        if (_watcher is not null)
        {
            return;
        }

        lock (_watcherSync)
        {
            if (_watcher is not null)
            {
                return;
            }

            var directory = RequireDirectory();
            Directory.CreateDirectory(directory);
            _watcher = new FileSystemWatcher(directory, "*.service.acmppkg.json")
            {
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.CreationTime | NotifyFilters.Size,
                IncludeSubdirectories = false,
                EnableRaisingEvents = true
            };
            _watcher.Changed += OnPackageFileChanged;
            _watcher.Created += OnPackageFileChanged;
            _watcher.Deleted += OnPackageFileChanged;
            _watcher.Renamed += OnPackageFileRenamed;
        }
    }

    private void OnPackageFileChanged(object? sender, FileSystemEventArgs eventArgs)
    {
        if (TryExtractKeyId(eventArgs.Name, ".service.acmppkg.json", out var keyId))
        {
            _staleKeys[keyId] = 0;
        }
    }

    private void OnPackageFileRenamed(object? sender, RenamedEventArgs eventArgs)
    {
        OnPackageFileChanged(sender, eventArgs);

        if (TryExtractKeyId(eventArgs.OldName, ".service.acmppkg.json", out var oldKeyId))
        {
            _staleKeys[oldKeyId] = 0;
        }
    }

    private static bool TryExtractKeyId(string? fileName, string suffix, out string keyId)
    {
        keyId = string.Empty;
        if (string.IsNullOrWhiteSpace(fileName) || !fileName.EndsWith(suffix, StringComparison.Ordinal))
        {
            return false;
        }

        keyId = fileName[..^suffix.Length];
        return !string.IsNullOrWhiteSpace(keyId);
    }

    private static string RequireKeyId(string? keyId)
    {
        if (string.IsNullOrWhiteSpace(keyId))
        {
            throw new ArgumentException("'keyId' is required.", nameof(keyId));
        }

        return keyId.Trim();
    }

    private sealed record CacheEntry(
        ServiceValidationCredentialPackage Package,
        DateTime SourceLastWriteTimeUtc,
        DateTimeOffset LoadedAtUtc)
    {
        public bool CanServe(
            DateTimeOffset now,
            DateTime? observedLastWriteTimeUtc,
            TimeSpan ttl,
            string? expectedKeyVersion)
        {
            if (!CanServeLastKnownGood(now, ttl))
            {
                return false;
            }

            if (!string.IsNullOrWhiteSpace(expectedKeyVersion) &&
                !string.Equals(Package.KeyVersion, expectedKeyVersion.Trim(), StringComparison.Ordinal))
            {
                return false;
            }

            return !observedLastWriteTimeUtc.HasValue || observedLastWriteTimeUtc.Value == SourceLastWriteTimeUtc;
        }

        public bool CanServeLastKnownGood(DateTimeOffset now, TimeSpan ttl) =>
            Package.ExpiresAt > now && LoadedAtUtc.Add(ttl) > now;
    }

    public void Dispose()
    {
        if (_watcher is null)
        {
            return;
        }

        _watcher.EnableRaisingEvents = false;
        _watcher.Dispose();
        _watcher = null;
    }
}
