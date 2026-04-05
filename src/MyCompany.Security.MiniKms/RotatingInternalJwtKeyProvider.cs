using System.Security.Cryptography;
using MyCompany.Security.MiniKms.Client;

namespace MyCompany.Security.MiniKms;

internal interface IRotatingInternalJwtKeyProvider
{
    string GetActiveKeyVersion();

    byte[] GetSigningKey(string keyVersion);

    IReadOnlyList<MiniKmsInternalJwtKeyVersionSummary> ListKeyVersions();

    IReadOnlyList<SecurityKeyDescriptor> ListValidationKeys();

    MiniKmsInternalJwtKeyVersionSummary AddKeyVersion(string? keyVersion, byte[]? signingKey, bool activate);

    MiniKmsInternalJwtKeyVersionSummary ActivateKeyVersion(string keyVersion);

    MiniKmsInternalJwtKeyVersionSummary RetireKeyVersion(string keyVersion);
}

internal sealed record SecurityKeyDescriptor(
    string KeyVersion,
    byte[] SigningKey,
    bool IsActive);

internal sealed class RotatingInternalJwtKeyProvider : IRotatingInternalJwtKeyProvider
{
    private readonly object _sync = new();
    private readonly IMiniKmsInternalJwtKeyStateStore _stateStore;
    private MiniKmsInternalJwtKeySnapshot _snapshot;

    public RotatingInternalJwtKeyProvider(IMiniKmsInternalJwtKeyStateStore stateStore)
    {
        _stateStore = stateStore ?? throw new ArgumentNullException(nameof(stateStore));
        _snapshot = _stateStore.Load();
    }

    public string GetActiveKeyVersion()
    {
        lock (_sync)
        {
            return _snapshot.ActiveKeyVersion;
        }
    }

    public byte[] GetSigningKey(string keyVersion)
    {
        var resolvedKeyVersion = NormalizeKeyVersion(keyVersion);
        lock (_sync)
        {
            if (!_snapshot.KeyRecords.TryGetValue(resolvedKeyVersion, out var record))
            {
                throw new InvalidOperationException($"MiniKMS internal JWT key version '{resolvedKeyVersion}' does not exist.");
            }

            return record.SigningKey.ToArray();
        }
    }

    public IReadOnlyList<MiniKmsInternalJwtKeyVersionSummary> ListKeyVersions()
    {
        lock (_sync)
        {
            return _snapshot.KeyRecords
                .OrderBy(pair => pair.Key, StringComparer.Ordinal)
                .Select(pair => new MiniKmsInternalJwtKeyVersionSummary(
                    pair.Key,
                    ResolveStatus(pair.Key, pair.Value),
                    string.Equals(pair.Key, _snapshot.ActiveKeyVersion, StringComparison.Ordinal),
                    pair.Value.CreatedAt,
                    pair.Value.ActivatedAt,
                    pair.Value.RetiredAt))
                .ToArray();
        }
    }

    public IReadOnlyList<SecurityKeyDescriptor> ListValidationKeys()
    {
        lock (_sync)
        {
            return _snapshot.KeyRecords
                .OrderBy(pair => pair.Key, StringComparer.Ordinal)
                .Select(pair => new SecurityKeyDescriptor(
                    pair.Key,
                    pair.Value.SigningKey.ToArray(),
                    string.Equals(pair.Key, _snapshot.ActiveKeyVersion, StringComparison.Ordinal)))
                .ToArray();
        }
    }

    public MiniKmsInternalJwtKeyVersionSummary AddKeyVersion(string? keyVersion, byte[]? signingKey, bool activate)
    {
        var resolvedKeyVersion = string.IsNullOrWhiteSpace(keyVersion)
            ? $"svcjwt-{DateTimeOffset.UtcNow:yyyyMMddHHmmss}"
            : keyVersion.Trim();
        var resolvedSigningKey = signingKey ?? RandomNumberGenerator.GetBytes(32);

        if (resolvedSigningKey.Length != 32)
        {
            throw new ArgumentException("MiniKMS internal JWT signing keys must be exactly 32 bytes.", nameof(signingKey));
        }

        lock (_sync)
        {
            if (_snapshot.KeyRecords.ContainsKey(resolvedKeyVersion))
            {
                throw new InvalidOperationException($"MiniKMS internal JWT key version '{resolvedKeyVersion}' already exists.");
            }

            var now = DateTimeOffset.UtcNow;
            _snapshot.KeyRecords[resolvedKeyVersion] = new MiniKmsInternalJwtKeyRecord(
                resolvedSigningKey.ToArray(),
                now,
                activate ? now : null,
                null);
            if (activate)
            {
                RetireCurrentActiveKey(now);
                _snapshot = _snapshot with { ActiveKeyVersion = resolvedKeyVersion };
            }

            SaveSnapshot();
            return new MiniKmsInternalJwtKeyVersionSummary(
                resolvedKeyVersion,
                activate ? "Active" : "Available",
                activate,
                now,
                activate ? now : null,
                null);
        }
    }

    public MiniKmsInternalJwtKeyVersionSummary ActivateKeyVersion(string keyVersion)
    {
        var resolvedKeyVersion = NormalizeKeyVersion(keyVersion);
        lock (_sync)
        {
            if (!_snapshot.KeyRecords.TryGetValue(resolvedKeyVersion, out var record))
            {
                throw new InvalidOperationException($"MiniKMS internal JWT key version '{resolvedKeyVersion}' does not exist.");
            }

            var now = DateTimeOffset.UtcNow;
            RetireCurrentActiveKey(now);
            _snapshot = _snapshot with { ActiveKeyVersion = resolvedKeyVersion };
            _snapshot.KeyRecords[resolvedKeyVersion] = record with
            {
                ActivatedAt = now,
                RetiredAt = null
            };
            SaveSnapshot();
            return new MiniKmsInternalJwtKeyVersionSummary(
                resolvedKeyVersion,
                "Active",
                true,
                record.CreatedAt,
                now,
                null);
        }
    }

    public MiniKmsInternalJwtKeyVersionSummary RetireKeyVersion(string keyVersion)
    {
        var resolvedKeyVersion = NormalizeKeyVersion(keyVersion);
        lock (_sync)
        {
            if (!_snapshot.KeyRecords.TryGetValue(resolvedKeyVersion, out var record))
            {
                throw new InvalidOperationException($"MiniKMS internal JWT key version '{resolvedKeyVersion}' does not exist.");
            }

            if (string.Equals(resolvedKeyVersion, _snapshot.ActiveKeyVersion, StringComparison.Ordinal))
            {
                throw new InvalidOperationException("The active MiniKMS internal JWT key version cannot be retired directly. Activate a replacement key first.");
            }

            var now = DateTimeOffset.UtcNow;
            _snapshot.KeyRecords[resolvedKeyVersion] = record with { RetiredAt = now };
            SaveSnapshot();
            return new MiniKmsInternalJwtKeyVersionSummary(
                resolvedKeyVersion,
                "Retired",
                false,
                record.CreatedAt,
                record.ActivatedAt,
                now);
        }
    }

    private static string NormalizeKeyVersion(string? keyVersion)
    {
        return string.IsNullOrWhiteSpace(keyVersion)
            ? throw new ArgumentException("A MiniKMS internal JWT key version is required.", nameof(keyVersion))
            : keyVersion.Trim();
    }

    private void RetireCurrentActiveKey(DateTimeOffset retiredAt)
    {
        if (_snapshot.KeyRecords.TryGetValue(_snapshot.ActiveKeyVersion, out var currentRecord))
        {
            _snapshot.KeyRecords[_snapshot.ActiveKeyVersion] = currentRecord with { RetiredAt = retiredAt };
        }
    }

    private string ResolveStatus(string keyVersion, MiniKmsInternalJwtKeyRecord record)
    {
        if (string.Equals(keyVersion, _snapshot.ActiveKeyVersion, StringComparison.Ordinal))
        {
            return "Active";
        }

        return record.RetiredAt.HasValue ? "Retired" : "Available";
    }

    private void SaveSnapshot()
    {
        _stateStore.Save(_snapshot);
    }
}
