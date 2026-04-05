using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace MyCompany.Security.MiniKms.Client;

public sealed class MiniKmsInternalJwtOptions
{
    public const string ConfigSource = "Config";
    public const string ManagedStateSource = "MiniKmsState";

    public string KeySource { get; set; } = ManagedStateSource;

    public string Issuer { get; set; } = "acmp-internal-services";

    public string Audience { get; set; } = "mini-kms-internal";

    public string ActiveKeyVersion { get; set; } = "svcjwt-v1";

    public string SigningKey { get; set; } = string.Empty;

    public string Subject { get; set; } = "acmp-api";

    public int TokenLifetimeMinutes { get; set; } = 5;

    public MiniKmsInternalJwtManagedStateOptions ManagedState { get; set; } = new();
}

public sealed class MiniKmsInternalJwtTokenProvider
{
    public const string ScopeClaimType = "scope";
    public const string RequiredScope = "minikms.internal";

    private readonly object _sync = new();
    private readonly MiniKmsInternalJwtOptions _options;
    private readonly IMiniKmsInternalJwtKeyStateStore? _managedStateStore;
    private string? _cachedToken;
    private DateTimeOffset _cachedTokenExpiresAtUtc;
    private string? _cachedKeyVersion;
    private byte[]? _cachedSigningKey;

    public MiniKmsInternalJwtTokenProvider(MiniKmsInternalJwtOptions options)
    {
        _options = CloneAndValidate(options);
        if (string.Equals(_options.KeySource, MiniKmsInternalJwtOptions.ManagedStateSource, StringComparison.OrdinalIgnoreCase))
        {
            _managedStateStore = MiniKmsInternalJwtStateStoreFactory.Create(
                _options.ManagedState,
                MiniKmsInternalJwtStateStoreFactory.CreateBootstrapSnapshot(
                    _options.ActiveKeyVersion,
                    TryResolveBootstrapSigningKey(_options.SigningKey)));
        }
    }

    public string Actor => _options.Subject;

    public string GetAccessToken()
    {
        lock (_sync)
        {
            if (!string.IsNullOrWhiteSpace(_cachedToken) &&
                _cachedTokenExpiresAtUtc > DateTimeOffset.UtcNow.AddSeconds(30))
            {
                return _cachedToken;
            }

            _cachedToken = CreateToken(_options, ResolveSigningKey, out var expiresAtUtc);
            _cachedTokenExpiresAtUtc = expiresAtUtc;
            return _cachedToken;
        }
    }

    public static string CreateToken(MiniKmsInternalJwtOptions options, string? subjectOverride = null)
    {
        var resolvedOptions = CloneAndValidate(options);
        Func<(string KeyVersion, byte[] SigningKey)> resolver;
        if (string.Equals(resolvedOptions.KeySource, MiniKmsInternalJwtOptions.ManagedStateSource, StringComparison.OrdinalIgnoreCase))
        {
            var stateStore = MiniKmsInternalJwtStateStoreFactory.Create(
                resolvedOptions.ManagedState,
                MiniKmsInternalJwtStateStoreFactory.CreateBootstrapSnapshot(
                    resolvedOptions.ActiveKeyVersion,
                    TryResolveBootstrapSigningKey(resolvedOptions.SigningKey)));
            resolver = () =>
            {
                var snapshot = stateStore.Load();
                if (!snapshot.KeyRecords.TryGetValue(snapshot.ActiveKeyVersion, out var keyRecord))
                {
                    throw new InvalidOperationException($"MiniKMS internal JWT key version '{snapshot.ActiveKeyVersion}' does not exist in the managed state store.");
                }

                return (snapshot.ActiveKeyVersion, keyRecord.SigningKey.ToArray());
            };
        }
        else
        {
            resolver = () => ResolveSigningKeyStatic(resolvedOptions);
        }

        return CreateToken(
            resolvedOptions,
            resolver,
            out _,
            subjectOverride);
    }

    private static string CreateToken(
        MiniKmsInternalJwtOptions options,
        Func<(string KeyVersion, byte[] SigningKey)> signingKeyResolver,
        out DateTimeOffset expiresAtUtc,
        string? subjectOverride = null)
    {
        var resolvedOptions = options;
        var subject = string.IsNullOrWhiteSpace(subjectOverride)
            ? resolvedOptions.Subject
            : subjectOverride.Trim();
        var now = DateTimeOffset.UtcNow;
        expiresAtUtc = now.AddMinutes(resolvedOptions.TokenLifetimeMinutes);
        var (keyVersion, signingKeyBytes) = signingKeyResolver();
        var signingKey = new SymmetricSecurityKey(signingKeyBytes);
        var credentials = new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256);
        var token = new JwtSecurityToken(
            issuer: resolvedOptions.Issuer,
            audience: resolvedOptions.Audience,
            claims:
            [
                new Claim(JwtRegisteredClaimNames.Sub, subject),
                new Claim(ScopeClaimType, RequiredScope),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N"))
            ],
            notBefore: now.UtcDateTime,
            expires: expiresAtUtc.UtcDateTime,
            signingCredentials: credentials);
        token.Header["kid"] = keyVersion;

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    private (string KeyVersion, byte[] SigningKey) ResolveSigningKey()
    {
        if (_managedStateStore is null)
        {
            return ResolveSigningKeyStatic(_options);
        }

        var snapshot = _managedStateStore.Load();
        if (!_cachedKeyVersion?.Equals(snapshot.ActiveKeyVersion, StringComparison.Ordinal) ?? true)
        {
            if (!snapshot.KeyRecords.TryGetValue(snapshot.ActiveKeyVersion, out var keyRecord))
            {
                throw new InvalidOperationException($"MiniKMS internal JWT key version '{snapshot.ActiveKeyVersion}' does not exist in the managed state store.");
            }

            _cachedKeyVersion = snapshot.ActiveKeyVersion;
            _cachedSigningKey = keyRecord.SigningKey.ToArray();
        }

        return (_cachedKeyVersion!, _cachedSigningKey!.ToArray());
    }

    private static (string KeyVersion, byte[] SigningKey) ResolveSigningKeyStatic(MiniKmsInternalJwtOptions options)
    {
        if (string.IsNullOrWhiteSpace(options.SigningKey))
        {
            throw new InvalidOperationException("MiniKMS internal JWT signing key must be configured when KeySource is Config.");
        }

        return (options.ActiveKeyVersion, Encoding.UTF8.GetBytes(options.SigningKey));
    }

    private static byte[]? TryResolveBootstrapSigningKey(string? signingKey)
    {
        if (string.IsNullOrWhiteSpace(signingKey))
        {
            return null;
        }

        try
        {
            return Convert.FromBase64String(signingKey);
        }
        catch (FormatException)
        {
            return Encoding.UTF8.GetBytes(signingKey);
        }
    }

    private static MiniKmsInternalJwtOptions CloneAndValidate(MiniKmsInternalJwtOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        var clone = new MiniKmsInternalJwtOptions
        {
            KeySource = options.KeySource?.Trim() ?? string.Empty,
            Issuer = options.Issuer?.Trim() ?? string.Empty,
            Audience = options.Audience?.Trim() ?? string.Empty,
            SigningKey = options.SigningKey ?? string.Empty,
            ActiveKeyVersion = options.ActiveKeyVersion?.Trim() ?? string.Empty,
            Subject = options.Subject?.Trim() ?? string.Empty,
            TokenLifetimeMinutes = options.TokenLifetimeMinutes,
            ManagedState = new MiniKmsInternalJwtManagedStateOptions
            {
                Provider = options.ManagedState.Provider?.Trim() ?? string.Empty,
                StateFilePath = options.ManagedState.StateFilePath ?? string.Empty,
                SqlServer = new MiniKmsInternalJwtManagedSqlServerOptions
                {
                    ConnectionString = options.ManagedState.SqlServer.ConnectionString ?? string.Empty
                },
                Postgres = new MiniKmsInternalJwtManagedPostgresOptions
                {
                    ConnectionString = options.ManagedState.Postgres.ConnectionString ?? string.Empty
                }
            }
        };

        if (string.IsNullOrWhiteSpace(clone.KeySource))
        {
            throw new InvalidOperationException("MiniKMS internal JWT key source must be configured.");
        }

        if (string.IsNullOrWhiteSpace(clone.Issuer))
        {
            throw new InvalidOperationException("MiniKMS internal JWT issuer must be configured.");
        }

        if (string.IsNullOrWhiteSpace(clone.Audience))
        {
            throw new InvalidOperationException("MiniKMS internal JWT audience must be configured.");
        }

        if (clone.TokenLifetimeMinutes <= 0)
        {
            throw new InvalidOperationException("MiniKMS internal JWT token lifetime must be greater than zero.");
        }

        if (string.IsNullOrWhiteSpace(clone.Subject))
        {
            throw new InvalidOperationException("MiniKMS internal JWT subject must be configured.");
        }

        if (string.Equals(clone.KeySource, MiniKmsInternalJwtOptions.ConfigSource, StringComparison.OrdinalIgnoreCase))
        {
            if (string.IsNullOrWhiteSpace(clone.ActiveKeyVersion))
            {
                throw new InvalidOperationException("MiniKMS internal JWT active key version must be configured when KeySource is Config.");
            }

            if (string.IsNullOrWhiteSpace(clone.SigningKey) || Encoding.UTF8.GetByteCount(clone.SigningKey) < 32)
            {
                throw new InvalidOperationException("MiniKMS internal JWT signing key must be configured and be at least 32 bytes long when KeySource is Config.");
            }

            return clone;
        }

        if (!string.Equals(clone.KeySource, MiniKmsInternalJwtOptions.ManagedStateSource, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("MiniKMS internal JWT key source must be either 'Config' or 'MiniKmsState'.");
        }

        if (string.IsNullOrWhiteSpace(clone.ActiveKeyVersion))
        {
            clone.ActiveKeyVersion = "svcjwt-v1";
        }

        return clone;
    }
}
