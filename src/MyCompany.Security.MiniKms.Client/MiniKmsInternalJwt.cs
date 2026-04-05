using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace MyCompany.Security.MiniKms.Client;

public sealed class MiniKmsInternalJwtOptions
{
    public string Issuer { get; set; } = "acmp-internal-services";

    public string Audience { get; set; } = "mini-kms-internal";

    public string SigningKey { get; set; } = "AcmpMiniKmsInternalSigningKey123456789!";

    public string Subject { get; set; } = "acmp-api";

    public int TokenLifetimeMinutes { get; set; } = 5;
}

public sealed class MiniKmsInternalJwtTokenProvider
{
    public const string ScopeClaimType = "scope";
    public const string RequiredScope = "minikms.internal";

    private readonly object _sync = new();
    private readonly MiniKmsInternalJwtOptions _options;
    private string? _cachedToken;
    private DateTimeOffset _cachedTokenExpiresAtUtc;

    public MiniKmsInternalJwtTokenProvider(MiniKmsInternalJwtOptions options)
    {
        _options = CloneAndValidate(options);
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

            _cachedToken = CreateToken(_options, out var expiresAtUtc);
            _cachedTokenExpiresAtUtc = expiresAtUtc;
            return _cachedToken;
        }
    }

    public static string CreateToken(MiniKmsInternalJwtOptions options, string? subjectOverride = null)
    {
        return CreateToken(options, out _, subjectOverride);
    }

    private static string CreateToken(
        MiniKmsInternalJwtOptions options,
        out DateTimeOffset expiresAtUtc,
        string? subjectOverride = null)
    {
        var resolvedOptions = CloneAndValidate(options);
        var subject = string.IsNullOrWhiteSpace(subjectOverride)
            ? resolvedOptions.Subject
            : subjectOverride.Trim();
        var now = DateTimeOffset.UtcNow;
        expiresAtUtc = now.AddMinutes(resolvedOptions.TokenLifetimeMinutes);
        var signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(resolvedOptions.SigningKey));
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

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    private static MiniKmsInternalJwtOptions CloneAndValidate(MiniKmsInternalJwtOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        var clone = new MiniKmsInternalJwtOptions
        {
            Issuer = options.Issuer?.Trim() ?? string.Empty,
            Audience = options.Audience?.Trim() ?? string.Empty,
            SigningKey = options.SigningKey ?? string.Empty,
            Subject = options.Subject?.Trim() ?? string.Empty,
            TokenLifetimeMinutes = options.TokenLifetimeMinutes
        };

        if (string.IsNullOrWhiteSpace(clone.Issuer))
        {
            throw new InvalidOperationException("MiniKMS internal JWT issuer must be configured.");
        }

        if (string.IsNullOrWhiteSpace(clone.Audience))
        {
            throw new InvalidOperationException("MiniKMS internal JWT audience must be configured.");
        }

        if (string.IsNullOrWhiteSpace(clone.SigningKey) || Encoding.UTF8.GetByteCount(clone.SigningKey) < 32)
        {
            throw new InvalidOperationException("MiniKMS internal JWT signing key must be configured and be at least 32 bytes long.");
        }

        if (string.IsNullOrWhiteSpace(clone.Subject))
        {
            throw new InvalidOperationException("MiniKMS internal JWT subject must be configured.");
        }

        if (clone.TokenLifetimeMinutes <= 0)
        {
            throw new InvalidOperationException("MiniKMS internal JWT token lifetime must be greater than zero.");
        }

        return clone;
    }
}
