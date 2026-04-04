using System.Security.Claims;

namespace MyCompany.AuthPlatform.Api;

internal static class AuthenticationModes
{
    public const string DemoHeader = "DemoHeader";
    public const string EmbeddedIdentity = "EmbeddedIdentity";
    public const string JwtBearer = "JwtBearer";
}

internal sealed class AuthProviderOptions
{
    public const string SectionName = "Authentication";

    public string Mode { get; set; } = AuthenticationModes.DemoHeader;

    public EmbeddedIdentityAuthOptions EmbeddedIdentity { get; set; } = new();

    public JwtBearerAuthOptions JwtBearer { get; set; } = new();
}

internal sealed class EmbeddedIdentityAuthOptions
{
    public string Issuer { get; set; } = "acmp-embedded-identity";

    public string Audience { get; set; } = "acmp-api";

    public string SigningKey { get; set; } = "ReplaceThisEmbeddedIdentitySigningKey123!";

    public int AccessTokenLifetimeMinutes { get; set; } = 60;

    public List<EmbeddedIdentityUserOptions> Users { get; set; } = [];
}

internal sealed class EmbeddedIdentityUserOptions
{
    public string Username { get; set; } = string.Empty;

    public string Password { get; set; } = string.Empty;

    public string? DisplayName { get; set; }

    public List<string> Roles { get; set; } = [];
}

internal sealed class JwtBearerAuthOptions
{
    public string? Authority { get; set; }

    public string? Audience { get; set; }

    public bool RequireHttpsMetadata { get; set; } = true;

    public string NameClaimType { get; set; } = "name";

    public List<string> RoleClaimTypes { get; set; } =
    [
        "roles",
        "role",
        "groups",
        ClaimTypes.Role,
    ];

    public List<string> ViewerRoles { get; set; } =
    [
        "AccessViewer",
    ];

    public List<string> OperatorRoles { get; set; } =
    [
        "AccessOperator",
    ];

    public List<string> AdministratorRoles { get; set; } =
    [
        "AccessAdministrator",
    ];
}
