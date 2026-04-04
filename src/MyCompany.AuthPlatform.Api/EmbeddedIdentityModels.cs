namespace MyCompany.AuthPlatform.Api;

internal sealed record EmbeddedIdentityTokenRequest(
    string Username,
    string Password);

internal sealed record EmbeddedIdentityTokenResponse(
    string AccessToken,
    string TokenType,
    DateTimeOffset ExpiresAt,
    string Username,
    string DisplayName,
    IReadOnlyList<string> Roles);
