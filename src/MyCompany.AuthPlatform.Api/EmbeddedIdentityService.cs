using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using MyCompany.AuthPlatform.Application;
using MyCompany.AuthPlatform.Persistence.Abstractions;
using MyCompany.Shared.Contracts.Domain;

namespace MyCompany.AuthPlatform.Api;

internal sealed class EmbeddedIdentityService
{
    private readonly IOptions<AuthProviderOptions> _options;
    private readonly IAuthPlatformUnitOfWork _unitOfWork;
    private readonly ILogger<EmbeddedIdentityService> _logger;

    public EmbeddedIdentityService(
        IOptions<AuthProviderOptions> options,
        IAuthPlatformUnitOfWork unitOfWork,
        ILogger<EmbeddedIdentityService> logger)
    {
        _options = options;
        _unitOfWork = unitOfWork;
        _logger = logger;
    }

    public async Task<EmbeddedIdentityTokenResponse> IssueTokenAsync(
        EmbeddedIdentityTokenRequest request,
        CancellationToken cancellationToken = default)
    {
        var options = _options.Value.EmbeddedIdentity;
        var username = request.Username?.Trim();
        var password = request.Password ?? string.Empty;
        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
        {
            throw new ApplicationServiceException(400, "validation_error", "'username' and 'password' are required.");
        }

        var user = await _unitOfWork.AdminUsers.GetByUsernameAsync(username, cancellationToken);
        if (user is null ||
            user.Status != AdminUserStatus.Active ||
            !AdminUserPasswordHasher.VerifyPassword(
                password,
                user.PasswordHash,
                user.PasswordSalt,
                user.PasswordIterations,
                user.PasswordHashAlgorithm))
        {
            _logger.LogInformation("Embedded identity login rejected for username {Username}.", username);
            throw new ApplicationServiceException(401, "invalid_credentials", "The supplied credentials are invalid.");
        }

        var roleAssignments = await _unitOfWork.AdminUserRoles.ListByUserIdAsync(user.UserId, cancellationToken);
        var roles = roleAssignments
            .Select(role => role.RoleName)
            .Where(role => !string.IsNullOrWhiteSpace(role))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        if (roles.Length == 0)
        {
            throw new ApplicationServiceException(403, "forbidden", "The persisted user does not have any roles assigned.");
        }

        var displayName = string.IsNullOrWhiteSpace(user.DisplayName) ? user.Username : user.DisplayName.Trim();
        var now = DateTimeOffset.UtcNow;
        var expiresAt = now.AddMinutes(Math.Max(options.AccessTokenLifetimeMinutes, 5));

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, user.Username),
            new(ClaimTypes.NameIdentifier, user.Username),
            new(ClaimTypes.Name, displayName),
            new("preferred_username", user.Username),
        };

        foreach (var role in roles)
        {
            claims.Add(new Claim(ClaimTypes.Role, role));
            claims.Add(new Claim(AdminAccessDefaults.LocalRoleClaimType, role));
        }

        var signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(options.SigningKey));
        var credentials = new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256);
        var token = new JwtSecurityToken(
            issuer: options.Issuer,
            audience: options.Audience,
            claims: claims,
            notBefore: now.UtcDateTime,
            expires: expiresAt.UtcDateTime,
            signingCredentials: credentials);

        var handler = new JwtSecurityTokenHandler();
        user.LastLoginAt = now;
        user.UpdatedAt = now;
        user.UpdatedBy = user.Username;
        await _unitOfWork.AdminUsers.UpdateAsync(user, cancellationToken);
        await _unitOfWork.SaveChangesAsync(cancellationToken);

        return new EmbeddedIdentityTokenResponse(
            AccessToken: handler.WriteToken(token),
            TokenType: "Bearer",
            ExpiresAt: expiresAt,
            Username: user.Username,
            DisplayName: displayName,
            Roles: roles);
    }
}
