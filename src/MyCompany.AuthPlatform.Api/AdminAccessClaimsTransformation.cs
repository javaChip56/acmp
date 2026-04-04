using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using MyCompany.AuthPlatform.Application;

namespace MyCompany.AuthPlatform.Api;

internal sealed class AdminAccessClaimsTransformation : IClaimsTransformation
{
    private readonly IOptions<AuthProviderOptions> _options;

    public AdminAccessClaimsTransformation(IOptions<AuthProviderOptions> options)
    {
        _options = options;
    }

    public Task<ClaimsPrincipal> TransformAsync(ClaimsPrincipal principal)
    {
        if (principal.Identity?.IsAuthenticated != true)
        {
            return Task.FromResult(principal);
        }

        if (principal.HasClaim(claim => claim.Type == AdminAccessDefaults.LocalRoleClaimType))
        {
            return Task.FromResult(principal);
        }

        var identity = principal.Identities.FirstOrDefault(current => current.IsAuthenticated);
        if (identity is null)
        {
            return Task.FromResult(principal);
        }

        var jwtOptions = _options.Value.JwtBearer;
        var roleClaimTypes = jwtOptions.RoleClaimTypes
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Distinct(StringComparer.Ordinal)
            .ToArray();

        var externalRoles = principal.Claims
            .Where(claim => roleClaimTypes.Contains(claim.Type, StringComparer.Ordinal))
            .Select(claim => claim.Value)
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        AppendLocalRole(identity, externalRoles, jwtOptions.ViewerRoles, AdminAccessRole.AccessViewer);
        AppendLocalRole(identity, externalRoles, jwtOptions.OperatorRoles, AdminAccessRole.AccessOperator);
        AppendLocalRole(identity, externalRoles, jwtOptions.AdministratorRoles, AdminAccessRole.AccessAdministrator);

        return Task.FromResult(principal);
    }

    private static void AppendLocalRole(
        ClaimsIdentity identity,
        IReadOnlyCollection<string> externalRoles,
        IReadOnlyCollection<string> mappedValues,
        AdminAccessRole localRole)
    {
        if (!externalRoles.Any(role => mappedValues.Contains(role, StringComparer.OrdinalIgnoreCase)))
        {
            return;
        }

        var roleValue = localRole.ToString();
        if (!identity.HasClaim(ClaimTypes.Role, roleValue))
        {
            identity.AddClaim(new Claim(ClaimTypes.Role, roleValue));
        }

        if (!identity.HasClaim(AdminAccessDefaults.LocalRoleClaimType, roleValue))
        {
            identity.AddClaim(new Claim(AdminAccessDefaults.LocalRoleClaimType, roleValue));
        }
    }
}
