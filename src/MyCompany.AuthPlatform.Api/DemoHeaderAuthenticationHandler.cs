using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using MyCompany.AuthPlatform.Application;

namespace MyCompany.AuthPlatform.Api;

internal sealed class DemoHeaderAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    public DemoHeaderAuthenticationHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder)
        : base(options, logger, encoder)
    {
    }

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var roleHeader = Request.Headers[DemoAuthenticationDefaults.RoleHeaderName].ToString();
        var role = ResolveRole(roleHeader);
        if (role is null)
        {
            return Task.FromResult(AuthenticateResult.Fail(
                $"The supplied {DemoAuthenticationDefaults.RoleHeaderName} header is invalid."));
        }

        var actorHeader = Request.Headers[DemoAuthenticationDefaults.ActorHeaderName].ToString();
        var actor = string.IsNullOrWhiteSpace(actorHeader)
            ? $"demo.{role.Value.ToString().ToLowerInvariant()}"
            : actorHeader.Trim();

        var claims = new[]
        {
            new Claim(ClaimTypes.Name, actor),
            new Claim(ClaimTypes.NameIdentifier, actor),
            new Claim(ClaimTypes.Role, role.Value.ToString()),
            new Claim(DemoAuthenticationDefaults.RoleClaimType, role.Value.ToString()),
        };

        var identity = new ClaimsIdentity(claims, DemoAuthenticationDefaults.AuthenticationScheme);
        var principal = new ClaimsPrincipal(identity);
        var ticket = new AuthenticationTicket(principal, DemoAuthenticationDefaults.AuthenticationScheme);
        return Task.FromResult(AuthenticateResult.Success(ticket));
    }

    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        Response.StatusCode = StatusCodes.Status401Unauthorized;
        Response.ContentType = "application/json";
        return Response.WriteAsJsonAsync(new ApiErrorResponse(
            "authentication_required",
            $"Provide a valid {DemoAuthenticationDefaults.RoleHeaderName} header using AccessViewer, AccessOperator, or AccessAdministrator."));
    }

    protected override Task HandleForbiddenAsync(AuthenticationProperties properties)
    {
        Response.StatusCode = StatusCodes.Status403Forbidden;
        Response.ContentType = "application/json";
        return Response.WriteAsJsonAsync(new ApiErrorResponse(
            "forbidden",
            "The current role is not permitted to perform this action."));
    }

    private static AdminAccessRole? ResolveRole(string? headerValue)
    {
        if (string.IsNullOrWhiteSpace(headerValue))
        {
            return AdminAccessRole.AccessViewer;
        }

        if (Enum.TryParse<AdminAccessRole>(headerValue.Trim(), ignoreCase: true, out var role))
        {
            return role;
        }

        return null;
    }
}
