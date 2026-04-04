using System.Security.Claims;
using MyCompany.AuthPlatform.Application;

namespace MyCompany.AuthPlatform.Api;

internal static class ApiExecution
{
    public static async Task<IResult> ExecuteAsync(
        HttpContext httpContext,
        Func<AdminAccessContext, Task<IResult>> action)
    {
        try
        {
            var accessContext = ResolveAccessContext(httpContext);
            return await action(accessContext);
        }
        catch (ApplicationServiceException exception)
        {
            return Results.Json(
                new ApiErrorResponse(exception.ErrorCode, exception.Message),
                statusCode: exception.StatusCode);
        }
    }

    private static AdminAccessContext ResolveAccessContext(HttpContext httpContext)
    {
        var roleValue = httpContext.User.FindFirstValue(AdminAccessDefaults.LocalRoleClaimType)
            ?? throw new ApplicationServiceException(401, "authentication_required", "An authenticated admin context is required.");
        if (!Enum.TryParse<AdminAccessRole>(roleValue, ignoreCase: true, out var role))
        {
            throw new ApplicationServiceException(401, "authentication_required", "The authenticated admin role is invalid.");
        }

        var actor = httpContext.User.Identity?.Name;
        if (string.IsNullOrWhiteSpace(actor))
        {
            actor = $"demo.{role.ToString().ToLowerInvariant()}";
        }

        var correlationId = httpContext.Request.Headers[AdminAccessDefaults.CorrelationIdHeaderName].ToString();
        if (string.IsNullOrWhiteSpace(correlationId))
        {
            correlationId = $"demo-{Guid.NewGuid():N}";
        }

        return new AdminAccessContext(actor, role, correlationId);
    }
}
