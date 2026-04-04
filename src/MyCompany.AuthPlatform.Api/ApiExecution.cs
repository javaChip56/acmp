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
        var roleHeader = httpContext.Request.Headers["X-Demo-Role"].ToString();
        var role = ResolveRole(roleHeader);
        var actorHeader = httpContext.Request.Headers["X-Demo-Actor"].ToString();
        var actor = string.IsNullOrWhiteSpace(actorHeader)
            ? $"demo.{role.ToString().ToLowerInvariant()}"
            : actorHeader.Trim();
        var correlationId = httpContext.Request.Headers["X-Correlation-Id"].ToString();
        if (string.IsNullOrWhiteSpace(correlationId))
        {
            correlationId = $"demo-{Guid.NewGuid():N}";
        }

        return new AdminAccessContext(actor, role, correlationId);
    }

    private static AdminAccessRole ResolveRole(string? headerValue)
    {
        if (string.IsNullOrWhiteSpace(headerValue))
        {
            return AdminAccessRole.AccessViewer;
        }

        if (Enum.TryParse<AdminAccessRole>(headerValue.Trim(), ignoreCase: true, out var role))
        {
            return role;
        }

        throw new ApplicationServiceException(
            400,
            "invalid_demo_role",
            "The supplied X-Demo-Role header is invalid. Use AccessViewer, AccessOperator, or AccessAdministrator.");
    }
}
