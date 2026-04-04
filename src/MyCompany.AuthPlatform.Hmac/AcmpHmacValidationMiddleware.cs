using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;

namespace MyCompany.AuthPlatform.Hmac;

public sealed class AcmpHmacValidationMiddlewareOptions
{
    public Func<HttpContext, string?>? RequiredScopeResolver { get; set; }

    public bool SkipWhenNoHmacHeaders { get; set; } = true;

    public string AuthenticationType { get; set; } = "AcmpHmac";
}

public sealed class AcmpHmacValidationMiddleware
{
    private static readonly string[] RequiredHeaderNames = ["X-Key-Id", "X-Timestamp", "X-Signature"];

    private readonly RequestDelegate _next;
    private readonly HmacRequestValidator _validator;
    private readonly AcmpHmacValidationMiddlewareOptions _options;

    public AcmpHmacValidationMiddleware(
        RequestDelegate next,
        HmacRequestValidator validator,
        AcmpHmacValidationMiddlewareOptions? options = null)
    {
        _next = next ?? throw new ArgumentNullException(nameof(next));
        _validator = validator ?? throw new ArgumentNullException(nameof(validator));
        _options = options ?? new AcmpHmacValidationMiddlewareOptions();
    }

    public async Task InvokeAsync(HttpContext context)
    {
        if (_options.SkipWhenNoHmacHeaders && RequiredHeaderNames.All(header => !context.Request.Headers.ContainsKey(header)))
        {
            await _next(context);
            return;
        }

        context.Request.EnableBuffering();
        byte[] body;
        await using (var bodyStream = new MemoryStream())
        {
            await context.Request.Body.CopyToAsync(bodyStream, context.RequestAborted);
            body = bodyStream.ToArray();
        }

        context.Request.Body.Position = 0;
        var validationResult = await _validator.ValidateAsync(
            new HmacValidationRequest(
                context.Request.Method,
                context.Request.Path.Value ?? "/",
                context.Request.QueryString.HasValue ? context.Request.QueryString.Value : null,
                body,
                null,
                new HmacSignatureHeaders(
                    context.Request.Headers["X-Key-Id"].ToString(),
                    context.Request.Headers["X-Signature"].ToString(),
                    context.Request.Headers["X-Timestamp"].ToString(),
                    context.Request.Headers["X-Nonce"].ToString())),
            _options.RequiredScopeResolver?.Invoke(context),
            context.RequestAborted);

        if (!validationResult.IsValid)
        {
            context.Response.StatusCode = string.Equals(validationResult.FailureCode, "insufficient_scope", StringComparison.Ordinal)
                ? StatusCodes.Status403Forbidden
                : StatusCodes.Status401Unauthorized;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync(JsonSerializer.Serialize(new
            {
                errorCode = validationResult.FailureCode,
                message = validationResult.FailureMessage
            }), context.RequestAborted);
            return;
        }

        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, validationResult.CredentialId?.ToString() ?? string.Empty),
            new("acmp:key_id", validationResult.KeyId ?? string.Empty),
            new("acmp:key_version", validationResult.KeyVersion ?? string.Empty)
        };
        claims.AddRange(validationResult.Scopes.Select(scope => new Claim("scope", scope)));

        context.User = new ClaimsPrincipal(new ClaimsIdentity(claims, _options.AuthenticationType));
        await _next(context);
    }
}

public static class AcmpHmacValidationMiddlewareExtensions
{
    public static IApplicationBuilder UseAcmpHmacValidation(
        this IApplicationBuilder app,
        AcmpHmacValidationMiddlewareOptions? options = null)
    {
        return app.UseMiddleware<AcmpHmacValidationMiddleware>(options ?? new AcmpHmacValidationMiddlewareOptions());
    }
}
