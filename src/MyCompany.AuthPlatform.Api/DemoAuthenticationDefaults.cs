namespace MyCompany.AuthPlatform.Api;

internal static class DemoAuthenticationDefaults
{
    public const string AuthenticationScheme = "DemoHeader";
    public const string RoleHeaderName = "X-Demo-Role";
    public const string ActorHeaderName = "X-Demo-Actor";
    public const string CorrelationIdHeaderName = "X-Correlation-Id";
    public const string RoleClaimType = "acmp_demo_role";
}
