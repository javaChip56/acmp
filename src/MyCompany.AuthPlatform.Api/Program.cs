using System.Text.Json.Serialization;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http.Json;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using MyCompany.AuthPlatform.Application;
using MyCompany.AuthPlatform.Api;
using MyCompany.AuthPlatform.Persistence.Abstractions;
using MyCompany.AuthPlatform.Persistence.InMemory;

var builder = WebApplication.CreateBuilder(args);

builder.Services.Configure<JsonOptions>(options =>
{
    options.SerializerOptions.Converters.Add(new JsonStringEnumConverter());
});

builder.Services.Configure<PersistenceOptions>(
    builder.Configuration.GetSection(PersistenceOptions.SectionName));
builder.Services.Configure<DemoModeOptions>(
    builder.Configuration.GetSection(DemoModeOptions.SectionName));
builder.Services.Configure<AuthProviderOptions>(
    builder.Configuration.GetSection(AuthProviderOptions.SectionName));

var authProviderOptions = builder.Configuration
    .GetSection(AuthProviderOptions.SectionName)
    .Get<AuthProviderOptions>()
    ?? new AuthProviderOptions();

var authenticationBuilder = builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = ResolveAuthenticationScheme(authProviderOptions);
    options.DefaultChallengeScheme = ResolveAuthenticationScheme(authProviderOptions);
});

if (string.Equals(authProviderOptions.Mode, AuthenticationModes.DemoHeader, StringComparison.OrdinalIgnoreCase))
{
    authenticationBuilder.AddScheme<AuthenticationSchemeOptions, DemoHeaderAuthenticationHandler>(
        DemoAuthenticationDefaults.AuthenticationScheme,
        _ => { });
}
else if (string.Equals(authProviderOptions.Mode, AuthenticationModes.JwtBearer, StringComparison.OrdinalIgnoreCase))
{
    var jwtOptions = authProviderOptions.JwtBearer;
    if (string.IsNullOrWhiteSpace(jwtOptions.Authority))
    {
        throw new InvalidOperationException("Authentication:JwtBearer:Authority must be configured when Authentication:Mode is JwtBearer.");
    }

    if (string.IsNullOrWhiteSpace(jwtOptions.Audience))
    {
        throw new InvalidOperationException("Authentication:JwtBearer:Audience must be configured when Authentication:Mode is JwtBearer.");
    }

    authenticationBuilder.AddJwtBearer(options =>
    {
        options.Authority = jwtOptions.Authority;
        options.Audience = jwtOptions.Audience;
        options.RequireHttpsMetadata = jwtOptions.RequireHttpsMetadata;
        options.MapInboundClaims = false;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            NameClaimType = jwtOptions.NameClaimType,
            RoleClaimType = ClaimTypes.Role,
        };
        options.Events = new JwtBearerEvents
        {
            OnChallenge = async context =>
            {
                context.HandleResponse();
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsJsonAsync(new ApiErrorResponse(
                    "authentication_required",
                    "Provide a valid bearer token issued by the configured identity provider."));
            },
            OnForbidden = async context =>
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsJsonAsync(new ApiErrorResponse(
                    "forbidden",
                    "The authenticated identity is not permitted to perform this action."));
            },
        };
    });
    builder.Services.AddTransient<AdminAccessClaimsTransformation>();
    builder.Services.AddTransient<IClaimsTransformation>(serviceProvider =>
        serviceProvider.GetRequiredService<AdminAccessClaimsTransformation>());
}
else
{
    throw new InvalidOperationException(
        $"Authentication mode '{authProviderOptions.Mode}' is not supported. Use '{AuthenticationModes.DemoHeader}' or '{AuthenticationModes.JwtBearer}'.");
}

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy(
        AdminAccessPolicies.Viewer,
        policy => policy.RequireRole(
            AdminAccessRole.AccessViewer.ToString(),
            AdminAccessRole.AccessOperator.ToString(),
            AdminAccessRole.AccessAdministrator.ToString()));
    options.AddPolicy(
        AdminAccessPolicies.Operator,
        policy => policy.RequireRole(
            AdminAccessRole.AccessOperator.ToString(),
            AdminAccessRole.AccessAdministrator.ToString()));
    options.AddPolicy(
        AdminAccessPolicies.Administrator,
        policy => policy.RequireRole(AdminAccessRole.AccessAdministrator.ToString()));
});

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddSingleton<InMemoryPersistenceState>();
builder.Services.AddSingleton<IAuthPlatformUnitOfWork>(serviceProvider =>
{
    var persistenceOptions = serviceProvider.GetRequiredService<IOptions<PersistenceOptions>>().Value;
    if (!string.Equals(persistenceOptions.Provider, PersistenceOptions.InMemoryDemoProvider, StringComparison.OrdinalIgnoreCase))
    {
        throw new InvalidOperationException(
            $"Persistence provider '{persistenceOptions.Provider}' is not implemented. " +
            $"Use '{PersistenceOptions.InMemoryDemoProvider}' to run the demo host.");
    }

    return new InMemoryAuthPlatformUnitOfWork(serviceProvider.GetRequiredService<InMemoryPersistenceState>());
});
builder.Services.AddSingleton<DemoDataSeeder>();
builder.Services.AddSingleton<AuthPlatformApplicationService>();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

var persistence = app.Services.GetRequiredService<IOptions<PersistenceOptions>>().Value;
if (!string.Equals(persistence.Provider, PersistenceOptions.InMemoryDemoProvider, StringComparison.OrdinalIgnoreCase))
{
    throw new InvalidOperationException(
        $"Configured persistence provider '{persistence.Provider}' is not supported by the current host.");
}

await app.Services.GetRequiredService<DemoDataSeeder>().SeedAsync(app.Lifetime.ApplicationStopping);

app.MapGet("/", () => Results.Redirect("/swagger"))
    .ExcludeFromDescription();

app.MapGet("/health", (IOptions<PersistenceOptions> persistenceOptions) =>
{
    return TypedResults.Ok(new HealthResponse("Healthy", persistenceOptions.Value.Provider));
})
.WithName("GetHealth")
.WithOpenApi();

app.MapGet("/api/system/info", (
    IOptions<PersistenceOptions> persistenceOptions,
    IOptions<DemoModeOptions> demoOptions) =>
{
    return TypedResults.Ok(new DemoSystemInfoResponse(
        AppName: "Authentication Credential Management Platform",
        Mode: "Demo",
        PersistenceProvider: persistenceOptions.Value.Provider,
        SeedOnStartup: demoOptions.Value.SeedOnStartup,
        AuthenticationMode: authProviderOptions.Mode,
        Notes:
        [
            "This host currently uses the demo-only in-memory persistence provider.",
            authProviderOptions.Mode == AuthenticationModes.DemoHeader
                ? "Demo authentication is implemented through an ASP.NET Core header-backed scheme using X-Demo-Role and X-Demo-Actor."
                : "Authentication is implemented through JWT bearer tokens issued by the configured identity provider.",
            "Restarting the process clears the in-memory demo data."
        ],
        SupportedRoles:
        [
            "AccessViewer",
            "AccessOperator",
            "AccessAdministrator"
        ]));
})
.WithName("GetSystemInfo")
.WithOpenApi();

app.MapGet("/api/clients", (
    HttpContext httpContext,
    AuthPlatformApplicationService service,
    CancellationToken cancellationToken) =>
    ApiExecution.ExecuteAsync(httpContext, async accessContext =>
        Results.Ok(await service.ListClientsAsync(accessContext, cancellationToken))))
.WithName("ListClients")
.RequireAuthorization(AdminAccessPolicies.Viewer)
.WithOpenApi();

app.MapGet("/api/clients/{clientId:guid}", (
    Guid clientId,
    HttpContext httpContext,
    AuthPlatformApplicationService service,
    CancellationToken cancellationToken) =>
    ApiExecution.ExecuteAsync(httpContext, async accessContext =>
        Results.Ok(await service.GetClientAsync(clientId, accessContext, cancellationToken))))
.WithName("GetClient")
.RequireAuthorization(AdminAccessPolicies.Viewer)
.WithOpenApi();

app.MapPost("/api/clients", (
    CreateServiceClientRequest request,
    HttpContext httpContext,
    AuthPlatformApplicationService service,
    CancellationToken cancellationToken) =>
    ApiExecution.ExecuteAsync(httpContext, async accessContext =>
    {
        var client = await service.CreateServiceClientAsync(request, accessContext, cancellationToken);
        return Results.Created($"/api/clients/{client.ClientId}", client);
    }))
.WithName("CreateClient")
.RequireAuthorization(AdminAccessPolicies.Operator)
.WithOpenApi();

app.MapGet("/api/clients/{clientId:guid}/credentials", (
    Guid clientId,
    HttpContext httpContext,
    AuthPlatformApplicationService service,
    CancellationToken cancellationToken) =>
    ApiExecution.ExecuteAsync(httpContext, async accessContext =>
        Results.Ok(await service.ListClientCredentialsAsync(clientId, accessContext, cancellationToken))))
.WithName("ListClientCredentials")
.RequireAuthorization(AdminAccessPolicies.Viewer)
.WithOpenApi();

app.MapPost("/api/clients/{clientId:guid}/credentials/hmac", (
    Guid clientId,
    IssueHmacCredentialRequest request,
    HttpContext httpContext,
    AuthPlatformApplicationService service,
    CancellationToken cancellationToken) =>
    ApiExecution.ExecuteAsync(httpContext, async accessContext =>
    {
        var credential = await service.IssueHmacCredentialAsync(clientId, request, accessContext, cancellationToken);
        return Results.Created($"/api/credentials/{credential.CredentialId}", credential);
    }))
.WithName("IssueHmacCredential")
.RequireAuthorization(AdminAccessPolicies.Operator)
.WithOpenApi();

app.MapGet("/api/credentials/{credentialId:guid}", (
    Guid credentialId,
    HttpContext httpContext,
    AuthPlatformApplicationService service,
    CancellationToken cancellationToken) =>
    ApiExecution.ExecuteAsync(httpContext, async accessContext =>
        Results.Ok(await service.GetCredentialAsync(credentialId, accessContext, cancellationToken))))
.WithName("GetCredential")
.RequireAuthorization(AdminAccessPolicies.Viewer)
.WithOpenApi();

app.MapPost("/api/credentials/{credentialId:guid}/rotate", (
    Guid credentialId,
    RotateHmacCredentialRequest request,
    HttpContext httpContext,
    AuthPlatformApplicationService service,
    CancellationToken cancellationToken) =>
    ApiExecution.ExecuteAsync(httpContext, async accessContext =>
        Results.Ok(await service.RotateHmacCredentialAsync(credentialId, accessContext: accessContext, request: request, cancellationToken: cancellationToken))))
.WithName("RotateCredential")
.RequireAuthorization(AdminAccessPolicies.Operator)
.WithOpenApi();

app.MapPost("/api/credentials/{credentialId:guid}/revoke", (
    Guid credentialId,
    RevokeCredentialRequest request,
    HttpContext httpContext,
    AuthPlatformApplicationService service,
    CancellationToken cancellationToken) =>
    ApiExecution.ExecuteAsync(httpContext, async accessContext =>
        Results.Ok(await service.RevokeCredentialAsync(credentialId, request, accessContext, cancellationToken))))
.WithName("RevokeCredential")
.RequireAuthorization(AdminAccessPolicies.Operator)
.WithOpenApi();

app.MapGet("/api/audit", (
    HttpContext httpContext,
    AuthPlatformApplicationService service,
    CancellationToken cancellationToken) =>
    ApiExecution.ExecuteAsync(httpContext, async accessContext =>
        Results.Ok(await service.ListAuditLogAsync(accessContext, cancellationToken))))
.WithName("ListAuditLog")
.RequireAuthorization(AdminAccessPolicies.Administrator)
.WithOpenApi();

app.Run();

static string ResolveAuthenticationScheme(AuthProviderOptions options)
{
    if (string.Equals(options.Mode, AuthenticationModes.JwtBearer, StringComparison.OrdinalIgnoreCase))
    {
        return JwtBearerDefaults.AuthenticationScheme;
    }

    return DemoAuthenticationDefaults.AuthenticationScheme;
}
