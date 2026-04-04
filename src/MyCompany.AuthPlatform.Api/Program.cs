using System.Text.Json.Serialization;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http.Json;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using MyCompany.AuthPlatform.Application;
using MyCompany.AuthPlatform.Api;
using MyCompany.AuthPlatform.Persistence.Abstractions;
using MyCompany.AuthPlatform.Persistence.InMemory;
using MyCompany.AuthPlatform.Persistence.SqlServer;

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
else if (string.Equals(authProviderOptions.Mode, AuthenticationModes.EmbeddedIdentity, StringComparison.OrdinalIgnoreCase))
{
    ValidateEmbeddedIdentityOptions(authProviderOptions.EmbeddedIdentity);
    authenticationBuilder.AddJwtBearer(options =>
    {
        ConfigureLocalJwtBearer(options, authProviderOptions.EmbeddedIdentity, "Provide a valid bearer token issued by the embedded identity provider.");
    });
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
        ConfigureBearerErrorResponses(options, "Provide a valid bearer token issued by the configured identity provider.");
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
builder.Services.AddScoped<IAuthPlatformUnitOfWork>(serviceProvider =>
{
    var persistenceOptions = serviceProvider.GetRequiredService<IOptions<PersistenceOptions>>().Value;
    if (string.Equals(persistenceOptions.Provider, PersistenceOptions.InMemoryDemoProvider, StringComparison.OrdinalIgnoreCase))
    {
        return new InMemoryAuthPlatformUnitOfWork(serviceProvider.GetRequiredService<InMemoryPersistenceState>());
    }

    throw new InvalidOperationException(
        $"Persistence provider '{persistenceOptions.Provider}' is not implemented. " +
        $"Use '{PersistenceOptions.InMemoryDemoProvider}' or '{PersistenceOptions.SqlServerProvider}'.");
});

if (string.Equals(builder.Configuration[$"{PersistenceOptions.SectionName}:Provider"], PersistenceOptions.SqlServerProvider, StringComparison.OrdinalIgnoreCase))
{
    builder.Services.AddAuthPlatformSqlServerPersistence(builder.Configuration);
}

builder.Services.AddScoped<DemoDataSeeder>();
builder.Services.AddScoped<AuthPlatformApplicationService>();
builder.Services.AddScoped<EmbeddedIdentityService>();

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
if (!string.Equals(persistence.Provider, PersistenceOptions.InMemoryDemoProvider, StringComparison.OrdinalIgnoreCase) &&
    !string.Equals(persistence.Provider, PersistenceOptions.SqlServerProvider, StringComparison.OrdinalIgnoreCase))
{
    throw new InvalidOperationException(
        $"Configured persistence provider '{persistence.Provider}' is not supported by the current host.");
}

if (string.Equals(persistence.Provider, PersistenceOptions.SqlServerProvider, StringComparison.OrdinalIgnoreCase))
{
    await app.Services.ApplyAuthPlatformSqlServerMigrationsAsync();
}

using (var scope = app.Services.CreateScope())
{
    await scope.ServiceProvider.GetRequiredService<DemoDataSeeder>().SeedAsync(app.Lifetime.ApplicationStopping);
}

app.MapGet("/", () => Results.Redirect("/swagger"))
    .ExcludeFromDescription();

app.MapGet("/health", (IOptions<PersistenceOptions> persistenceOptions) =>
{
    return TypedResults.Ok(new HealthResponse("Healthy", persistenceOptions.Value.Provider));
})
.WithName("GetHealth")
.WithOpenApi();

if (string.Equals(authProviderOptions.Mode, AuthenticationModes.EmbeddedIdentity, StringComparison.OrdinalIgnoreCase))
{
    app.MapPost("/api/auth/token", async (
        EmbeddedIdentityTokenRequest request,
        EmbeddedIdentityService service,
        CancellationToken cancellationToken) =>
    {
        try
        {
            return Results.Ok(await service.IssueTokenAsync(request, cancellationToken));
        }
        catch (ApplicationServiceException exception)
        {
            return Results.Json(
                new ApiErrorResponse(exception.ErrorCode, exception.Message),
                statusCode: exception.StatusCode);
        }
    })
    .AllowAnonymous()
    .WithName("IssueEmbeddedIdentityToken")
    .WithOpenApi();
}

app.MapGet("/api/system/info", (
    IOptions<PersistenceOptions> persistenceOptions,
    IOptions<DemoModeOptions> demoOptions) =>
{
    return TypedResults.Ok(new DemoSystemInfoResponse(
        AppName: "Authentication Credential Management Platform",
        Mode: string.Equals(persistenceOptions.Value.Provider, PersistenceOptions.InMemoryDemoProvider, StringComparison.OrdinalIgnoreCase)
            ? "Demo"
            : "Configured",
        PersistenceProvider: persistenceOptions.Value.Provider,
        SeedOnStartup: demoOptions.Value.SeedOnStartup,
        AuthenticationMode: authProviderOptions.Mode,
        Notes:
        [
            string.Equals(persistenceOptions.Value.Provider, PersistenceOptions.InMemoryDemoProvider, StringComparison.OrdinalIgnoreCase)
                ? "This host currently uses the demo-only in-memory persistence provider."
                : "This host currently uses the SQL Server persistence provider.",
            authProviderOptions.Mode == AuthenticationModes.DemoHeader
                ? "Demo authentication is implemented through an ASP.NET Core header-backed scheme using X-Demo-Role and X-Demo-Actor."
                : authProviderOptions.Mode == AuthenticationModes.EmbeddedIdentity
                    ? "Authentication is implemented through an embedded identity provider that issues local bearer tokens."
                    : "Authentication is implemented through JWT bearer tokens issued by the configured identity provider.",
            string.Equals(persistenceOptions.Value.Provider, PersistenceOptions.InMemoryDemoProvider, StringComparison.OrdinalIgnoreCase)
                ? "Restarting the process clears the in-memory demo data."
                : "SQL-backed data persists across application restarts."
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

app.MapGet("/api/admin/users", (
    HttpContext httpContext,
    AuthPlatformApplicationService service,
    CancellationToken cancellationToken) =>
    ApiExecution.ExecuteAsync(httpContext, async accessContext =>
        Results.Ok(await service.ListAdminUsersAsync(accessContext, cancellationToken))))
.WithName("ListAdminUsers")
.RequireAuthorization(AdminAccessPolicies.Administrator)
.WithOpenApi();

app.MapGet("/api/admin/users/{userId:guid}", (
    Guid userId,
    HttpContext httpContext,
    AuthPlatformApplicationService service,
    CancellationToken cancellationToken) =>
    ApiExecution.ExecuteAsync(httpContext, async accessContext =>
        Results.Ok(await service.GetAdminUserAsync(userId, accessContext, cancellationToken))))
.WithName("GetAdminUser")
.RequireAuthorization(AdminAccessPolicies.Administrator)
.WithOpenApi();

app.MapPost("/api/admin/users", (
    CreateAdminUserRequest request,
    HttpContext httpContext,
    AuthPlatformApplicationService service,
    CancellationToken cancellationToken) =>
    ApiExecution.ExecuteAsync(httpContext, async accessContext =>
    {
        var user = await service.CreateAdminUserAsync(request, accessContext, cancellationToken);
        return Results.Created($"/api/admin/users/{user.UserId}", user);
    }))
.WithName("CreateAdminUser")
.RequireAuthorization(AdminAccessPolicies.Administrator)
.WithOpenApi();

app.MapPost("/api/admin/users/{userId:guid}/disable", (
    Guid userId,
    DisableAdminUserRequest request,
    HttpContext httpContext,
    AuthPlatformApplicationService service,
    CancellationToken cancellationToken) =>
    ApiExecution.ExecuteAsync(httpContext, async accessContext =>
        Results.Ok(await service.DisableAdminUserAsync(userId, request, accessContext, cancellationToken))))
.WithName("DisableAdminUser")
.RequireAuthorization(AdminAccessPolicies.Administrator)
.WithOpenApi();

app.MapPost("/api/admin/users/{userId:guid}/reset-password", (
    Guid userId,
    ResetAdminUserPasswordRequest request,
    HttpContext httpContext,
    AuthPlatformApplicationService service,
    CancellationToken cancellationToken) =>
    ApiExecution.ExecuteAsync(httpContext, async accessContext =>
        Results.Ok(await service.ResetAdminUserPasswordAsync(userId, request, accessContext, cancellationToken))))
.WithName("ResetAdminUserPassword")
.RequireAuthorization(AdminAccessPolicies.Administrator)
.WithOpenApi();

app.MapPut("/api/admin/users/{userId:guid}/roles", (
    Guid userId,
    AssignAdminUserRolesRequest request,
    HttpContext httpContext,
    AuthPlatformApplicationService service,
    CancellationToken cancellationToken) =>
    ApiExecution.ExecuteAsync(httpContext, async accessContext =>
        Results.Ok(await service.AssignAdminUserRolesAsync(userId, request, accessContext, cancellationToken))))
.WithName("AssignAdminUserRoles")
.RequireAuthorization(AdminAccessPolicies.Administrator)
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
    if (string.Equals(options.Mode, AuthenticationModes.JwtBearer, StringComparison.OrdinalIgnoreCase) ||
        string.Equals(options.Mode, AuthenticationModes.EmbeddedIdentity, StringComparison.OrdinalIgnoreCase))
    {
        return JwtBearerDefaults.AuthenticationScheme;
    }

    return DemoAuthenticationDefaults.AuthenticationScheme;
}

static void ValidateEmbeddedIdentityOptions(EmbeddedIdentityAuthOptions options)
{
    if (string.IsNullOrWhiteSpace(options.Issuer))
    {
        throw new InvalidOperationException("Authentication:EmbeddedIdentity:Issuer must be configured when Authentication:Mode is EmbeddedIdentity.");
    }

    if (string.IsNullOrWhiteSpace(options.Audience))
    {
        throw new InvalidOperationException("Authentication:EmbeddedIdentity:Audience must be configured when Authentication:Mode is EmbeddedIdentity.");
    }

    if (string.IsNullOrWhiteSpace(options.SigningKey) || Encoding.UTF8.GetByteCount(options.SigningKey) < 32)
    {
        throw new InvalidOperationException("Authentication:EmbeddedIdentity:SigningKey must be configured and at least 32 bytes long when Authentication:Mode is EmbeddedIdentity.");
    }

}

static void ConfigureLocalJwtBearer(JwtBearerOptions options, EmbeddedIdentityAuthOptions embeddedIdentityOptions, string challengeMessage)
{
    options.MapInboundClaims = false;
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidIssuer = embeddedIdentityOptions.Issuer,
        ValidateAudience = true,
        ValidAudience = embeddedIdentityOptions.Audience,
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(embeddedIdentityOptions.SigningKey)),
        ValidateLifetime = true,
        ClockSkew = TimeSpan.FromMinutes(1),
        NameClaimType = ClaimTypes.Name,
        RoleClaimType = ClaimTypes.Role,
    };
    ConfigureBearerErrorResponses(options, challengeMessage);
}

static void ConfigureBearerErrorResponses(JwtBearerOptions options, string challengeMessage)
{
    options.Events = new JwtBearerEvents
    {
        OnChallenge = async context =>
        {
            context.HandleResponse();
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsJsonAsync(new ApiErrorResponse(
                "authentication_required",
                challengeMessage));
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
}
