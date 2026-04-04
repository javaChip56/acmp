using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Http.Json;
using Microsoft.Extensions.Options;
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
        Notes:
        [
            "This host currently uses the demo-only in-memory persistence provider.",
            "Demo authorization is driven by the X-Demo-Role and X-Demo-Actor headers until full authentication is implemented.",
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
.WithOpenApi();

app.MapGet("/api/clients/{clientId:guid}", (
    Guid clientId,
    HttpContext httpContext,
    AuthPlatformApplicationService service,
    CancellationToken cancellationToken) =>
    ApiExecution.ExecuteAsync(httpContext, async accessContext =>
        Results.Ok(await service.GetClientAsync(clientId, accessContext, cancellationToken))))
.WithName("GetClient")
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
.WithOpenApi();

app.MapGet("/api/clients/{clientId:guid}/credentials", (
    Guid clientId,
    HttpContext httpContext,
    AuthPlatformApplicationService service,
    CancellationToken cancellationToken) =>
    ApiExecution.ExecuteAsync(httpContext, async accessContext =>
        Results.Ok(await service.ListClientCredentialsAsync(clientId, accessContext, cancellationToken))))
.WithName("ListClientCredentials")
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
.WithOpenApi();

app.MapGet("/api/credentials/{credentialId:guid}", (
    Guid credentialId,
    HttpContext httpContext,
    AuthPlatformApplicationService service,
    CancellationToken cancellationToken) =>
    ApiExecution.ExecuteAsync(httpContext, async accessContext =>
        Results.Ok(await service.GetCredentialAsync(credentialId, accessContext, cancellationToken))))
.WithName("GetCredential")
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
.WithOpenApi();

app.MapGet("/api/audit", (
    HttpContext httpContext,
    AuthPlatformApplicationService service,
    CancellationToken cancellationToken) =>
    ApiExecution.ExecuteAsync(httpContext, async accessContext =>
        Results.Ok(await service.ListAuditLogAsync(accessContext, cancellationToken))))
.WithName("ListAuditLog")
.WithOpenApi();

app.Run();
