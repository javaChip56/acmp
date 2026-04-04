using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Http.Json;
using Microsoft.Extensions.Options;
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
            "Authentication and RBAC policies are defined in the docs but are not yet enforced by this demo host.",
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

app.MapGet("/api/clients", async (IAuthPlatformUnitOfWork unitOfWork, CancellationToken cancellationToken) =>
{
    var clients = await unitOfWork.ServiceClients.ListAsync(
        new ListServiceClientsRequest { Take = 100 },
        cancellationToken);

    var items = clients.Items.Select(client => new ServiceClientSummaryResponse(
        client.ClientId,
        client.ClientCode,
        client.ClientName,
        client.Owner,
        client.Environment,
        client.Status,
        client.Description,
        client.CreatedAt,
        client.UpdatedAt));

    return TypedResults.Ok(items);
})
.WithName("ListClients")
.WithOpenApi();

app.MapGet("/api/clients/{clientId:guid}/credentials", async (
    Guid clientId,
    IAuthPlatformUnitOfWork unitOfWork,
    CancellationToken cancellationToken) =>
{
    var client = await unitOfWork.ServiceClients.GetByIdAsync(clientId, cancellationToken);
    if (client is null)
    {
        return Results.NotFound(new { errorCode = "client_not_found", message = "The specified client could not be found." });
    }

    var credentials = await unitOfWork.Credentials.ListAsync(
        new ListCredentialsRequest { ClientId = clientId, Take = 100 },
        cancellationToken);

    var items = new List<CredentialSummaryResponse>();
    foreach (var credential in credentials.Items)
    {
        var scopes = await unitOfWork.CredentialScopes.ListByCredentialIdAsync(credential.CredentialId, cancellationToken);
        var hmacDetail = await unitOfWork.HmacCredentialDetails.GetByCredentialIdAsync(credential.CredentialId, cancellationToken);

        items.Add(new CredentialSummaryResponse(
            credential.CredentialId,
            credential.ClientId,
            credential.AuthenticationMode,
            credential.Status,
            credential.Environment,
            credential.ExpiresAt,
            credential.DisabledAt,
            credential.RevokedAt,
            credential.ReplacedByCredentialId,
            credential.RotationGraceEndsAt,
            credential.Notes,
            hmacDetail?.KeyId,
            hmacDetail?.KeyVersion,
            scopes.Select(scope => scope.ScopeName).OrderBy(scope => scope, StringComparer.Ordinal).ToArray(),
            credential.CreatedAt,
            credential.UpdatedAt));
    }

    return TypedResults.Ok(new ClientCredentialListResponse(
        client.ClientId,
        client.ClientCode,
        client.ClientName,
        items));
})
.WithName("ListClientCredentials")
.WithOpenApi();

app.MapGet("/api/audit", async (IAuthPlatformUnitOfWork unitOfWork, CancellationToken cancellationToken) =>
{
    var auditEntries = await unitOfWork.AuditLogs.ListAsync(
        new ListAuditLogEntriesRequest { Take = 200 },
        cancellationToken);

    var items = auditEntries.Items.Select(entry => new AuditLogResponse(
        entry.AuditId,
        entry.Timestamp,
        entry.Actor,
        entry.Action,
        entry.TargetType,
        entry.TargetId,
        entry.Environment,
        entry.Reason,
        entry.Outcome,
        entry.CorrelationId,
        entry.MetadataJson));

    return TypedResults.Ok(items);
})
.WithName("ListAuditLog")
.WithOpenApi();

app.Run();
