using Microsoft.AspNetCore.Http.Json;
using Microsoft.Extensions.Options;
using MyCompany.AuthPlatform.Application;
using MyCompany.Security.MiniKms;
using MyCompany.Security.MiniKms.Client;

var builder = WebApplication.CreateBuilder(args);

builder.Services.Configure<JsonOptions>(_ => { });
builder.Services.Configure<MiniKmsServiceOptions>(
    builder.Configuration.GetSection(MiniKmsServiceOptions.SectionName));

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddSingleton<IMiniKmsStateStore>(serviceProvider =>
{
    var options = serviceProvider.GetRequiredService<IOptions<MiniKmsServiceOptions>>().Value;
    if (string.IsNullOrWhiteSpace(options.ServiceApiKey))
    {
        throw new InvalidOperationException("MiniKms:ServiceApiKey must be configured for the MiniKMS service.");
    }

    var keys = options.MasterKeys.ToDictionary(
        pair => pair.Key,
        pair => Convert.FromBase64String(pair.Value),
        StringComparer.Ordinal);
    var now = DateTimeOffset.UtcNow;
    var bootstrapSnapshot = new MiniKmsStateSnapshot(
        options.ActiveKeyVersion,
        keys.ToDictionary(
            pair => pair.Key,
            pair => new MiniKmsKeyRecord(
                pair.Value.ToArray(),
                now,
                string.Equals(pair.Key, options.ActiveKeyVersion, StringComparison.Ordinal) ? now : null,
                null),
            StringComparer.Ordinal),
        []);

    return options.DemoModeEnabled
        ? new InMemoryMiniKmsStateStore(bootstrapSnapshot)
        : new FileMiniKmsStateStore(options.StateFilePath, bootstrapSnapshot);
});
builder.Services.AddSingleton<IRotatingMasterKeyProvider, RotatingMasterKeyProvider>();
builder.Services.AddSingleton<IMasterKeyProvider>(serviceProvider =>
    serviceProvider.GetRequiredService<IRotatingMasterKeyProvider>());
builder.Services.AddSingleton<IMiniKms, LocalMiniKms>();
builder.Services.AddSingleton<IMiniKmsAuditLog>(serviceProvider =>
    (IMiniKmsAuditLog)serviceProvider.GetRequiredService<IRotatingMasterKeyProvider>());

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

var miniKms = app.Services.GetRequiredService<IMiniKms>();
var options = app.Services.GetRequiredService<IOptions<MiniKmsServiceOptions>>().Value;
var rotatingProvider = app.Services.GetRequiredService<IRotatingMasterKeyProvider>();
var auditLog = app.Services.GetRequiredService<IMiniKmsAuditLog>();

app.MapGet("/health", () =>
{
    return TypedResults.Ok(new MiniKmsHealthResponse(
        options.DemoModeEnabled ? "Healthy (Demo Mode)" : "Healthy",
        $"{miniKms.ProviderName}/{app.Services.GetRequiredService<IMiniKmsStateStore>().ProviderName}",
        miniKms.ActiveKeyVersion));
})
.WithName("GetMiniKmsHealth")
.WithOpenApi();

var internalApi = app.MapGroup("/internal/minikms");
internalApi.AddEndpointFilter(async (context, next) =>
{
    var configuredApiKey = options.ServiceApiKey?.Trim();
    var providedApiKey = context.HttpContext.Request.Headers[RemoteMiniKmsClient.ApiKeyHeaderName].ToString();

    if (string.IsNullOrWhiteSpace(configuredApiKey) ||
        !string.Equals(providedApiKey, configuredApiKey, StringComparison.Ordinal))
    {
        return Results.Json(
            new { errorCode = "minikms_forbidden", message = "A valid MiniKMS API key is required." },
            statusCode: StatusCodes.Status401Unauthorized);
    }

    return await next(context);
});

internalApi.MapPost("/generate-secret", (GenerateSecretRequest request, HttpContext httpContext) =>
{
    var secret = miniKms.GenerateRandomSecret(request.SizeInBytes);
    auditLog.Write(
        "GenerateSecret",
        "Success",
        ResolveActor(httpContext),
        miniKms.ActiveKeyVersion,
        $"Generated {request.SizeInBytes} bytes of secret material.");
    return TypedResults.Ok(new GenerateSecretResponse(
        Convert.ToBase64String(secret),
        miniKms.ActiveKeyVersion,
        miniKms.ProviderName));
})
.WithName("GenerateMiniKmsSecret")
.WithOpenApi();

internalApi.MapPost("/encrypt", (EncryptSecretRequest request, HttpContext httpContext) =>
{
    var plaintext = Convert.FromBase64String(request.PlaintextBase64);
    var package = miniKms.Encrypt(plaintext, request.KeyVersion);
    auditLog.Write(
        "EncryptSecret",
        "Success",
        ResolveActor(httpContext),
        package.KeyVersion,
        $"Encrypted {plaintext.Length} bytes of secret material.");
    return TypedResults.Ok(new EncryptSecretResponse(
        Convert.ToBase64String(package.EncryptedSecret),
        Convert.ToBase64String(package.EncryptedDataKey),
        package.KeyVersion,
        package.EncryptionAlgorithm,
        Convert.ToBase64String(package.Iv),
        Convert.ToBase64String(package.Tag),
        miniKms.ProviderName));
})
.WithName("EncryptMiniKmsSecret")
.WithOpenApi();

internalApi.MapPost("/decrypt", (DecryptSecretRequest request, HttpContext httpContext) =>
{
    var plaintext = miniKms.Decrypt(new EncryptedSecretPackage(
        Convert.FromBase64String(request.EncryptedSecretBase64),
        Convert.FromBase64String(request.EncryptedDataKeyBase64),
        request.KeyVersion,
        request.EncryptionAlgorithm,
        Convert.FromBase64String(request.IvBase64),
        Convert.FromBase64String(request.TagBase64)));
    auditLog.Write(
        "DecryptSecret",
        "Success",
        ResolveActor(httpContext),
        request.KeyVersion,
        $"Decrypted {plaintext.Length} bytes of secret material.");
    return TypedResults.Ok(new DecryptSecretResponse(
        Convert.ToBase64String(plaintext),
        request.KeyVersion,
        miniKms.ProviderName));
})
.WithName("DecryptMiniKmsSecret")
.WithOpenApi();

internalApi.MapGet("/keys", () =>
{
    return TypedResults.Ok(rotatingProvider.ListKeyVersions());
})
.WithName("ListMiniKmsKeys")
.WithOpenApi();

internalApi.MapGet("/audit", (int? take) =>
{
    return TypedResults.Ok(auditLog.List(take ?? 50));
})
.WithName("ListMiniKmsAudit")
.WithOpenApi();

internalApi.MapPost("/keys", (CreateKeyVersionRequest request, HttpContext httpContext) =>
{
    try
    {
        var keyMaterial = string.IsNullOrWhiteSpace(request.MasterKeyBase64)
            ? null
            : Convert.FromBase64String(request.MasterKeyBase64);
        var summary = rotatingProvider.AddKeyVersion(request.KeyVersion, keyMaterial, request.Activate);
        auditLog.Write(
            "CreateKeyVersion",
            "Success",
            ResolveActor(httpContext),
            summary.KeyVersion,
            summary.IsActive
                ? "Created and activated a new MiniKMS key version."
                : "Created a new MiniKMS key version.");
        return TypedResults.Ok(summary);
    }
    catch (FormatException)
    {
        return Results.Json(
            new { errorCode = "minikms_validation_error", message = "MasterKeyBase64 must be a valid base64 string when provided." },
            statusCode: StatusCodes.Status400BadRequest);
    }
    catch (ArgumentException exception)
    {
        auditLog.Write("CreateKeyVersion", "Rejected", ResolveActor(httpContext), request.KeyVersion, exception.Message);
        return Results.Json(
            new { errorCode = "minikms_validation_error", message = exception.Message },
            statusCode: StatusCodes.Status400BadRequest);
    }
    catch (InvalidOperationException exception)
    {
        auditLog.Write("CreateKeyVersion", "Rejected", ResolveActor(httpContext), request.KeyVersion, exception.Message);
        return Results.Json(
            new { errorCode = "minikms_conflict", message = exception.Message },
            statusCode: StatusCodes.Status409Conflict);
    }
})
.WithName("CreateMiniKmsKey")
.WithOpenApi();

internalApi.MapPost("/keys/{keyVersion}/activate", (string keyVersion, HttpContext httpContext) =>
{
    try
    {
        var summary = rotatingProvider.ActivateKeyVersion(keyVersion);
        auditLog.Write(
            "ActivateKeyVersion",
            "Success",
            ResolveActor(httpContext),
            summary.KeyVersion,
            "Activated a MiniKMS key version and soft-retired the previous active key.");
        return TypedResults.Ok(summary);
    }
    catch (ArgumentException exception)
    {
        auditLog.Write("ActivateKeyVersion", "Rejected", ResolveActor(httpContext), keyVersion, exception.Message);
        return Results.Json(
            new { errorCode = "minikms_validation_error", message = exception.Message },
            statusCode: StatusCodes.Status400BadRequest);
    }
    catch (InvalidOperationException exception)
    {
        auditLog.Write("ActivateKeyVersion", "Rejected", ResolveActor(httpContext), keyVersion, exception.Message);
        return Results.Json(
            new { errorCode = "minikms_not_found", message = exception.Message },
            statusCode: StatusCodes.Status404NotFound);
    }
})
.WithName("ActivateMiniKmsKey")
.WithOpenApi();

internalApi.MapPost("/keys/{keyVersion}/retire", (string keyVersion, HttpContext httpContext) =>
{
    try
    {
        var summary = rotatingProvider.RetireKeyVersion(keyVersion);
        auditLog.Write(
            "RetireKeyVersion",
            "Success",
            ResolveActor(httpContext),
            summary.KeyVersion,
            "Soft-retired a MiniKMS key version. The key remains available for decryption only.");
        return TypedResults.Ok(summary);
    }
    catch (ArgumentException exception)
    {
        auditLog.Write("RetireKeyVersion", "Rejected", ResolveActor(httpContext), keyVersion, exception.Message);
        return Results.Json(
            new { errorCode = "minikms_validation_error", message = exception.Message },
            statusCode: StatusCodes.Status400BadRequest);
    }
    catch (InvalidOperationException exception)
    {
        auditLog.Write("RetireKeyVersion", "Rejected", ResolveActor(httpContext), keyVersion, exception.Message);
        return Results.Json(
            new
            {
                errorCode = exception.Message.Contains("cannot be retired directly", StringComparison.OrdinalIgnoreCase)
                    ? "minikms_invalid_state"
                    : "minikms_not_found",
                message = exception.Message
            },
            statusCode: exception.Message.Contains("cannot be retired directly", StringComparison.OrdinalIgnoreCase)
                ? StatusCodes.Status409Conflict
                : StatusCodes.Status404NotFound);
    }
})
.WithName("RetireMiniKmsKey")
.WithOpenApi();

static string ResolveActor(HttpContext httpContext)
{
    var actor = httpContext.Request.Headers[RemoteMiniKmsClient.ActorHeaderName].ToString();
    return string.IsNullOrWhiteSpace(actor) ? "system" : actor.Trim();
}

app.Run();

public partial class Program
{
}
