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
builder.Services.AddSingleton<IRotatingMasterKeyProvider>(serviceProvider =>
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
    return new RotatingMasterKeyProvider(keys, options.ActiveKeyVersion);
});
builder.Services.AddSingleton<IMasterKeyProvider>(serviceProvider =>
    serviceProvider.GetRequiredService<IRotatingMasterKeyProvider>());
builder.Services.AddSingleton<IMiniKms, LocalMiniKms>();

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

app.MapGet("/health", () =>
{
    return TypedResults.Ok(new MiniKmsHealthResponse(
        "Healthy",
        miniKms.ProviderName,
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

internalApi.MapPost("/generate-secret", (GenerateSecretRequest request) =>
{
    var secret = miniKms.GenerateRandomSecret(request.SizeInBytes);
    return TypedResults.Ok(new GenerateSecretResponse(
        Convert.ToBase64String(secret),
        miniKms.ActiveKeyVersion,
        miniKms.ProviderName));
})
.WithName("GenerateMiniKmsSecret")
.WithOpenApi();

internalApi.MapPost("/encrypt", (EncryptSecretRequest request) =>
{
    var plaintext = Convert.FromBase64String(request.PlaintextBase64);
    var package = miniKms.Encrypt(plaintext, request.KeyVersion);
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

internalApi.MapPost("/decrypt", (DecryptSecretRequest request) =>
{
    var plaintext = miniKms.Decrypt(new EncryptedSecretPackage(
        Convert.FromBase64String(request.EncryptedSecretBase64),
        Convert.FromBase64String(request.EncryptedDataKeyBase64),
        request.KeyVersion,
        request.EncryptionAlgorithm,
        Convert.FromBase64String(request.IvBase64),
        Convert.FromBase64String(request.TagBase64)));
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

internalApi.MapPost("/keys", (CreateKeyVersionRequest request) =>
{
    try
    {
        var keyMaterial = string.IsNullOrWhiteSpace(request.MasterKeyBase64)
            ? null
            : Convert.FromBase64String(request.MasterKeyBase64);
        return TypedResults.Ok(rotatingProvider.AddKeyVersion(request.KeyVersion, keyMaterial, request.Activate));
    }
    catch (FormatException)
    {
        return Results.Json(
            new { errorCode = "minikms_validation_error", message = "MasterKeyBase64 must be a valid base64 string when provided." },
            statusCode: StatusCodes.Status400BadRequest);
    }
    catch (ArgumentException exception)
    {
        return Results.Json(
            new { errorCode = "minikms_validation_error", message = exception.Message },
            statusCode: StatusCodes.Status400BadRequest);
    }
    catch (InvalidOperationException exception)
    {
        return Results.Json(
            new { errorCode = "minikms_conflict", message = exception.Message },
            statusCode: StatusCodes.Status409Conflict);
    }
})
.WithName("CreateMiniKmsKey")
.WithOpenApi();

internalApi.MapPost("/keys/{keyVersion}/activate", (string keyVersion) =>
{
    try
    {
        return TypedResults.Ok(rotatingProvider.ActivateKeyVersion(keyVersion));
    }
    catch (ArgumentException exception)
    {
        return Results.Json(
            new { errorCode = "minikms_validation_error", message = exception.Message },
            statusCode: StatusCodes.Status400BadRequest);
    }
    catch (InvalidOperationException exception)
    {
        return Results.Json(
            new { errorCode = "minikms_not_found", message = exception.Message },
            statusCode: StatusCodes.Status404NotFound);
    }
})
.WithName("ActivateMiniKmsKey")
.WithOpenApi();

app.Run();

public partial class Program
{
}
