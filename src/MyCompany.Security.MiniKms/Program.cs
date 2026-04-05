using System.Security.Claims;
using System.Text;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http.Json;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using MyCompany.AuthPlatform.Application;
using MyCompany.Security.MiniKms;
using MyCompany.Security.MiniKms.Client;

var builder = WebApplication.CreateBuilder(args);

builder.Services.Configure<JsonOptions>(_ => { });
builder.Services.Configure<MiniKmsServiceOptions>(
    builder.Configuration.GetSection(MiniKmsServiceOptions.SectionName));

var configuredOptions = builder.Configuration
    .GetSection(MiniKmsServiceOptions.SectionName)
    .Get<MiniKmsServiceOptions>()
    ?? new MiniKmsServiceOptions();

ValidateMiniKmsInternalJwtOptions(configuredOptions.InternalJwt);

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.MapInboundClaims = false;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = configuredOptions.InternalJwt.Issuer,
            ValidateAudience = true,
            ValidAudience = configuredOptions.InternalJwt.Audience,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuredOptions.InternalJwt.SigningKey)),
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromMinutes(1),
            NameClaimType = JwtRegisteredClaimNames.Sub,
        };
        options.Events = new JwtBearerEvents
        {
            OnChallenge = async context =>
            {
                context.HandleResponse();
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsJsonAsync(new
                {
                    errorCode = "minikms_authentication_required",
                    message = "A valid internal bearer token is required."
                });
            },
            OnForbidden = async context =>
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsJsonAsync(new
                {
                    errorCode = "minikms_forbidden",
                    message = "The bearer token is not permitted to access MiniKMS internal endpoints."
                });
            }
        };
    });
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("MiniKmsInternalApi", policy =>
    {
        policy.RequireAuthenticatedUser();
        policy.RequireClaim(
            MiniKmsInternalJwtTokenProvider.ScopeClaimType,
            MiniKmsInternalJwtTokenProvider.RequiredScope);
    });
});

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddSingleton<IMiniKmsStateStore>(serviceProvider =>
{
    var options = serviceProvider.GetRequiredService<IOptions<MiniKmsServiceOptions>>().Value;

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

    if (options.DemoModeEnabled)
    {
        return new InMemoryMiniKmsStateStore(bootstrapSnapshot);
    }

    if (string.Equals(options.PersistenceProvider, MiniKmsServiceOptions.FileProvider, StringComparison.OrdinalIgnoreCase))
    {
        return new FileMiniKmsStateStore(options.StateFilePath, bootstrapSnapshot);
    }

    if (string.Equals(options.PersistenceProvider, MiniKmsServiceOptions.SqlServerProvider, StringComparison.OrdinalIgnoreCase))
    {
        return new SqlServerMiniKmsStateStore(options.SqlServer.ConnectionString, bootstrapSnapshot);
    }

    if (string.Equals(options.PersistenceProvider, MiniKmsServiceOptions.PostgresProvider, StringComparison.OrdinalIgnoreCase))
    {
        return new PostgresMiniKmsStateStore(options.Postgres.ConnectionString, bootstrapSnapshot);
    }

    throw new InvalidOperationException(
        $"MiniKms:PersistenceProvider '{options.PersistenceProvider}' is not supported. " +
        $"Use '{MiniKmsServiceOptions.FileProvider}', '{MiniKmsServiceOptions.SqlServerProvider}', '{MiniKmsServiceOptions.PostgresProvider}', or enable demo mode.");
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
app.UseAuthentication();
app.UseAuthorization();

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
internalApi.RequireAuthorization("MiniKmsInternalApi");

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
    var actor = httpContext.User.FindFirstValue(JwtRegisteredClaimNames.Sub) ??
        httpContext.User.FindFirstValue(ClaimTypes.NameIdentifier) ??
        httpContext.User.Identity?.Name;
    return string.IsNullOrWhiteSpace(actor) ? "system" : actor.Trim();
}

static void ValidateMiniKmsInternalJwtOptions(MiniKmsInternalJwtOptions options)
{
    if (string.IsNullOrWhiteSpace(options.Issuer))
    {
        throw new InvalidOperationException("MiniKms:InternalJwt:Issuer must be configured for the MiniKMS service.");
    }

    if (string.IsNullOrWhiteSpace(options.Audience))
    {
        throw new InvalidOperationException("MiniKms:InternalJwt:Audience must be configured for the MiniKMS service.");
    }

    if (string.IsNullOrWhiteSpace(options.SigningKey) || Encoding.UTF8.GetByteCount(options.SigningKey) < 32)
    {
        throw new InvalidOperationException("MiniKms:InternalJwt:SigningKey must be configured and be at least 32 bytes long for the MiniKMS service.");
    }
}

app.Run();

public partial class Program
{
}
