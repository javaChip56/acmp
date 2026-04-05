using System.Security.Claims;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Http.Json;
using MyCompany.AuthPlatform.Hmac;
using MyCompany.AuthPlatform.Packaging;

var builder = WebApplication.CreateBuilder(args);

builder.Services.Configure<JsonOptions>(options =>
{
    options.SerializerOptions.Converters.Add(new JsonStringEnumConverter());
});

var validationOptions = builder.Configuration
    .GetSection("AcmpHmac:Validation")
    .Get<ServicePackageCacheOptions>()
    ?? throw new InvalidOperationException("AcmpHmac:Validation configuration is required.");

builder.Services.AddSingleton(validationOptions);
builder.Services.AddSingleton<IX509CertificateResolver, CompositeX509CertificateResolver>();
builder.Services.AddSingleton<IHmacCredentialPackageReader, X509HmacCredentialPackageReader>();
builder.Services.AddSingleton<EncryptedFileServiceCredentialStore>();
builder.Services.AddSingleton(serviceProvider =>
    new HmacRequestValidator(
        serviceProvider.GetRequiredService<EncryptedFileServiceCredentialStore>(),
        new HmacValidationOptions
        {
            AllowedClockSkew = TimeSpan.FromMinutes(5),
            RequireNonce = true
        }));

var app = builder.Build();

app.UseHttpsRedirection();

app.UseAcmpHmacValidation(new AcmpHmacValidationMiddlewareOptions
{
    RequiredScopeResolver = context =>
        context.Request.Path.StartsWithSegments("/api/orders", StringComparison.OrdinalIgnoreCase)
            ? "orders.write"
            : null
});

app.MapGet("/", () => Results.Redirect("/health"))
    .ExcludeFromDescription();

app.MapGet("/health", (ServicePackageCacheOptions options) => Results.Ok(new
{
    status = "Healthy",
    mode = "EncryptedFile",
    packageDirectory = options.PackageDirectory,
    preloadedKeyIds = options.PreloadKeyIds
}))
.WithName("GetHealth");

app.MapPost("/api/orders/create", (HttpContext httpContext, CreateOrderRequest request) =>
{
    var scopes = httpContext.User.FindAll("scope").Select(claim => claim.Value).ToArray();
    var keyId = httpContext.User.FindFirstValue("acmp:key_id");
    var keyVersion = httpContext.User.FindFirstValue("acmp:key_version");

    return Results.Ok(new
    {
        accepted = true,
        request.OrderId,
        request.Description,
        authentication = new
        {
            keyId,
            keyVersion,
            scopes
        }
    });
})
.WithName("CreateOrder");

app.Run();

internal sealed record CreateOrderRequest(int OrderId, string? Description);
