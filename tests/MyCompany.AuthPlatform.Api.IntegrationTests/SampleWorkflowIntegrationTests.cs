using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using MyCompany.AuthPlatform.Api;
using MyCompany.AuthPlatform.Hmac;
using MyCompany.AuthPlatform.Hmac.Client;
using MyCompany.AuthPlatform.Packaging;
using Xunit;

namespace MyCompany.AuthPlatform.Api.IntegrationTests;

public sealed class SampleWorkflowIntegrationTests
{
    private static readonly Guid SeededOrdersClientId = Guid.Parse("1f4a8ec5-31f6-4df8-8b7d-6c22f4f9d0a1");
    private static readonly Guid SeededActiveCredentialId = Guid.Parse("bd0dd9fc-90d2-4dc8-a99e-5f5d65d8b041");

    [Fact]
    public async Task ManagementApi_IssuedPackages_WorkEndToEndWithSampleConfigurations()
    {
        using var tempDirectory = new TemporaryDirectory();
        using var rsa = RSA.Create(3072);
        using var factory = new SampleWorkflowApiFactory();
        using var managementClient = factory.CreateClient();
        var operatorToken = await IssueTokenAsync(managementClient, "operator.demo", "OperatorPass!123");
        var publicKeyPem = rsa.ExportSubjectPublicKeyInfoPem();
        var publicKeyFingerprint = ComputePublicKeyFingerprint(rsa);
        var privateKeyPath = Path.Combine(tempDirectory.Path, "recipient-private-key.pem");
        await File.WriteAllTextAsync(privateKeyPath, rsa.ExportPkcs8PrivateKeyPem());

        var createBindingResponse = await SendAuthorizedPostAsync(
            managementClient,
            $"/api/clients/{SeededOrdersClientId}/recipient-bindings",
            new
            {
                bindingName = "orders-api-prod-rsa-2026q2",
                bindingType = "ExternalRsaPublicKey",
                algorithm = "RSA-3072",
                publicKeyPem,
                certificateThumbprint = (string?)null,
                storeLocation = (string?)null,
                storeName = (string?)null,
                certificatePath = (string?)null,
                privateKeyPathHint = privateKeyPath,
                keyId = "orders-api-prod-rsa",
                keyVersion = "2026q2",
                notes = "End-to-end sample workflow binding."
            },
            operatorToken);

        createBindingResponse.EnsureSuccessStatusCode();
        var bindingPayload = await createBindingResponse.Content.ReadFromJsonAsync<JsonObject>();
        var bindingId = bindingPayload?["bindingId"]?.GetValue<Guid>()
            ?? throw new InvalidOperationException("Binding id was not returned by the API.");

        var servicePackageResponse = await SendAuthorizedPostAsync(
            managementClient,
            $"/api/credentials/{SeededActiveCredentialId}/issue-encrypted-package",
            new
            {
                recipientBindingId = bindingId,
                reason = "End-to-end sample service package issuance."
            },
            operatorToken);
        servicePackageResponse.EnsureSuccessStatusCode();

        var clientPackageResponse = await SendAuthorizedPostAsync(
            managementClient,
            $"/api/credentials/{SeededActiveCredentialId}/issue-client-package",
            new
            {
                recipientBindingId = bindingId,
                reason = "End-to-end sample client package issuance."
            },
            operatorToken);
        clientPackageResponse.EnsureSuccessStatusCode();

        var servicePackagePath = Path.Combine(tempDirectory.Path, "key-uat-orders-0002.service.acmppkg.json");
        var clientPackagePath = Path.Combine(tempDirectory.Path, "key-uat-orders-0002.client.acmppkg.json");
        await File.WriteAllBytesAsync(servicePackagePath, await servicePackageResponse.Content.ReadAsByteArrayAsync());
        await File.WriteAllBytesAsync(clientPackagePath, await clientPackageResponse.Content.ReadAsByteArrayAsync());

        await using var recipientApp = await CreateRecipientApplicationAsync(tempDirectory.Path, privateKeyPath, bindingId, publicKeyFingerprint);
        var targetHandler = recipientApp.GetTestServer().CreateHandler();
        using var signedClient = CreateSignedClient(tempDirectory.Path, privateKeyPath, bindingId, publicKeyFingerprint, targetHandler);

        var response = await signedClient.PostAsJsonAsync("/api/orders/create", new
        {
            orderId = 321,
            description = "Submitted from end-to-end integration test."
        });

        response.EnsureSuccessStatusCode();
        var payload = await response.Content.ReadFromJsonAsync<JsonObject>();

        Assert.NotNull(payload);
        Assert.True(payload!["accepted"]?.GetValue<bool>());
        Assert.Equal("key-uat-orders-0002", payload["authentication"]?["keyId"]?.GetValue<string>());
        Assert.Equal("kms-v1", payload["authentication"]?["keyVersion"]?.GetValue<string>());
        var scopes = payload["authentication"]?["scopes"]?.AsArray().Select(node => node?.GetValue<string>() ?? string.Empty).ToArray();
        Assert.NotNull(scopes);
        Assert.Equal(["orders.read", "orders.write"], scopes);
    }

    private static HttpClient CreateSignedClient(
        string packageDirectory,
        string privateKeyPath,
        Guid bindingId,
        string publicKeyFingerprint,
        HttpMessageHandler innerHandler)
    {
        var configuration = BuildSampleConfiguration(
            Path.Combine(GetRepositoryRoot(), "samples", "MyCompany.AuthPlatform.ClientSample", "appsettings.json"),
            Path.Combine(GetRepositoryRoot(), "samples", "MyCompany.AuthPlatform.ClientSample", "appsettings.Development.json"),
            new Dictionary<string, string?>
            {
                ["AcmpHmac:Signing:KeyId"] = "key-uat-orders-0002",
                ["AcmpHmac:Signing:ExpectedKeyVersion"] = "kms-v1",
                ["AcmpHmac:Signing:PackageDirectory"] = packageDirectory,
                ["AcmpHmac:Signing:PackageReadOptions:ExpectedBindingId"] = bindingId.ToString(),
                ["AcmpHmac:Signing:PackageReadOptions:ExpectedBindingType"] = "ExternalRsaPublicKey",
                ["AcmpHmac:Signing:PackageReadOptions:ExpectedBindingKeyId"] = "orders-api-prod-rsa",
                ["AcmpHmac:Signing:PackageReadOptions:ExpectedBindingKeyVersion"] = "2026q2",
                ["AcmpHmac:Signing:PackageReadOptions:ExpectedPublicKeyFingerprint"] = publicKeyFingerprint,
                ["AcmpHmac:Signing:PackageReadOptions:ExternalRsaPrivateKeyPath"] = privateKeyPath,
                ["TargetApi:BaseUrl"] = "http://localhost"
            });

        var packageOptions = configuration
            .GetSection("AcmpHmac:Signing")
            .Get<ClientPackageCacheOptions>()
            ?? throw new InvalidOperationException("AcmpHmac:Signing configuration could not be bound.");
        var signingOptions = configuration
            .GetSection("AcmpHmac:Signing")
            .Get<AcmpHmacSigningHandlerOptions>()
            ?? throw new InvalidOperationException("AcmpHmac:Signing handler configuration could not be bound.");

        signingOptions.NonceGenerator = () => Guid.NewGuid().ToString("N");

        var reader = new X509HmacCredentialPackageReader(new CompositeX509CertificateResolver());
        var store = new EncryptedFileClientCredentialStore(packageOptions, reader);
        var signer = new HmacRequestSigner(store);
        var signingHandler = new AcmpHmacSigningHandler(signer, signingOptions)
        {
            InnerHandler = innerHandler
        };

        return new HttpClient(signingHandler)
        {
            BaseAddress = new Uri("http://localhost", UriKind.Absolute)
        };
    }

    private static async Task<WebApplication> CreateRecipientApplicationAsync(
        string packageDirectory,
        string privateKeyPath,
        Guid bindingId,
        string publicKeyFingerprint)
    {
        var configuration = BuildSampleConfiguration(
            Path.Combine(GetRepositoryRoot(), "samples", "MyCompany.AuthPlatform.RecipientSample", "appsettings.json"),
            Path.Combine(GetRepositoryRoot(), "samples", "MyCompany.AuthPlatform.RecipientSample", "appsettings.Development.json"),
            new Dictionary<string, string?>
            {
                ["AcmpHmac:Validation:PackageDirectory"] = packageDirectory,
                ["AcmpHmac:Validation:PackageReadOptions:ExpectedBindingId"] = bindingId.ToString(),
                ["AcmpHmac:Validation:PackageReadOptions:ExpectedBindingType"] = "ExternalRsaPublicKey",
                ["AcmpHmac:Validation:PackageReadOptions:ExpectedBindingKeyId"] = "orders-api-prod-rsa",
                ["AcmpHmac:Validation:PackageReadOptions:ExpectedBindingKeyVersion"] = "2026q2",
                ["AcmpHmac:Validation:PackageReadOptions:ExpectedPublicKeyFingerprint"] = publicKeyFingerprint,
                ["AcmpHmac:Validation:PackageReadOptions:ExternalRsaPrivateKeyPath"] = privateKeyPath
            });

        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            EnvironmentName = Environments.Development
        });
        builder.WebHost.UseTestServer();
        builder.Configuration.Sources.Clear();
        builder.Configuration.AddConfiguration(configuration);
        var validationOptions = builder.Configuration
            .GetSection("AcmpHmac:Validation")
            .Get<ServicePackageCacheOptions>()
            ?? throw new InvalidOperationException("AcmpHmac:Validation configuration could not be bound.");

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
        app.UseAcmpHmacValidation(new AcmpHmacValidationMiddlewareOptions
        {
            RequiredScopeResolver = context =>
                context.Request.Path.StartsWithSegments("/api/orders", StringComparison.OrdinalIgnoreCase)
                    ? "orders.write"
                    : null
        });
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
        });

        await app.StartAsync();
        return app;
    }

    private static IConfigurationRoot BuildSampleConfiguration(
        string appsettingsPath,
        string developmentSettingsPath,
        IDictionary<string, string?> overrides)
    {
        var baseDirectory = Path.GetDirectoryName(appsettingsPath)
            ?? throw new InvalidOperationException("The sample appsettings directory could not be resolved.");

        return new ConfigurationBuilder()
            .SetBasePath(baseDirectory)
            .AddJsonFile(Path.GetFileName(appsettingsPath), optional: false, reloadOnChange: false)
            .AddJsonFile(Path.GetFileName(developmentSettingsPath), optional: true, reloadOnChange: false)
            .AddInMemoryCollection(overrides)
            .Build();
    }

    private static string GetRepositoryRoot() =>
        Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", ".."));

    private static async Task<string> IssueTokenAsync(HttpClient client, string username, string password)
    {
        var response = await client.PostAsJsonAsync("/api/auth/token", new
        {
            username,
            password
        });

        response.EnsureSuccessStatusCode();
        var payload = await response.Content.ReadFromJsonAsync<JsonObject>();
        return payload?["accessToken"]?.GetValue<string>()
            ?? throw new InvalidOperationException("Access token was not returned by the API.");
    }

    private static Task<HttpResponseMessage> SendAuthorizedPostAsync<TPayload>(HttpClient client, string path, TPayload payload, string token)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, path)
        {
            Content = JsonContent.Create(payload)
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return client.SendAsync(request);
    }

    private static string ComputePublicKeyFingerprint(RSA rsa)
    {
        var subjectPublicKeyInfo = rsa.ExportSubjectPublicKeyInfo();
        var hash = SHA256.HashData(subjectPublicKeyInfo);
        return $"SHA256:{Convert.ToBase64String(hash)}";
    }

    private sealed record CreateOrderRequest(int OrderId, string? Description);

    private sealed class TemporaryDirectory : IDisposable
    {
        public TemporaryDirectory()
        {
            Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"acmp-e2e-tests-{Guid.NewGuid():N}");
            Directory.CreateDirectory(Path);
        }

        public string Path { get; }

        public void Dispose()
        {
            if (Directory.Exists(Path))
            {
                Directory.Delete(Path, recursive: true);
            }
        }
    }

    private sealed class SampleWorkflowApiFactory : WebApplicationFactory<ApiEntryPoint>
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment("Development");
            builder.DisableWindowsEventLog();
            builder.ConfigureAppConfiguration((_, configBuilder) =>
            {
                configBuilder.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["Persistence:Provider"] = "InMemoryDemo",
                    ["DemoMode:SeedOnStartup"] = "true",
                    ["Authentication:Mode"] = "EmbeddedIdentity"
                });
            });
        }
    }
}
