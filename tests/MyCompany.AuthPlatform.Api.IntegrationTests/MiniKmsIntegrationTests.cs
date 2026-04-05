using System.Net;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using MyCompany.AuthPlatform.Application;
using MyCompany.AuthPlatform.Api;
using MyCompany.Security.MiniKms;
using MyCompany.Security.MiniKms.Client;
using Xunit;

namespace MyCompany.AuthPlatform.Api.IntegrationTests;

public sealed class MiniKmsIntegrationTests
{
    [Fact]
    public void RemoteMiniKmsClient_RoundTripsSecretAgainstMiniKmsService()
    {
        using var factory = new MiniKmsFactory();
        using var httpClient = factory.CreateClient();
        var remoteMiniKms = new RemoteMiniKmsClient(httpClient, "integration-test-api-key");

        var secret = remoteMiniKms.GenerateRandomSecret();
        var encrypted = remoteMiniKms.Encrypt(secret);
        var decrypted = remoteMiniKms.Decrypt(encrypted);

        Assert.Equal("RemoteMiniKms", remoteMiniKms.ProviderName);
        Assert.Equal("kms-v1", remoteMiniKms.ActiveKeyVersion);
        Assert.Equal(Convert.ToBase64String(secret), Convert.ToBase64String(decrypted));
    }

    [Fact]
    public async Task MiniKmsService_RejectsMissingApiKey()
    {
        using var factory = new MiniKmsFactory();
        using var httpClient = factory.CreateClient();

        var response = await httpClient.PostAsJsonAsync(
            "/internal/minikms/generate-secret",
            new GenerateSecretRequest(32));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task MainApi_ReportsRemoteMiniKmsProviderWhenConfigured()
    {
        using var factory = new RemoteMiniKmsConfiguredApiFactory();
        using var client = factory.CreateClient();

        var health = await client.GetFromJsonAsync<JsonObject>("/health");

        Assert.Equal("RemoteMiniKms", health?["miniKmsProvider"]?.GetValue<string>());
        Assert.Equal("kms-v1", health?["miniKmsKeyVersion"]?.GetValue<string>());
    }

    [Fact]
    public async Task MiniKmsService_CanCreateAndActivateNewKeyVersion()
    {
        using var factory = new MiniKmsFactory();
        using var client = factory.CreateClient();

        var createRequest = new HttpRequestMessage(HttpMethod.Post, "/internal/minikms/keys")
        {
            Content = JsonContent.Create(new CreateKeyVersionRequest("kms-v2", null, false))
        };
        createRequest.Headers.TryAddWithoutValidation(RemoteMiniKmsClient.ApiKeyHeaderName, "integration-test-api-key");

        var createResponse = await client.SendAsync(createRequest);
        createResponse.EnsureSuccessStatusCode();

        var activateRequest = new HttpRequestMessage(HttpMethod.Post, "/internal/minikms/keys/kms-v2/activate");
        activateRequest.Headers.TryAddWithoutValidation(RemoteMiniKmsClient.ApiKeyHeaderName, "integration-test-api-key");

        var activateResponse = await client.SendAsync(activateRequest);
        activateResponse.EnsureSuccessStatusCode();

        var keysRequest = new HttpRequestMessage(HttpMethod.Get, "/internal/minikms/keys");
        keysRequest.Headers.TryAddWithoutValidation(RemoteMiniKmsClient.ApiKeyHeaderName, "integration-test-api-key");

        var keysResponse = await client.SendAsync(keysRequest);
        keysResponse.EnsureSuccessStatusCode();
        var keys = await keysResponse.Content.ReadFromJsonAsync<MiniKmsKeyVersionSummary[]>();
        var health = await client.GetFromJsonAsync<MiniKmsHealthResponse>("/health");

        Assert.NotNull(keys);
        Assert.Contains(keys!, key => key.KeyVersion == "kms-v2" && key.IsActive && key.Status == "Active");
        Assert.Contains(keys!, key => key.KeyVersion == "kms-v1" && !key.IsActive && key.Status == "Retired" && key.RetiredAt.HasValue);
        Assert.Equal("kms-v2", health?.ActiveKeyVersion);
    }

    [Fact]
    public async Task MainApi_ReflectsRotatedRemoteMiniKmsKeyVersion()
    {
        using var factory = new RemoteMiniKmsConfiguredApiFactory();

        var rotateRequest = new HttpRequestMessage(HttpMethod.Post, "/internal/minikms/keys")
        {
            Content = JsonContent.Create(new CreateKeyVersionRequest("kms-v2", null, true))
        };
        rotateRequest.Headers.TryAddWithoutValidation(RemoteMiniKmsClient.ApiKeyHeaderName, "integration-test-api-key");
        var rotateResponse = await factory.MiniKmsClient.SendAsync(rotateRequest);
        rotateResponse.EnsureSuccessStatusCode();

        using var client = factory.CreateClient();
        var health = await client.GetFromJsonAsync<JsonObject>("/health");

        Assert.Equal("RemoteMiniKms", health?["miniKmsProvider"]?.GetValue<string>());
        Assert.Equal("kms-v2", health?["miniKmsKeyVersion"]?.GetValue<string>());
    }

    [Fact]
    public async Task MiniKmsService_ExposesAuditLogAndSoftRetiresExplicitKey()
    {
        using var factory = new MiniKmsFactory();
        using var client = factory.CreateClient();

        var createRequest = new HttpRequestMessage(HttpMethod.Post, "/internal/minikms/keys")
        {
            Content = JsonContent.Create(new CreateKeyVersionRequest("kms-v2", null, false))
        };
        createRequest.Headers.TryAddWithoutValidation(RemoteMiniKmsClient.ApiKeyHeaderName, "integration-test-api-key");
        createRequest.Headers.TryAddWithoutValidation(RemoteMiniKmsClient.ActorHeaderName, "ops-user");
        var createResponse = await client.SendAsync(createRequest);
        createResponse.EnsureSuccessStatusCode();

        var retireRequest = new HttpRequestMessage(HttpMethod.Post, "/internal/minikms/keys/kms-v2/retire");
        retireRequest.Headers.TryAddWithoutValidation(RemoteMiniKmsClient.ApiKeyHeaderName, "integration-test-api-key");
        retireRequest.Headers.TryAddWithoutValidation(RemoteMiniKmsClient.ActorHeaderName, "ops-user");
        var retireResponse = await client.SendAsync(retireRequest);
        retireResponse.EnsureSuccessStatusCode();

        var keysRequest = new HttpRequestMessage(HttpMethod.Get, "/internal/minikms/keys");
        keysRequest.Headers.TryAddWithoutValidation(RemoteMiniKmsClient.ApiKeyHeaderName, "integration-test-api-key");
        var keysResponse = await client.SendAsync(keysRequest);
        keysResponse.EnsureSuccessStatusCode();
        var keys = await keysResponse.Content.ReadFromJsonAsync<MiniKmsKeyVersionSummary[]>();

        var auditRequest = new HttpRequestMessage(HttpMethod.Get, "/internal/minikms/audit?take=10");
        auditRequest.Headers.TryAddWithoutValidation(RemoteMiniKmsClient.ApiKeyHeaderName, "integration-test-api-key");
        var auditResponse = await client.SendAsync(auditRequest);
        auditResponse.EnsureSuccessStatusCode();
        var auditEntries = await auditResponse.Content.ReadFromJsonAsync<MiniKmsAuditEntry[]>();

        Assert.NotNull(keys);
        Assert.Contains(keys!, key => key.KeyVersion == "kms-v2" && key.Status == "Retired" && key.RetiredAt.HasValue);
        Assert.NotNull(auditEntries);
        Assert.Contains(auditEntries!, entry => entry.Action == "CreateKeyVersion" && entry.Actor == "ops-user" && entry.KeyVersion == "kms-v2");
        Assert.Contains(auditEntries!, entry => entry.Action == "RetireKeyVersion" && entry.Actor == "ops-user" && entry.KeyVersion == "kms-v2");
    }

    [Fact]
    public async Task MiniKmsService_RejectsRetiringActiveKey()
    {
        using var factory = new MiniKmsFactory();
        using var client = factory.CreateClient();

        var retireRequest = new HttpRequestMessage(HttpMethod.Post, "/internal/minikms/keys/kms-v1/retire");
        retireRequest.Headers.TryAddWithoutValidation(RemoteMiniKmsClient.ApiKeyHeaderName, "integration-test-api-key");
        var retireResponse = await client.SendAsync(retireRequest);

        Assert.Equal(HttpStatusCode.Conflict, retireResponse.StatusCode);
    }

    private sealed class MiniKmsFactory : WebApplicationFactory<MiniKmsEntryPoint>
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment("Development");
            builder.ConfigureAppConfiguration((_, configBuilder) =>
            {
                configBuilder.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["MiniKms:ServiceApiKey"] = "integration-test-api-key",
                    ["MiniKms:ActiveKeyVersion"] = "kms-v1",
                    ["MiniKms:MasterKeys:kms-v1"] = "QWNtcFNlY3JldE1hc3RlcktleUZvckttc3YxIUFCQ0Q="
                });
            });
        }
    }

    private sealed class RemoteMiniKmsConfiguredApiFactory : WebApplicationFactory<ApiEntryPoint>
    {
        private readonly MiniKmsFactory _miniKmsFactory = new();
        private readonly HttpClient _miniKmsClient;

        public RemoteMiniKmsConfiguredApiFactory()
        {
            _miniKmsClient = _miniKmsFactory.CreateClient();
        }

        public HttpClient MiniKmsClient => _miniKmsClient;

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment("Development");
            builder.ConfigureAppConfiguration((_, configBuilder) =>
            {
                configBuilder.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["Persistence:Provider"] = "InMemoryDemo",
                    ["DemoMode:SeedOnStartup"] = "false",
                    ["Authentication:Mode"] = "EmbeddedIdentity",
                    ["MiniKms:Provider"] = "RemoteMiniKms",
                    ["MiniKms:ActiveKeyVersion"] = "kms-v1",
                    ["MiniKms:Remote:BaseUrl"] = "https://localhost:7190",
                    ["MiniKms:Remote:ApiKey"] = "integration-test-api-key",
                    ["MiniKms:Remote:TimeoutSeconds"] = "15"
                });
            });
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<IMiniKms>();
                services.RemoveAll<IHmacSecretProtector>();
                services.AddSingleton<IMiniKms>(_ =>
                    new RemoteMiniKmsClient(MiniKmsClient, "integration-test-api-key"));
                services.AddSingleton<IHmacSecretProtector>(serviceProvider =>
                    new MiniKmsHmacSecretProtector(serviceProvider.GetRequiredService<IMiniKms>()));
            });
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _miniKmsClient.Dispose();
                _miniKmsFactory.Dispose();
            }

            base.Dispose(disposing);
        }
    }
}
