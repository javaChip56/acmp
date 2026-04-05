using System.Net;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
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
        var remoteMiniKms = new RemoteMiniKmsClient(httpClient, "integration-test-api-key", "kms-v1");

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
        }
    }
}
