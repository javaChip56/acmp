using System.Net;
using System.Net.Http.Json;
using System.Net.Http.Headers;
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
        var remoteMiniKms = new RemoteMiniKmsClient(httpClient, factory.InternalJwtOptions);

        var secret = remoteMiniKms.GenerateRandomSecret();
        var encrypted = remoteMiniKms.Encrypt(secret);
        var decrypted = remoteMiniKms.Decrypt(encrypted);

        Assert.Equal("RemoteMiniKms", remoteMiniKms.ProviderName);
        Assert.Equal("kms-v1", remoteMiniKms.ActiveKeyVersion);
        Assert.Equal(Convert.ToBase64String(secret), Convert.ToBase64String(decrypted));
    }

    [Fact]
    public async Task MiniKmsService_RejectsMissingBearerToken()
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
    public async Task MiniKmsService_ReadinessEndpointReportsReady()
    {
        using var factory = new MiniKmsFactory();
        using var client = factory.CreateClient();

        var readiness = await client.GetFromJsonAsync<MiniKmsReadinessResponse>("/ready");

        Assert.Equal("Ready", readiness?.Status);
        Assert.NotNull(readiness?.Checks);
        Assert.All(readiness!.Checks, check => Assert.Equal("Ready", check.Status));
    }

    [Fact]
    public async Task MainApi_ReadinessEndpointReportsReady()
    {
        using var factory = new RemoteMiniKmsConfiguredApiFactory();
        using var client = factory.CreateClient();

        var readiness = await client.GetFromJsonAsync<ReadinessResponse>("/ready");

        Assert.Equal("Ready", readiness?.Status);
        Assert.NotNull(readiness?.Checks);
        Assert.All(readiness!.Checks, check => Assert.Equal("Ready", check.Status));
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
        AuthorizeMiniKmsRequest(createRequest, factory.InternalJwtOptions);

        var createResponse = await client.SendAsync(createRequest);
        createResponse.EnsureSuccessStatusCode();

        var activateRequest = new HttpRequestMessage(HttpMethod.Post, "/internal/minikms/keys/kms-v2/activate");
        AuthorizeMiniKmsRequest(activateRequest, factory.InternalJwtOptions);

        var activateResponse = await client.SendAsync(activateRequest);
        activateResponse.EnsureSuccessStatusCode();

        var keysRequest = new HttpRequestMessage(HttpMethod.Get, "/internal/minikms/keys");
        AuthorizeMiniKmsRequest(keysRequest, factory.InternalJwtOptions);

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
        AuthorizeMiniKmsRequest(rotateRequest, factory.InternalJwtOptions);
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
        AuthorizeMiniKmsRequest(createRequest, factory.InternalJwtOptions, "ops-user");
        var createResponse = await client.SendAsync(createRequest);
        createResponse.EnsureSuccessStatusCode();

        var retireRequest = new HttpRequestMessage(HttpMethod.Post, "/internal/minikms/keys/kms-v2/retire");
        AuthorizeMiniKmsRequest(retireRequest, factory.InternalJwtOptions, "ops-user");
        var retireResponse = await client.SendAsync(retireRequest);
        retireResponse.EnsureSuccessStatusCode();

        var keysRequest = new HttpRequestMessage(HttpMethod.Get, "/internal/minikms/keys");
        AuthorizeMiniKmsRequest(keysRequest, factory.InternalJwtOptions);
        var keysResponse = await client.SendAsync(keysRequest);
        keysResponse.EnsureSuccessStatusCode();
        var keys = await keysResponse.Content.ReadFromJsonAsync<MiniKmsKeyVersionSummary[]>();

        var auditRequest = new HttpRequestMessage(HttpMethod.Get, "/internal/minikms/audit?take=10");
        AuthorizeMiniKmsRequest(auditRequest, factory.InternalJwtOptions);
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
        AuthorizeMiniKmsRequest(retireRequest, factory.InternalJwtOptions);
        var retireResponse = await client.SendAsync(retireRequest);

        Assert.Equal(HttpStatusCode.Conflict, retireResponse.StatusCode);
    }

    [Fact]
    public async Task FileBackedMiniKmsState_PersistsAcrossFactoryRestart()
    {
        var stateFilePath = Path.Combine(Path.GetTempPath(), $"acmp-minikms-{Guid.NewGuid():N}.json");

        try
        {
            using (var firstFactory = new MiniKmsFactory(stateFilePath: stateFilePath))
            using (var firstClient = firstFactory.CreateClient())
            {
                var createRequest = new HttpRequestMessage(HttpMethod.Post, "/internal/minikms/keys")
                {
                    Content = JsonContent.Create(new CreateKeyVersionRequest("kms-v3", null, true))
                };
                AuthorizeMiniKmsRequest(createRequest, firstFactory.InternalJwtOptions);
                var createResponse = await firstClient.SendAsync(createRequest);
                createResponse.EnsureSuccessStatusCode();
            }

            using var secondFactory = new MiniKmsFactory(stateFilePath: stateFilePath);
            using var secondClient = secondFactory.CreateClient();

            var keysRequest = new HttpRequestMessage(HttpMethod.Get, "/internal/minikms/keys");
            AuthorizeMiniKmsRequest(keysRequest, secondFactory.InternalJwtOptions);
            var keysResponse = await secondClient.SendAsync(keysRequest);
            keysResponse.EnsureSuccessStatusCode();
            var keys = await keysResponse.Content.ReadFromJsonAsync<MiniKmsKeyVersionSummary[]>();

            var health = await secondClient.GetFromJsonAsync<MiniKmsHealthResponse>("/health");

            Assert.NotNull(keys);
            Assert.Contains(keys!, key => key.KeyVersion == "kms-v3" && key.IsActive);
            Assert.Equal("kms-v3", health?.ActiveKeyVersion);
            Assert.Contains("/File", health?.ProviderName);
        }
        finally
        {
            if (File.Exists(stateFilePath))
            {
                File.Delete(stateFilePath);
            }
        }
    }

    [Fact]
    public async Task DemoModeMiniKmsState_RemainsInMemoryAcrossFactoryRestart()
    {
        using (var firstFactory = new MiniKmsFactory(demoModeEnabled: true))
        using (var firstClient = firstFactory.CreateClient())
        {
            var createRequest = new HttpRequestMessage(HttpMethod.Post, "/internal/minikms/keys")
            {
                Content = JsonContent.Create(new CreateKeyVersionRequest("kms-demo-2", null, true))
            };
            AuthorizeMiniKmsRequest(createRequest, firstFactory.InternalJwtOptions);
            var createResponse = await firstClient.SendAsync(createRequest);
            createResponse.EnsureSuccessStatusCode();
        }

        using var secondFactory = new MiniKmsFactory(demoModeEnabled: true);
        using var secondClient = secondFactory.CreateClient();

        var keysRequest = new HttpRequestMessage(HttpMethod.Get, "/internal/minikms/keys");
        AuthorizeMiniKmsRequest(keysRequest, secondFactory.InternalJwtOptions);
        var keysResponse = await secondClient.SendAsync(keysRequest);
        keysResponse.EnsureSuccessStatusCode();
        var keys = await keysResponse.Content.ReadFromJsonAsync<MiniKmsKeyVersionSummary[]>();

        var health = await secondClient.GetFromJsonAsync<MiniKmsHealthResponse>("/health");

        Assert.NotNull(keys);
        Assert.DoesNotContain(keys!, key => key.KeyVersion == "kms-demo-2");
        Assert.Equal("kms-v1", health?.ActiveKeyVersion);
        Assert.Contains("/InMemoryDemo", health?.ProviderName);
    }

    private sealed class MiniKmsFactory : WebApplicationFactory<MiniKmsEntryPoint>
    {
        private readonly string? _stateFilePath;
        private readonly string? _jwtStateFilePath;
        private readonly bool _demoModeEnabled;
        private readonly bool _ownsStateFilePath;
        private readonly bool _ownsJwtStateFilePath;

        public MiniKmsFactory(string? stateFilePath = null, bool demoModeEnabled = false)
        {
            _demoModeEnabled = demoModeEnabled;
            if (!demoModeEnabled && string.IsNullOrWhiteSpace(stateFilePath))
            {
                _stateFilePath = Path.Combine(Path.GetTempPath(), $"acmp-minikms-test-{Guid.NewGuid():N}.json");
                _ownsStateFilePath = true;
            }
            else
            {
                _stateFilePath = stateFilePath;
                _ownsStateFilePath = false;
            }

            _jwtStateFilePath = Path.Combine(Path.GetTempPath(), $"acmp-minikms-jwt-test-{Guid.NewGuid():N}.json");
            _ownsJwtStateFilePath = true;
        }

        public MiniKmsInternalJwtOptions InternalJwtOptions => CreateIntegrationJwtOptions(_jwtStateFilePath!);

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment("Development");
            builder.DisableWindowsEventLog();
            builder.ConfigureAppConfiguration((_, configBuilder) =>
            {
                var overrides = new Dictionary<string, string?>
                {
                    ["MiniKms:DemoModeEnabled"] = _demoModeEnabled.ToString(),
                    ["MiniKms:ActiveKeyVersion"] = "kms-v1",
                    ["MiniKms:InternalJwt:KeySource"] = MiniKmsInternalJwtOptions.ManagedStateSource,
                    ["MiniKms:InternalJwt:Issuer"] = "acmp-internal-services",
                    ["MiniKms:InternalJwt:Audience"] = "mini-kms-internal",
                    ["MiniKms:InternalJwt:ActiveKeyVersion"] = "svcjwt-v1",
                    ["MiniKms:InternalJwt:SigningKey"] = "MDEyMzQ1Njc4OUFCQ0RFRjAxMjM0NTY3ODlBQkNERUY=",
                    ["MiniKms:InternalJwt:Subject"] = "acmp-api",
                    ["MiniKms:InternalJwt:TokenLifetimeMinutes"] = "5",
                    ["MiniKms:InternalJwt:ManagedState:Provider"] = "File",
                    ["MiniKms:InternalJwt:ManagedState:StateFilePath"] = _jwtStateFilePath,
                    ["MiniKms:MasterKeys:kms-v1"] = "QWNtcFNlY3JldE1hc3RlcktleUZvckttc3YxIUFCQ0Q="
                };

                if (!string.IsNullOrWhiteSpace(_stateFilePath))
                {
                    overrides["MiniKms:StateFilePath"] = _stateFilePath;
                }

                configBuilder.AddInMemoryCollection(overrides);
            });
        }

        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);

            if (disposing && _ownsStateFilePath && !string.IsNullOrWhiteSpace(_stateFilePath) && File.Exists(_stateFilePath))
            {
                File.Delete(_stateFilePath);
            }

            if (disposing && _ownsJwtStateFilePath && !string.IsNullOrWhiteSpace(_jwtStateFilePath) && File.Exists(_jwtStateFilePath))
            {
                File.Delete(_jwtStateFilePath);
            }
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

        public MiniKmsInternalJwtOptions InternalJwtOptions => _miniKmsFactory.InternalJwtOptions;

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment("Development");
            builder.DisableWindowsEventLog();
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
                    ["MiniKms:Remote:TimeoutSeconds"] = "15",
                    ["MiniKms:Remote:InternalJwt:KeySource"] = _miniKmsFactory.InternalJwtOptions.KeySource,
                    ["MiniKms:Remote:InternalJwt:Issuer"] = _miniKmsFactory.InternalJwtOptions.Issuer,
                    ["MiniKms:Remote:InternalJwt:Audience"] = _miniKmsFactory.InternalJwtOptions.Audience,
                    ["MiniKms:Remote:InternalJwt:ActiveKeyVersion"] = _miniKmsFactory.InternalJwtOptions.ActiveKeyVersion,
                    ["MiniKms:Remote:InternalJwt:Subject"] = _miniKmsFactory.InternalJwtOptions.Subject,
                    ["MiniKms:Remote:InternalJwt:TokenLifetimeMinutes"] = _miniKmsFactory.InternalJwtOptions.TokenLifetimeMinutes.ToString(),
                    ["MiniKms:Remote:InternalJwt:ManagedState:Provider"] = _miniKmsFactory.InternalJwtOptions.ManagedState.Provider,
                    ["MiniKms:Remote:InternalJwt:ManagedState:StateFilePath"] = _miniKmsFactory.InternalJwtOptions.ManagedState.StateFilePath
                });
            });
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<IMiniKms>();
                services.RemoveAll<IHmacSecretProtector>();
                services.AddSingleton<IMiniKms>(_ =>
                    new RemoteMiniKmsClient(MiniKmsClient, _miniKmsFactory.InternalJwtOptions));
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

    private static void AuthorizeMiniKmsRequest(HttpRequestMessage request, MiniKmsInternalJwtOptions jwtOptions, string subject = "acmp-api")
    {
        request.Headers.Authorization = new AuthenticationHeaderValue(
            "Bearer",
            MiniKmsInternalJwtTokenProvider.CreateToken(jwtOptions, subject));
    }

    private static MiniKmsInternalJwtOptions CreateIntegrationJwtOptions(string stateFilePath)
    {
        return new MiniKmsInternalJwtOptions
        {
            KeySource = MiniKmsInternalJwtOptions.ManagedStateSource,
            Issuer = "acmp-internal-services",
            Audience = "mini-kms-internal",
            ActiveKeyVersion = "svcjwt-v1",
            SigningKey = "MDEyMzQ1Njc4OUFCQ0RFRjAxMjM0NTY3ODlBQkNERUY=",
            Subject = "acmp-api",
            TokenLifetimeMinutes = 5,
            ManagedState = new MiniKmsInternalJwtManagedStateOptions
            {
                Provider = MiniKmsInternalJwtManagedStateOptions.FileProvider,
                StateFilePath = stateFilePath
            }
        };
    }
}
