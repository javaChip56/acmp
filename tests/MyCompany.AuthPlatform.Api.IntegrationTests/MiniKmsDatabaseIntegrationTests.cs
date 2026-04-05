using System.Net.Http.Json;
using System.Net.Http.Headers;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using MyCompany.Security.MiniKms;
using MyCompany.Security.MiniKms.Client;
using Xunit;

namespace MyCompany.AuthPlatform.Api.IntegrationTests;

public sealed class MiniKmsDatabaseIntegrationTests
{
    private static readonly MiniKmsInternalJwtOptions IntegrationJwtOptions = new()
    {
        Issuer = "acmp-internal-services",
        Audience = "mini-kms-internal",
        SigningKey = "AcmpMiniKmsInternalSigningKey123456789!",
        Subject = "acmp-api",
        TokenLifetimeMinutes = 5
    };

    [Fact]
    [Trait("Category", "SqlServer")]
    public async Task SqlServer_MiniKmsStatePersistsAcrossRestart()
    {
        if (!DatabaseIntegrationSupport.ShouldRun)
        {
            return;
        }

        var masterConnectionString = DatabaseIntegrationSupport.GetRequired("SQLSERVER_TEST_CONNECTION_STRING");
        var databaseName = $"acmp_minikms_sql_{Guid.NewGuid():N}";
        var connectionString = DatabaseIntegrationSupport.BuildSqlServerConnectionString(masterConnectionString, databaseName);

        var overrides = new Dictionary<string, string?>
        {
            ["MiniKms:DemoModeEnabled"] = "false",
            ["MiniKms:PersistenceProvider"] = "SqlServer",
            ["MiniKms:ActiveKeyVersion"] = "kms-v1",
            ["MiniKms:InternalJwt:Issuer"] = IntegrationJwtOptions.Issuer,
            ["MiniKms:InternalJwt:Audience"] = IntegrationJwtOptions.Audience,
            ["MiniKms:InternalJwt:SigningKey"] = IntegrationJwtOptions.SigningKey,
            ["MiniKms:InternalJwt:Subject"] = IntegrationJwtOptions.Subject,
            ["MiniKms:InternalJwt:TokenLifetimeMinutes"] = IntegrationJwtOptions.TokenLifetimeMinutes.ToString(),
            ["MiniKms:SqlServer:ConnectionString"] = connectionString,
            ["MiniKms:MasterKeys:kms-v1"] = "QWNtcFNlY3JldE1hc3RlcktleUZvckttc3YxIUFCQ0Q="
        };

        await AssertPersistenceAcrossRestartAsync(overrides, "kms-sql-2", "/SqlServer");
    }

    [Fact]
    [Trait("Category", "Postgres")]
    public async Task Postgres_MiniKmsStatePersistsAcrossRestart()
    {
        if (!DatabaseIntegrationSupport.ShouldRun)
        {
            return;
        }

        var adminConnectionString = DatabaseIntegrationSupport.GetRequired("POSTGRES_ADMIN_CONNECTION_STRING");
        var databaseName = $"acmp_minikms_pg_{Guid.NewGuid():N}";
        await DatabaseIntegrationSupport.CreatePostgresDatabaseAsync(adminConnectionString, databaseName);
        var connectionString = DatabaseIntegrationSupport.BuildPostgresConnectionString(adminConnectionString, databaseName);

        var overrides = new Dictionary<string, string?>
        {
            ["MiniKms:DemoModeEnabled"] = "false",
            ["MiniKms:PersistenceProvider"] = "Postgres",
            ["MiniKms:ActiveKeyVersion"] = "kms-v1",
            ["MiniKms:InternalJwt:Issuer"] = IntegrationJwtOptions.Issuer,
            ["MiniKms:InternalJwt:Audience"] = IntegrationJwtOptions.Audience,
            ["MiniKms:InternalJwt:SigningKey"] = IntegrationJwtOptions.SigningKey,
            ["MiniKms:InternalJwt:Subject"] = IntegrationJwtOptions.Subject,
            ["MiniKms:InternalJwt:TokenLifetimeMinutes"] = IntegrationJwtOptions.TokenLifetimeMinutes.ToString(),
            ["MiniKms:Postgres:ConnectionString"] = connectionString,
            ["MiniKms:MasterKeys:kms-v1"] = "QWNtcFNlY3JldE1hc3RlcktleUZvckttc3YxIUFCQ0Q="
        };

        await AssertPersistenceAcrossRestartAsync(overrides, "kms-pg-2", "/Postgres");
    }

    private static async Task AssertPersistenceAcrossRestartAsync(
        IReadOnlyDictionary<string, string?> overrides,
        string newKeyVersion,
        string expectedProviderSuffix)
    {
        using (var firstFactory = new ConfiguredMiniKmsFactory(overrides))
        using (var firstClient = firstFactory.CreateClient())
        {
            var createRequest = new HttpRequestMessage(HttpMethod.Post, "/internal/minikms/keys")
            {
                Content = JsonContent.Create(new CreateKeyVersionRequest(newKeyVersion, null, true))
            };
            AuthorizeMiniKmsRequest(createRequest);
            var createResponse = await firstClient.SendAsync(createRequest);
            createResponse.EnsureSuccessStatusCode();
        }

        using var secondFactory = new ConfiguredMiniKmsFactory(overrides);
        using var secondClient = secondFactory.CreateClient();

        var keysRequest = new HttpRequestMessage(HttpMethod.Get, "/internal/minikms/keys");
        AuthorizeMiniKmsRequest(keysRequest);
        var keysResponse = await secondClient.SendAsync(keysRequest);
        keysResponse.EnsureSuccessStatusCode();
        var keys = await keysResponse.Content.ReadFromJsonAsync<MiniKmsKeyVersionSummary[]>();

        var auditRequest = new HttpRequestMessage(HttpMethod.Get, "/internal/minikms/audit?take=20");
        AuthorizeMiniKmsRequest(auditRequest);
        var auditResponse = await secondClient.SendAsync(auditRequest);
        auditResponse.EnsureSuccessStatusCode();
        var auditEntries = await auditResponse.Content.ReadFromJsonAsync<MiniKmsAuditEntry[]>();

        var health = await secondClient.GetFromJsonAsync<JsonObject>("/health");

        Assert.NotNull(keys);
        Assert.Contains(keys!, key => key.KeyVersion == newKeyVersion && key.IsActive);
        Assert.NotNull(auditEntries);
        Assert.Contains(auditEntries!, entry => entry.Action == "CreateKeyVersion" && entry.KeyVersion == newKeyVersion);
        Assert.Equal(newKeyVersion, health?["miniKmsKeyVersion"]?.GetValue<string>());
        Assert.Contains(expectedProviderSuffix, health?["providerName"]?.GetValue<string>() ?? string.Empty);
    }

    private sealed class ConfiguredMiniKmsFactory : WebApplicationFactory<MiniKmsEntryPoint>
    {
        private readonly IEnumerable<KeyValuePair<string, string?>> _overrides;

        public ConfiguredMiniKmsFactory(IEnumerable<KeyValuePair<string, string?>> overrides)
        {
            _overrides = overrides;
        }

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment("Development");
            builder.ConfigureAppConfiguration((_, configBuilder) =>
            {
                configBuilder.AddInMemoryCollection(_overrides);
            });
        }
    }

    private static void AuthorizeMiniKmsRequest(HttpRequestMessage request, string subject = "acmp-api")
    {
        request.Headers.Authorization = new AuthenticationHeaderValue(
            "Bearer",
            MiniKmsInternalJwtTokenProvider.CreateToken(IntegrationJwtOptions, subject));
    }
}
