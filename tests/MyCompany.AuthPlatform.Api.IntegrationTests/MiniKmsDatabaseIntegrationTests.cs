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
        var integrationJwtOptions = CreateSqlServerIntegrationJwtOptions(connectionString);

        var overrides = new Dictionary<string, string?>
        {
            ["MiniKms:DemoModeEnabled"] = "false",
            ["MiniKms:PersistenceProvider"] = "SqlServer",
            ["MiniKms:ActiveKeyVersion"] = "kms-v1",
            ["MiniKms:InternalJwt:KeySource"] = integrationJwtOptions.KeySource,
            ["MiniKms:InternalJwt:Issuer"] = integrationJwtOptions.Issuer,
            ["MiniKms:InternalJwt:Audience"] = integrationJwtOptions.Audience,
            ["MiniKms:InternalJwt:ActiveKeyVersion"] = integrationJwtOptions.ActiveKeyVersion,
            ["MiniKms:InternalJwt:SigningKey"] = integrationJwtOptions.SigningKey,
            ["MiniKms:InternalJwt:Subject"] = integrationJwtOptions.Subject,
            ["MiniKms:InternalJwt:TokenLifetimeMinutes"] = integrationJwtOptions.TokenLifetimeMinutes.ToString(),
            ["MiniKms:InternalJwt:ManagedState:Provider"] = integrationJwtOptions.ManagedState.Provider,
            ["MiniKms:InternalJwt:ManagedState:SqlServer:ConnectionString"] = integrationJwtOptions.ManagedState.SqlServer.ConnectionString,
            ["MiniKms:SqlServer:ConnectionString"] = connectionString,
            ["MiniKms:MasterKeys:kms-v1"] = "QWNtcFNlY3JldE1hc3RlcktleUZvckttc3YxIUFCQ0Q="
        };

        await AssertPersistenceAcrossRestartAsync(overrides, integrationJwtOptions, "kms-sql-2", "/SqlServer");
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
        var integrationJwtOptions = CreatePostgresIntegrationJwtOptions(connectionString);

        var overrides = new Dictionary<string, string?>
        {
            ["MiniKms:DemoModeEnabled"] = "false",
            ["MiniKms:PersistenceProvider"] = "Postgres",
            ["MiniKms:ActiveKeyVersion"] = "kms-v1",
            ["MiniKms:InternalJwt:KeySource"] = integrationJwtOptions.KeySource,
            ["MiniKms:InternalJwt:Issuer"] = integrationJwtOptions.Issuer,
            ["MiniKms:InternalJwt:Audience"] = integrationJwtOptions.Audience,
            ["MiniKms:InternalJwt:ActiveKeyVersion"] = integrationJwtOptions.ActiveKeyVersion,
            ["MiniKms:InternalJwt:SigningKey"] = integrationJwtOptions.SigningKey,
            ["MiniKms:InternalJwt:Subject"] = integrationJwtOptions.Subject,
            ["MiniKms:InternalJwt:TokenLifetimeMinutes"] = integrationJwtOptions.TokenLifetimeMinutes.ToString(),
            ["MiniKms:InternalJwt:ManagedState:Provider"] = integrationJwtOptions.ManagedState.Provider,
            ["MiniKms:InternalJwt:ManagedState:Postgres:ConnectionString"] = integrationJwtOptions.ManagedState.Postgres.ConnectionString,
            ["MiniKms:Postgres:ConnectionString"] = connectionString,
            ["MiniKms:MasterKeys:kms-v1"] = "QWNtcFNlY3JldE1hc3RlcktleUZvckttc3YxIUFCQ0Q="
        };

        await AssertPersistenceAcrossRestartAsync(overrides, integrationJwtOptions, "kms-pg-2", "/Postgres");
    }

    private static async Task AssertPersistenceAcrossRestartAsync(
        IReadOnlyDictionary<string, string?> overrides,
        MiniKmsInternalJwtOptions integrationJwtOptions,
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
            AuthorizeMiniKmsRequest(createRequest, integrationJwtOptions);
            var createResponse = await firstClient.SendAsync(createRequest);
            createResponse.EnsureSuccessStatusCode();
        }

        using var secondFactory = new ConfiguredMiniKmsFactory(overrides);
        using var secondClient = secondFactory.CreateClient();

        var keysRequest = new HttpRequestMessage(HttpMethod.Get, "/internal/minikms/keys");
        AuthorizeMiniKmsRequest(keysRequest, integrationJwtOptions);
        var keysResponse = await secondClient.SendAsync(keysRequest);
        keysResponse.EnsureSuccessStatusCode();
        var keys = await keysResponse.Content.ReadFromJsonAsync<MiniKmsKeyVersionSummary[]>();

        var auditRequest = new HttpRequestMessage(HttpMethod.Get, "/internal/minikms/audit?take=20");
        AuthorizeMiniKmsRequest(auditRequest, integrationJwtOptions);
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
            builder.DisableWindowsEventLog();
            builder.ConfigureAppConfiguration((_, configBuilder) =>
            {
                configBuilder.AddInMemoryCollection(_overrides);
            });
        }
    }

    private static void AuthorizeMiniKmsRequest(HttpRequestMessage request, MiniKmsInternalJwtOptions jwtOptions, string subject = "acmp-api")
    {
        request.Headers.Authorization = new AuthenticationHeaderValue(
            "Bearer",
            MiniKmsInternalJwtTokenProvider.CreateToken(jwtOptions, subject));
    }

    private static MiniKmsInternalJwtOptions CreateSqlServerIntegrationJwtOptions(string connectionString)
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
                Provider = MiniKmsInternalJwtManagedStateOptions.SqlServerProvider,
                SqlServer = new MiniKmsInternalJwtManagedSqlServerOptions
                {
                    ConnectionString = connectionString
                }
            }
        };
    }

    private static MiniKmsInternalJwtOptions CreatePostgresIntegrationJwtOptions(string connectionString)
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
                Provider = MiniKmsInternalJwtManagedStateOptions.PostgresProvider,
                Postgres = new MiniKmsInternalJwtManagedPostgresOptions
                {
                    ConnectionString = connectionString
                }
            }
        };
    }
}
