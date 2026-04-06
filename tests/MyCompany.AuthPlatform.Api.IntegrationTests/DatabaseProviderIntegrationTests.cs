using System.Net.Http.Json;
using System.Net.Http.Headers;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using MyCompany.AuthPlatform.Api;
using Xunit;

namespace MyCompany.AuthPlatform.Api.IntegrationTests;

public sealed class DatabaseProviderIntegrationTests
{
    [Fact]
    [Trait("Category", "SqlServer")]
    public async Task SqlServer_HostStartsAndServesSeededData()
    {
        if (!DatabaseIntegrationSupport.ShouldRun)
        {
            return;
        }

        var masterConnectionString = DatabaseIntegrationSupport.GetRequired("SQLSERVER_TEST_CONNECTION_STRING");
        var databaseName = $"acmp_sql_{Guid.NewGuid():N}";
        var connectionString = DatabaseIntegrationSupport.BuildSqlServerConnectionString(masterConnectionString, databaseName);

        using var factory = new ConfiguredApiFactory(new Dictionary<string, string?>
        {
            ["Persistence:Provider"] = "SqlServer",
            ["Persistence:SqlServer:ConnectionString"] = connectionString,
            ["Persistence:SqlServer:ApplyMigrationsOnStartup"] = "true",
            ["DemoMode:SeedOnStartup"] = "true"
        });

        using var client = factory.CreateClient();
        var token = await IssueAdminTokenAsync(client);

        var health = await client.GetFromJsonAsync<JsonObject>("/health");
        var usersResponse = await SendAuthorizedGetAsync(client, "/api/admin/users", token);
        var clientsResponse = await SendAuthorizedGetAsync(client, "/api/clients", token);

        usersResponse.EnsureSuccessStatusCode();
        clientsResponse.EnsureSuccessStatusCode();

        var users = await usersResponse.Content.ReadFromJsonAsync<JsonArray>();
        var clients = await clientsResponse.Content.ReadFromJsonAsync<JsonArray>();

        Assert.Equal("SqlServer", health?["persistenceProvider"]?.GetValue<string>());
        Assert.NotNull(users);
        Assert.NotNull(clients);
        Assert.True(users!.Count >= 3);
        Assert.True(clients!.Count >= 2);
    }

    [Fact]
    [Trait("Category", "Postgres")]
    public async Task Postgres_HostStartsAndServesSeededData()
    {
        if (!DatabaseIntegrationSupport.ShouldRun)
        {
            return;
        }

        var adminConnectionString = DatabaseIntegrationSupport.GetRequired("POSTGRES_ADMIN_CONNECTION_STRING");
        var databaseName = $"acmp_pg_{Guid.NewGuid():N}";
        await DatabaseIntegrationSupport.CreatePostgresDatabaseAsync(adminConnectionString, databaseName);

        var connectionString = DatabaseIntegrationSupport.BuildPostgresConnectionString(adminConnectionString, databaseName);

        using var factory = new ConfiguredApiFactory(new Dictionary<string, string?>
        {
            ["Persistence:Provider"] = "Postgres",
            ["Persistence:Postgres:ConnectionString"] = connectionString,
            ["Persistence:Postgres:ApplyMigrationsOnStartup"] = "true",
            ["DemoMode:SeedOnStartup"] = "true"
        });

        using var client = factory.CreateClient();
        var token = await IssueAdminTokenAsync(client);

        var health = await client.GetFromJsonAsync<JsonObject>("/health");
        var usersResponse = await SendAuthorizedGetAsync(client, "/api/admin/users", token);
        var clientsResponse = await SendAuthorizedGetAsync(client, "/api/clients", token);

        usersResponse.EnsureSuccessStatusCode();
        clientsResponse.EnsureSuccessStatusCode();

        var users = await usersResponse.Content.ReadFromJsonAsync<JsonArray>();
        var clients = await clientsResponse.Content.ReadFromJsonAsync<JsonArray>();

        Assert.Equal("Postgres", health?["persistenceProvider"]?.GetValue<string>());
        Assert.NotNull(users);
        Assert.NotNull(clients);
        Assert.True(users!.Count >= 3);
        Assert.True(clients!.Count >= 2);
    }

    private static async Task<string> IssueAdminTokenAsync(HttpClient client)
    {
        var response = await client.PostAsJsonAsync("/api/auth/token", new
        {
            username = "administrator.demo",
            password = "AdministratorPass!123"
        });

        response.EnsureSuccessStatusCode();
        var payload = await response.Content.ReadFromJsonAsync<JsonObject>();
        return payload?["accessToken"]?.GetValue<string>()
            ?? throw new InvalidOperationException("Access token was not returned by the API.");
    }

    private static Task<HttpResponseMessage> SendAuthorizedGetAsync(HttpClient client, string path, string token)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, path);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return client.SendAsync(request);
    }

    private sealed class ConfiguredApiFactory : WebApplicationFactory<ApiEntryPoint>
    {
        private readonly IEnumerable<KeyValuePair<string, string?>> _overrides;

        public ConfiguredApiFactory(IEnumerable<KeyValuePair<string, string?>> overrides)
        {
            _overrides = overrides;
        }

        protected override void ConfigureWebHost(Microsoft.AspNetCore.Hosting.IWebHostBuilder builder)
        {
            builder.UseEnvironment("Development");
            builder.DisableWindowsEventLog();
            builder.ConfigureAppConfiguration((_, configBuilder) =>
            {
                configBuilder.AddInMemoryCollection(_overrides);
            });
        }
    }
}
