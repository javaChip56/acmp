using Microsoft.Data.SqlClient;
using Npgsql;

namespace MyCompany.AuthPlatform.Api.IntegrationTests;

internal static class DatabaseIntegrationSupport
{
    public static bool ShouldRun =>
        string.Equals(
            Environment.GetEnvironmentVariable("RUN_DATABASE_INTEGRATION_TESTS"),
            "true",
            StringComparison.OrdinalIgnoreCase);

    public static string GetRequired(string name)
    {
        var value = Environment.GetEnvironmentVariable(name);
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new InvalidOperationException($"Environment variable '{name}' must be configured for database integration tests.");
        }

        return value;
    }

    public static async Task CreatePostgresDatabaseAsync(string adminConnectionString, string databaseName)
    {
        await using var connection = new NpgsqlConnection(adminConnectionString);
        await connection.OpenAsync();

        await using var command = connection.CreateCommand();
        command.CommandText = $"CREATE DATABASE \"{databaseName}\"";
        await command.ExecuteNonQueryAsync();
    }

    public static string BuildSqlServerConnectionString(string masterConnectionString, string databaseName)
    {
        var builder = new SqlConnectionStringBuilder(masterConnectionString)
        {
            InitialCatalog = databaseName,
            Encrypt = false,
            TrustServerCertificate = true
        };

        return builder.ConnectionString;
    }

    public static string BuildPostgresConnectionString(string adminConnectionString, string databaseName)
    {
        var builder = new NpgsqlConnectionStringBuilder(adminConnectionString)
        {
            Database = databaseName
        };

        return builder.ConnectionString;
    }
}
