namespace MyCompany.AuthPlatform.Persistence.SqlServer;

public sealed class SqlServerPersistenceOptions
{
    public const string SectionName = "Persistence:SqlServer";

    public string ConnectionString { get; set; } = string.Empty;

    public bool ApplyMigrationsOnStartup { get; set; }
}
