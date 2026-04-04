namespace MyCompany.AuthPlatform.Persistence.Postgres;

public sealed class PostgresPersistenceOptions
{
    public const string SectionName = "Persistence:Postgres";

    public string ConnectionString { get; set; } = string.Empty;

    public bool ApplyMigrationsOnStartup { get; set; }
}
