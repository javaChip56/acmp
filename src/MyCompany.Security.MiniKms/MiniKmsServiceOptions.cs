using MyCompany.Security.MiniKms.Client;

namespace MyCompany.Security.MiniKms;

internal sealed class MiniKmsServiceOptions
{
    public const string SectionName = "MiniKms";
    public const string InMemoryDemoProvider = "InMemoryDemo";
    public const string FileProvider = "File";
    public const string SqlServerProvider = "SqlServer";
    public const string PostgresProvider = "Postgres";

    public bool DemoModeEnabled { get; set; }

    public string PersistenceProvider { get; set; } = FileProvider;

    public string ActiveKeyVersion { get; set; } = "kms-v1";

    public string StateFilePath { get; set; } = "App_Data/minikms-state.json";

    public MiniKmsInternalJwtOptions InternalJwt { get; set; } = new();

    public MiniKmsSqlServerOptions SqlServer { get; set; } = new();

    public MiniKmsPostgresOptions Postgres { get; set; } = new();

    public Dictionary<string, string> MasterKeys { get; set; } = new(StringComparer.Ordinal);
}

internal sealed class MiniKmsSqlServerOptions
{
    public string ConnectionString { get; set; } = string.Empty;
}

internal sealed class MiniKmsPostgresOptions
{
    public string ConnectionString { get; set; } = string.Empty;
}
