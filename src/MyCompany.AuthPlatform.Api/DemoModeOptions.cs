namespace MyCompany.AuthPlatform.Api;

public sealed class PersistenceOptions
{
    public const string SectionName = "Persistence";
    public const string InMemoryDemoProvider = "InMemoryDemo";
    public const string SqlServerProvider = "SqlServer";

    public string Provider { get; set; } = InMemoryDemoProvider;
}

public sealed class DemoModeOptions
{
    public const string SectionName = "DemoMode";

    public bool SeedOnStartup { get; set; } = true;
}
