namespace MyCompany.Security.MiniKms;

internal sealed class MiniKmsServiceOptions
{
    public const string SectionName = "MiniKms";

    public bool DemoModeEnabled { get; set; }

    public string ActiveKeyVersion { get; set; } = "kms-v1";

    public string ServiceApiKey { get; set; } = "dev-minikms-api-key";

    public string StateFilePath { get; set; } = "App_Data/minikms-state.json";

    public Dictionary<string, string> MasterKeys { get; set; } = new(StringComparer.Ordinal);
}
