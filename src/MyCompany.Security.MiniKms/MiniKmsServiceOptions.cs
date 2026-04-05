namespace MyCompany.Security.MiniKms;

internal sealed class MiniKmsServiceOptions
{
    public const string SectionName = "MiniKms";

    public string ActiveKeyVersion { get; set; } = "kms-v1";

    public string ServiceApiKey { get; set; } = "dev-minikms-api-key";

    public Dictionary<string, string> MasterKeys { get; set; } = new(StringComparer.Ordinal);
}
