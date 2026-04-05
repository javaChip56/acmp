namespace MyCompany.AuthPlatform.Api;

internal sealed class MiniKmsOptions
{
    public const string SectionName = "MiniKms";
    public const string LocalProvider = "LocalMiniKms";

    public string Provider { get; set; } = LocalProvider;

    public string ActiveKeyVersion { get; set; } = "kms-v1";

    public Dictionary<string, string> MasterKeys { get; set; } = new(StringComparer.Ordinal);
}
