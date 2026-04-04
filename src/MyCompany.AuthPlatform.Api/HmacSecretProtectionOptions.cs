namespace MyCompany.AuthPlatform.Api;

internal sealed class HmacSecretProtectionOptions
{
    public const string SectionName = "SecretProtection";

    public Dictionary<string, string> MasterKeys { get; set; } = new(StringComparer.Ordinal);
}
