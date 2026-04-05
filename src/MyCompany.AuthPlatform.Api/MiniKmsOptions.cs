namespace MyCompany.AuthPlatform.Api;

internal sealed class MiniKmsOptions
{
    public const string SectionName = "MiniKms";
    public const string LocalProvider = "LocalMiniKms";
    public const string RemoteProvider = "RemoteMiniKms";

    public string Provider { get; set; } = LocalProvider;

    public string ActiveKeyVersion { get; set; } = "kms-v1";

    public Dictionary<string, string> MasterKeys { get; set; } = new(StringComparer.Ordinal);

    public RemoteMiniKmsOptions Remote { get; set; } = new();
}

internal sealed class RemoteMiniKmsOptions
{
    public string BaseUrl { get; set; } = "https://localhost:7190";

    public string ApiKey { get; set; } = "dev-minikms-api-key";

    public int TimeoutSeconds { get; set; } = 15;
}
