using System.Net.Http.Json;
using MyCompany.AuthPlatform.Application;

namespace MyCompany.Security.MiniKms.Client;

public sealed class RemoteMiniKmsClient : IMiniKms
{
    public const string HttpClientName = "RemoteMiniKms";
    public const string ApiKeyHeaderName = "X-MiniKms-Api-Key";
    public const string ActorHeaderName = "X-MiniKms-Actor";

    private readonly HttpClient _httpClient;
    private readonly string _apiKey;

    public RemoteMiniKmsClient(HttpClient httpClient, string apiKey)
    {
        _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        _apiKey = string.IsNullOrWhiteSpace(apiKey)
            ? throw new ArgumentException("A MiniKMS API key is required for the remote provider.", nameof(apiKey))
            : apiKey.Trim();
    }

    public string ProviderName => "RemoteMiniKms";

    public string ActiveKeyVersion => GetHealth().ActiveKeyVersion;

    public byte[] GenerateRandomSecret(int sizeInBytes = 32)
    {
        if (sizeInBytes <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(sizeInBytes), "Secret size must be greater than zero.");
        }

        using var request = CreateRequest(
            HttpMethod.Post,
            "/internal/minikms/generate-secret",
            JsonContent.Create(new GenerateSecretRequest(sizeInBytes)));
        using var response = _httpClient.SendAsync(request).GetAwaiter().GetResult();
        response.EnsureSuccessStatusCode();
        var payload = response.Content.ReadFromJsonAsync<GenerateSecretResponse>().GetAwaiter().GetResult()
            ?? throw new InvalidOperationException("MiniKMS did not return a generate-secret payload.");
        return Convert.FromBase64String(payload.PlaintextBase64);
    }

    public EncryptedSecretPackage Encrypt(byte[] plaintext, string? keyVersion = null)
    {
        ArgumentNullException.ThrowIfNull(plaintext);

        if (plaintext.Length == 0)
        {
            throw new ArgumentException("Plaintext secret material is required.", nameof(plaintext));
        }

        using var request = CreateRequest(
            HttpMethod.Post,
            "/internal/minikms/encrypt",
            JsonContent.Create(new EncryptSecretRequest(
                Convert.ToBase64String(plaintext),
                string.IsNullOrWhiteSpace(keyVersion) ? null : keyVersion.Trim())));
        using var response = _httpClient.SendAsync(request).GetAwaiter().GetResult();
        response.EnsureSuccessStatusCode();
        var payload = response.Content.ReadFromJsonAsync<EncryptSecretResponse>().GetAwaiter().GetResult()
            ?? throw new InvalidOperationException("MiniKMS did not return an encrypt payload.");
        return new EncryptedSecretPackage(
            Convert.FromBase64String(payload.EncryptedSecretBase64),
            Convert.FromBase64String(payload.EncryptedDataKeyBase64),
            payload.KeyVersion,
            payload.EncryptionAlgorithm,
            Convert.FromBase64String(payload.IvBase64),
            Convert.FromBase64String(payload.TagBase64));
    }

    public byte[] Decrypt(EncryptedSecretPackage package)
    {
        ArgumentNullException.ThrowIfNull(package);

        using var request = CreateRequest(
            HttpMethod.Post,
            "/internal/minikms/decrypt",
            JsonContent.Create(new DecryptSecretRequest(
                Convert.ToBase64String(package.EncryptedSecret),
                Convert.ToBase64String(package.EncryptedDataKey),
                package.KeyVersion,
                package.EncryptionAlgorithm,
                Convert.ToBase64String(package.Iv),
                Convert.ToBase64String(package.Tag))));
        using var response = _httpClient.SendAsync(request).GetAwaiter().GetResult();
        response.EnsureSuccessStatusCode();
        var payload = response.Content.ReadFromJsonAsync<DecryptSecretResponse>().GetAwaiter().GetResult()
            ?? throw new InvalidOperationException("MiniKMS did not return a decrypt payload.");
        return Convert.FromBase64String(payload.PlaintextBase64);
    }

    private HttpRequestMessage CreateRequest(HttpMethod method, string relativePath, HttpContent content)
    {
        var request = new HttpRequestMessage(method, relativePath)
        {
            Content = content
        };
        request.Headers.TryAddWithoutValidation(ApiKeyHeaderName, _apiKey);
        request.Headers.TryAddWithoutValidation(ActorHeaderName, "acmp-api");
        return request;
    }

    private MiniKmsHealthResponse GetHealth()
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "/health");
        using var response = _httpClient.SendAsync(request).GetAwaiter().GetResult();
        response.EnsureSuccessStatusCode();
        return response.Content.ReadFromJsonAsync<MiniKmsHealthResponse>().GetAwaiter().GetResult()
            ?? throw new InvalidOperationException("MiniKMS did not return a health payload.");
    }
}
