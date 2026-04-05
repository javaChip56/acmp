using System.Net.Http.Json;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using MyCompany.AuthPlatform.Hmac.Client;
using MyCompany.AuthPlatform.Packaging;

var configuration = new ConfigurationBuilder()
    .SetBasePath(AppContext.BaseDirectory)
    .AddJsonFile("appsettings.json", optional: false, reloadOnChange: false)
    .AddJsonFile("appsettings.Development.json", optional: true, reloadOnChange: false)
    .AddEnvironmentVariables()
    .Build();

var signingPackageOptions = configuration
    .GetSection("AcmpHmac:Signing")
    .Get<ClientPackageCacheOptions>()
    ?? throw new InvalidOperationException("AcmpHmac:Signing configuration is required.");

var signingHandlerOptions = configuration
    .GetSection("AcmpHmac:Signing")
    .Get<AcmpHmacSigningHandlerOptions>()
    ?? throw new InvalidOperationException("AcmpHmac:Signing handler configuration is required.");

if (string.IsNullOrWhiteSpace(signingHandlerOptions.KeyId))
{
    throw new InvalidOperationException("AcmpHmac:Signing:KeyId must be configured.");
}

var targetApiOptions = configuration
    .GetSection("TargetApi")
    .Get<TargetApiOptions>()
    ?? throw new InvalidOperationException("TargetApi configuration is required.");

if (string.IsNullOrWhiteSpace(targetApiOptions.BaseUrl))
{
    throw new InvalidOperationException("TargetApi:BaseUrl must be configured.");
}

if (string.IsNullOrWhiteSpace(targetApiOptions.RelativePath))
{
    throw new InvalidOperationException("TargetApi:RelativePath must be configured.");
}

signingHandlerOptions.NonceGenerator ??= () => Guid.NewGuid().ToString("N");

var services = new ServiceCollection();
services.AddSingleton(signingPackageOptions);
services.AddSingleton(signingHandlerOptions);
services.AddSingleton<IX509CertificateResolver, CompositeX509CertificateResolver>();
services.AddSingleton<IHmacCredentialPackageReader, X509HmacCredentialPackageReader>();
services.AddSingleton<EncryptedFileClientCredentialStore>();
services.AddSingleton<HmacRequestSigner>();
services.AddHttpClient("AcmpTarget", client =>
{
    client.BaseAddress = new Uri(targetApiOptions.BaseUrl, UriKind.Absolute);
    client.Timeout = TimeSpan.FromSeconds(targetApiOptions.TimeoutSeconds > 0 ? targetApiOptions.TimeoutSeconds : 30);
})
.AddHttpMessageHandler(serviceProvider => new AcmpHmacSigningHandler(
    serviceProvider.GetRequiredService<HmacRequestSigner>(),
    serviceProvider.GetRequiredService<AcmpHmacSigningHandlerOptions>()));

using var serviceProvider = services.BuildServiceProvider();
var httpClientFactory = serviceProvider.GetRequiredService<IHttpClientFactory>();
var httpClient = httpClientFactory.CreateClient("AcmpTarget");

var requestPayload = new CreateOrderRequest(
    targetApiOptions.SampleOrderId > 0 ? targetApiOptions.SampleOrderId : 123,
    string.IsNullOrWhiteSpace(targetApiOptions.SampleDescription) ? "Submitted from ACMP client sample." : targetApiOptions.SampleDescription);

Console.WriteLine($"POST {new Uri(httpClient.BaseAddress!, targetApiOptions.RelativePath)}");
Console.WriteLine($"Using KeyId '{signingHandlerOptions.KeyId}' with expected version '{signingHandlerOptions.ExpectedKeyVersion ?? "any"}'.");

var response = await httpClient.PostAsJsonAsync(targetApiOptions.RelativePath, requestPayload);
var responseBody = await response.Content.ReadAsStringAsync();

Console.WriteLine($"Response: {(int)response.StatusCode} {response.StatusCode}");
Console.WriteLine(responseBody);

internal sealed record TargetApiOptions(
    string BaseUrl,
    string RelativePath,
    int TimeoutSeconds,
    int SampleOrderId,
    string? SampleDescription);

internal sealed record CreateOrderRequest(int OrderId, string? Description);
