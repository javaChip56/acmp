using System.Net.Http.Headers;
using System.Text;

namespace MyCompany.AuthPlatform.Hmac.Client;

public sealed class AcmpHmacSigningHandlerOptions
{
    public string KeyId { get; set; } = string.Empty;

    public string? ExpectedKeyVersion { get; set; }

    public Func<string?>? NonceGenerator { get; set; }
}

public sealed class AcmpHmacSigningHandler : DelegatingHandler
{
    private readonly HmacRequestSigner _signer;
    private readonly AcmpHmacSigningHandlerOptions _options;

    public AcmpHmacSigningHandler(
        HmacRequestSigner signer,
        AcmpHmacSigningHandlerOptions options)
    {
        _signer = signer ?? throw new ArgumentNullException(nameof(signer));
        _options = options ?? throw new ArgumentNullException(nameof(options));
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        var body = request.Content is null
            ? Array.Empty<byte>()
            : await request.Content.ReadAsByteArrayAsync(cancellationToken);
        var nonce = _options.NonceGenerator?.Invoke();
        var signingResult = await _signer.SignAsync(
            _options.KeyId,
            new HmacSigningRequest(
                request.Method.Method,
                request.RequestUri?.AbsolutePath ?? "/",
                request.RequestUri?.Query,
                body,
                _options.ExpectedKeyVersion,
                DateTimeOffset.UtcNow,
                nonce),
            cancellationToken);

        ApplyHeader(request.Headers, "X-Key-Id", signingResult.Headers.KeyId);
        ApplyHeader(request.Headers, "X-Timestamp", signingResult.Headers.Timestamp);
        ApplyHeader(request.Headers, "X-Signature", signingResult.Headers.Signature);

        if (string.IsNullOrWhiteSpace(signingResult.Headers.Nonce))
        {
            request.Headers.Remove("X-Nonce");
        }
        else
        {
            ApplyHeader(request.Headers, "X-Nonce", signingResult.Headers.Nonce);
        }

        if (request.Content is not null)
        {
            var replacementContent = new ByteArrayContent(body);
            foreach (var header in request.Content.Headers)
            {
                replacementContent.Headers.TryAddWithoutValidation(header.Key, header.Value);
            }

            request.Content = replacementContent;
        }

        return await base.SendAsync(request, cancellationToken);
    }

    private static void ApplyHeader(HttpRequestHeaders headers, string name, string value)
    {
        headers.Remove(name);
        headers.TryAddWithoutValidation(name, value);
    }
}
