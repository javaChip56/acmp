using MyCompany.AuthPlatform.Hmac;

namespace MyCompany.AuthPlatform.Hmac.Client;

public sealed record HmacSigningRequest(
    string Method,
    string Path,
    string? QueryString,
    byte[]? Body,
    string? ExpectedKeyVersion,
    DateTimeOffset? Timestamp,
    string? Nonce);

public sealed record HmacSigningResult(
    HmacSignatureHeaders Headers,
    string CanonicalString,
    string KeyVersion,
    IReadOnlyList<string> Scopes);

public sealed class HmacRequestSigner
{
    private const string SupportedCanonicalSigningProfile = "acmp-hmac-v1";

    private readonly EncryptedFileClientCredentialStore _credentialStore;

    public HmacRequestSigner(EncryptedFileClientCredentialStore credentialStore)
    {
        _credentialStore = credentialStore ?? throw new ArgumentNullException(nameof(credentialStore));
    }

    public async Task<HmacSigningResult> SignAsync(
        string keyId,
        HmacSigningRequest request,
        CancellationToken cancellationToken = default)
    {
        var package = await _credentialStore.GetByKeyIdAsync(keyId, request.ExpectedKeyVersion, cancellationToken);

        if (!string.Equals(package.HmacAlgorithm, "HMACSHA256", StringComparison.Ordinal))
        {
            throw new InvalidOperationException("The credential package specifies an unsupported HMAC algorithm.");
        }

        if (!string.Equals(package.CanonicalSigningProfileId, SupportedCanonicalSigningProfile, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("The credential package specifies an unsupported canonical signing profile.");
        }

        var timestamp = request.Timestamp ?? DateTimeOffset.UtcNow;
        var timestampText = HmacCanonicalRequestBuilder.FormatTimestamp(timestamp);
        var canonicalString = HmacCanonicalRequestBuilder.Build(
            request.Method,
            request.Path,
            request.QueryString,
            request.Body ?? Array.Empty<byte>(),
            timestampText,
            request.Nonce,
            package.KeyId);
        var signature = HmacCanonicalRequestBuilder.ComputeSignatureHex(package.Secret, canonicalString);

        return new HmacSigningResult(
            new HmacSignatureHeaders(package.KeyId, signature, timestampText, request.Nonce?.Trim()),
            canonicalString,
            package.KeyVersion,
            package.Scopes);
    }
}
