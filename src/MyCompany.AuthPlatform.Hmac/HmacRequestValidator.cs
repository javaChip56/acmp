using MyCompany.AuthPlatform.Packaging;

namespace MyCompany.AuthPlatform.Hmac;

public sealed record HmacValidationRequest(
    string Method,
    string Path,
    string? QueryString,
    byte[]? Body,
    string? ExpectedKeyVersion,
    HmacSignatureHeaders Headers);

public sealed record HmacValidationResult(
    bool IsValid,
    string? FailureCode,
    string? FailureMessage,
    Guid? CredentialId,
    string? KeyId,
    string? KeyVersion,
    IReadOnlyList<string> Scopes);

public sealed class HmacValidationOptions
{
    public TimeSpan AllowedClockSkew { get; set; } = TimeSpan.FromMinutes(5);

    public bool RequireNonce { get; set; }
}

public sealed class HmacRequestValidator
{
    private readonly EncryptedFileServiceCredentialStore _credentialStore;
    private readonly HmacValidationOptions _options;

    public HmacRequestValidator(
        EncryptedFileServiceCredentialStore credentialStore,
        HmacValidationOptions? options = null)
    {
        _credentialStore = credentialStore ?? throw new ArgumentNullException(nameof(credentialStore));
        _options = options ?? new HmacValidationOptions();
    }

    public async Task<HmacValidationResult> ValidateAsync(
        HmacValidationRequest request,
        string? requiredScope = null,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(request.Headers.KeyId))
        {
            return Failure("missing_key_id", "The X-Key-Id header is required.");
        }

        if (string.IsNullOrWhiteSpace(request.Headers.Timestamp))
        {
            return Failure("missing_timestamp", "The X-Timestamp header is required.");
        }

        if (string.IsNullOrWhiteSpace(request.Headers.Signature))
        {
            return Failure("missing_signature", "The X-Signature header is required.");
        }

        if (_options.RequireNonce && string.IsNullOrWhiteSpace(request.Headers.Nonce))
        {
            return Failure("missing_nonce", "The X-Nonce header is required by the current policy.");
        }

        if (!HmacCanonicalRequestBuilder.TryParseTimestamp(request.Headers.Timestamp, out var timestamp))
        {
            return Failure("invalid_timestamp_format", "The X-Timestamp header is not in the required UTC format.");
        }

        if (timestamp < DateTimeOffset.UtcNow.Subtract(_options.AllowedClockSkew) ||
            timestamp > DateTimeOffset.UtcNow.Add(_options.AllowedClockSkew))
        {
            return Failure("timestamp_skew_rejected", "The request timestamp is outside the allowed validation window.");
        }

        ServiceValidationCredentialPackage package;
        try
        {
            package = await _credentialStore.GetByKeyIdAsync(request.Headers.KeyId, request.ExpectedKeyVersion, cancellationToken);
        }
        catch (HmacCredentialPackageException exception)
        {
            return Failure("credential_resolution_failed", exception.Message);
        }

        if (!string.Equals(package.HmacAlgorithm, "HMACSHA256", StringComparison.Ordinal))
        {
            return Failure("unsupported_hmac_algorithm", "The credential package specifies an unsupported HMAC algorithm.");
        }

        var canonicalString = HmacCanonicalRequestBuilder.Build(
            request.Method,
            request.Path,
            request.QueryString,
            request.Body ?? Array.Empty<byte>(),
            request.Headers.Timestamp,
            request.Headers.Nonce,
            package.KeyId);
        var expectedSignature = HmacCanonicalRequestBuilder.ComputeSignatureHex(package.Secret, canonicalString);

        if (!HmacCanonicalRequestBuilder.FixedTimeEqualsHex(expectedSignature, request.Headers.Signature.Trim()))
        {
            return Failure("invalid_signature", "The supplied HMAC signature does not match the reconstructed request.");
        }

        if (!string.IsNullOrWhiteSpace(requiredScope) &&
            !package.Scopes.Contains(requiredScope.Trim(), StringComparer.Ordinal))
        {
            return Failure("insufficient_scope", "The credential is authenticated but does not have the required scope.");
        }

        return new HmacValidationResult(
            true,
            null,
            null,
            package.CredentialId,
            package.KeyId,
            package.KeyVersion,
            package.Scopes);
    }

    private static HmacValidationResult Failure(string code, string message) =>
        new(false, code, message, null, null, null, Array.Empty<string>());
}
