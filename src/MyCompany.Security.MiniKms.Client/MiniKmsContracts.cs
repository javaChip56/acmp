namespace MyCompany.Security.MiniKms.Client;

public sealed record GenerateSecretRequest(int SizeInBytes);

public sealed record GenerateSecretResponse(
    string PlaintextBase64,
    string KeyVersion,
    string ProviderName);

public sealed record EncryptSecretRequest(
    string PlaintextBase64,
    string? KeyVersion);

public sealed record EncryptSecretResponse(
    string EncryptedSecretBase64,
    string EncryptedDataKeyBase64,
    string KeyVersion,
    string EncryptionAlgorithm,
    string IvBase64,
    string TagBase64,
    string ProviderName);

public sealed record DecryptSecretRequest(
    string EncryptedSecretBase64,
    string EncryptedDataKeyBase64,
    string KeyVersion,
    string EncryptionAlgorithm,
    string IvBase64,
    string TagBase64);

public sealed record DecryptSecretResponse(
    string PlaintextBase64,
    string KeyVersion,
    string ProviderName);

public sealed record MiniKmsHealthResponse(
    string Status,
    string ProviderName,
    string ActiveKeyVersion);

public sealed record MiniKmsKeyVersionSummary(
    string KeyVersion,
    string Status,
    bool IsActive,
    DateTimeOffset CreatedAt,
    DateTimeOffset? ActivatedAt,
    DateTimeOffset? RetiredAt);

public sealed record CreateKeyVersionRequest(
    string? KeyVersion,
    string? MasterKeyBase64,
    bool Activate);

public sealed record MiniKmsAuditEntry(
    string AuditId,
    DateTimeOffset Timestamp,
    string Action,
    string Outcome,
    string Actor,
    string? KeyVersion,
    string Details);
