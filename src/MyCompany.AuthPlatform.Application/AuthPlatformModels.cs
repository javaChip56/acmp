using MyCompany.Shared.Contracts.Domain;

namespace MyCompany.AuthPlatform.Application;

public sealed record ServiceClientSummary(
    Guid ClientId,
    string ClientCode,
    string ClientName,
    string Owner,
    DeploymentEnvironment Environment,
    ServiceClientStatus Status,
    string? Description,
    DateTimeOffset CreatedAt,
    DateTimeOffset UpdatedAt);

public sealed record CredentialSummary(
    Guid CredentialId,
    Guid ClientId,
    AuthenticationMode AuthenticationMode,
    CredentialStatus Status,
    DeploymentEnvironment Environment,
    DateTimeOffset? ExpiresAt,
    DateTimeOffset? DisabledAt,
    DateTimeOffset? RevokedAt,
    Guid? ReplacedByCredentialId,
    DateTimeOffset? RotationGraceEndsAt,
    string? Notes,
    string? KeyId,
    string? KeyVersion,
    IReadOnlyList<string> Scopes,
    DateTimeOffset CreatedAt,
    DateTimeOffset UpdatedAt);

public sealed record ClientCredentialList(
    Guid ClientId,
    string ClientCode,
    string ClientName,
    IReadOnlyList<CredentialSummary> Items);

public sealed record AuditLogSummary(
    Guid AuditId,
    DateTimeOffset Timestamp,
    string Actor,
    string Action,
    string TargetType,
    string? TargetId,
    DeploymentEnvironment? Environment,
    string? Reason,
    AuditOutcome? Outcome,
    string? CorrelationId,
    string? MetadataJson);

public sealed record AdminUserSummary(
    Guid UserId,
    string Username,
    string DisplayName,
    AdminUserStatus Status,
    DateTimeOffset? LastLoginAt,
    IReadOnlyList<string> Roles,
    DateTimeOffset CreatedAt,
    DateTimeOffset UpdatedAt);

public sealed record CreateServiceClientRequest(
    string ClientCode,
    string ClientName,
    string Owner,
    DeploymentEnvironment Environment,
    string? Description,
    string? MetadataJson);

public sealed record CreateAdminUserRequest(
    string Username,
    string DisplayName,
    string Password,
    IReadOnlyList<string> Roles);

public sealed record DisableAdminUserRequest(
    string? Reason);

public sealed record ResetAdminUserPasswordRequest(
    string NewPassword,
    string? Reason);

public sealed record AssignAdminUserRolesRequest(
    IReadOnlyList<string> Roles,
    string? Reason);

public sealed record IssueHmacCredentialRequest(
    DateTimeOffset ExpiresAt,
    IReadOnlyList<string> Scopes,
    string? Notes,
    string? KeyId,
    string? KeyVersion);

public sealed record RotateHmacCredentialRequest(
    DateTimeOffset ExpiresAt,
    DateTimeOffset? GracePeriodEndsAt,
    IReadOnlyList<string>? Scopes,
    string? Notes,
    string? NewKeyId,
    string? NewKeyVersion,
    string? Reason);

public sealed record RevokeCredentialRequest(
    string Reason);

public enum CredentialPackageType
{
    ServiceValidation = 1,
    ClientSigning = 2,
}

public static class RecipientProtectionBindingTypes
{
    public const string X509StoreThumbprint = "X509StoreThumbprint";
    public const string X509File = "X509File";
}

public sealed record IssueCredentialPackageRequest(
    string BindingType,
    string? CertificateThumbprint,
    string? StoreLocation,
    string? StoreName,
    string? CertificatePath,
    string? PrivateKeyPath,
    string? CertificatePem,
    string? Reason);

public sealed record HmacCredentialPackageProtectionBinding(
    string BindingType,
    string? CertificateThumbprint,
    string? StoreLocation,
    string? StoreName,
    string? CertificatePath,
    string? PrivateKeyPath,
    string? CertificatePem);

public sealed record HmacCredentialPackageDefinition(
    CredentialPackageType PackageType,
    string PackageId,
    Guid CredentialId,
    string KeyId,
    string KeyVersion,
    CredentialStatus CredentialStatus,
    DeploymentEnvironment Environment,
    DateTimeOffset ExpiresAt,
    DateTimeOffset IssuedAt,
    HmacCredentialPackageProtectionBinding ProtectionBinding,
    string HmacAlgorithm,
    IReadOnlyList<string> Scopes,
    byte[] Secret,
    string? CanonicalSigningProfileId);

public sealed record IssuedCredentialPackage(
    Guid CredentialId,
    string KeyId,
    string PackageType,
    string FileName,
    string ContentType,
    DateTimeOffset IssuedAt,
    string KeyVersion,
    string PackageId,
    byte[] PackageBytes);

public interface IHmacCredentialPackageProtector
{
    Task<IssuedCredentialPackage> ProtectAsync(
        HmacCredentialPackageDefinition definition,
        CancellationToken cancellationToken = default);
}
