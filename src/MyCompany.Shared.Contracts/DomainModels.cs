using System;
using System.Collections.Generic;

namespace MyCompany.Shared.Contracts.Domain;

public enum DeploymentEnvironment
{
    Dev = 1,
    Test = 2,
    Uat = 3,
    Prod = 4,
}

public enum ServiceClientStatus
{
    Active = 1,
    Disabled = 2,
}

public enum CredentialStatus
{
    Active = 1,
    Disabled = 2,
    Revoked = 3,
}

public enum AuthenticationMode
{
    Hmac = 1,
    Jwt = 2,
    Mtls = 3,
    OAuth2ClientCredentials = 4,
    Kerberos = 5,
    ApiKey = 6,
    AsymmetricSignature = 7,
}

public enum HmacAlgorithm
{
    HmacSha256 = 1,
}

public enum AuditOutcome
{
    Succeeded = 1,
    Rejected = 2,
    Failed = 3,
}

public enum AdminUserStatus
{
    Active = 1,
    Disabled = 2,
}

public sealed class ServiceClient
{
    public Guid ClientId { get; set; }
    public string ClientCode { get; set; } = string.Empty;
    public string ClientName { get; set; } = string.Empty;
    public string Owner { get; set; } = string.Empty;
    public DeploymentEnvironment Environment { get; set; }
    public ServiceClientStatus Status { get; set; } = ServiceClientStatus.Active;
    public string? Description { get; set; }
    public string? MetadataJson { get; set; }
    public DateTimeOffset? DisabledAt { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public string CreatedBy { get; set; } = string.Empty;
    public DateTimeOffset UpdatedAt { get; set; }
    public string UpdatedBy { get; set; } = string.Empty;
    public string? ConcurrencyToken { get; set; }
}

public sealed class Credential
{
    public Guid CredentialId { get; set; }
    public Guid ClientId { get; set; }
    public AuthenticationMode AuthenticationMode { get; set; } = AuthenticationMode.Hmac;
    public CredentialStatus Status { get; set; } = CredentialStatus.Active;
    public DeploymentEnvironment Environment { get; set; }
    public DateTimeOffset? ExpiresAt { get; set; }
    public DateTimeOffset? DisabledAt { get; set; }
    public DateTimeOffset? RevokedAt { get; set; }
    public Guid? ReplacedByCredentialId { get; set; }
    public DateTimeOffset? RotationGraceEndsAt { get; set; }
    public string? Notes { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public string CreatedBy { get; set; } = string.Empty;
    public DateTimeOffset UpdatedAt { get; set; }
    public string UpdatedBy { get; set; } = string.Empty;
    public string? ConcurrencyToken { get; set; }
}

public sealed class CredentialScope
{
    public Guid CredentialId { get; set; }
    public string ScopeName { get; set; } = string.Empty;
    public DateTimeOffset CreatedAt { get; set; }
    public string CreatedBy { get; set; } = string.Empty;
}

public sealed class HmacCredentialDetail
{
    public Guid CredentialId { get; set; }
    public string KeyId { get; set; } = string.Empty;
    public byte[] EncryptedSecret { get; set; } = Array.Empty<byte>();
    public byte[] EncryptedDataKey { get; set; } = Array.Empty<byte>();
    public string KeyVersion { get; set; } = string.Empty;
    public HmacAlgorithm HmacAlgorithm { get; set; } = HmacAlgorithm.HmacSha256;
    public string EncryptionAlgorithm { get; set; } = string.Empty;
    public byte[]? Iv { get; set; }
    public byte[]? Tag { get; set; }
    public DateTimeOffset? LastUsedAt { get; set; }
}

public sealed class AuditLogEntry
{
    public Guid AuditId { get; set; }
    public DateTimeOffset Timestamp { get; set; }
    public string Actor { get; set; } = string.Empty;
    public string Action { get; set; } = string.Empty;
    public string TargetType { get; set; } = string.Empty;
    public string? TargetId { get; set; }
    public DeploymentEnvironment? Environment { get; set; }
    public string? Reason { get; set; }
    public AuditOutcome? Outcome { get; set; }
    public string? CorrelationId { get; set; }
    public string? MetadataJson { get; set; }
}

public sealed class AdminUser
{
    public Guid UserId { get; set; }
    public string Username { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public AdminUserStatus Status { get; set; } = AdminUserStatus.Active;
    public byte[] PasswordHash { get; set; } = Array.Empty<byte>();
    public byte[] PasswordSalt { get; set; } = Array.Empty<byte>();
    public string PasswordHashAlgorithm { get; set; } = string.Empty;
    public int PasswordIterations { get; set; }
    public DateTimeOffset? LastLoginAt { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public string CreatedBy { get; set; } = string.Empty;
    public DateTimeOffset UpdatedAt { get; set; }
    public string UpdatedBy { get; set; } = string.Empty;
    public string? ConcurrencyToken { get; set; }
}

public sealed class AdminUserRoleAssignment
{
    public Guid UserId { get; set; }
    public string RoleName { get; set; } = string.Empty;
    public DateTimeOffset CreatedAt { get; set; }
    public string CreatedBy { get; set; } = string.Empty;
}

public sealed class OptionalNonce
{
    public Guid NonceId { get; set; }
    public string KeyId { get; set; } = string.Empty;
    public string NonceValue { get; set; } = string.Empty;
    public DateTimeOffset SeenAt { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
}

public sealed class PagedResult<T>
{
    public required IReadOnlyList<T> Items { get; init; }
    public required int Skip { get; init; }
    public required int Take { get; init; }
    public required int TotalCount { get; init; }
}
