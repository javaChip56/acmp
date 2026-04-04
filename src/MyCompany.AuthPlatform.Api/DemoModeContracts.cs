using MyCompany.Shared.Contracts.Domain;

namespace MyCompany.AuthPlatform.Api;

public sealed record HealthResponse(
    string Status,
    string PersistenceProvider);

public sealed record DemoSystemInfoResponse(
    string AppName,
    string Mode,
    string PersistenceProvider,
    bool SeedOnStartup,
    IReadOnlyList<string> Notes,
    IReadOnlyList<string> SupportedRoles);

public sealed record ServiceClientSummaryResponse(
    Guid ClientId,
    string ClientCode,
    string ClientName,
    string Owner,
    DeploymentEnvironment Environment,
    ServiceClientStatus Status,
    string? Description,
    DateTimeOffset CreatedAt,
    DateTimeOffset UpdatedAt);

public sealed record CredentialSummaryResponse(
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

public sealed record ClientCredentialListResponse(
    Guid ClientId,
    string ClientCode,
    string ClientName,
    IReadOnlyList<CredentialSummaryResponse> Items);

public sealed record AuditLogResponse(
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
