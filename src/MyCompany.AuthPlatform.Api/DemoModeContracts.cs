namespace MyCompany.AuthPlatform.Api;

public sealed record HealthResponse(
    string Status,
    string PersistenceProvider,
    string MiniKmsProvider,
    string MiniKmsKeyVersion);

public sealed record ReadinessCheckResponse(
    string Name,
    string Status,
    string Details);

public sealed record ReadinessResponse(
    string Status,
    IReadOnlyList<ReadinessCheckResponse> Checks,
    string PersistenceProvider,
    string MiniKmsProvider,
    string MiniKmsKeyVersion);

public sealed record DemoSystemInfoResponse(
    string AppName,
    string Mode,
    string PersistenceProvider,
    bool SeedOnStartup,
    string AuthenticationMode,
    IReadOnlyList<string> Notes,
    IReadOnlyList<string> SupportedRoles);

public sealed record ApiErrorResponse(
    string ErrorCode,
    string Message);
