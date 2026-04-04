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

public sealed record ApiErrorResponse(
    string ErrorCode,
    string Message);
