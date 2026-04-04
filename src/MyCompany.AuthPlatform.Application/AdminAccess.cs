namespace MyCompany.AuthPlatform.Application;

public enum AdminAccessRole
{
    AccessViewer = 1,
    AccessOperator = 2,
    AccessAdministrator = 3,
}

public sealed record AdminAccessContext(
    string Actor,
    AdminAccessRole Role,
    string CorrelationId);
