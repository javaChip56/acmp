namespace MyCompany.AuthPlatform.Application;

public sealed class ApplicationServiceException : Exception
{
    public ApplicationServiceException(int statusCode, string errorCode, string message)
        : base(message)
    {
        StatusCode = statusCode;
        ErrorCode = errorCode;
    }

    public int StatusCode { get; }

    public string ErrorCode { get; }
}
