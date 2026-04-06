using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Logging;

namespace MyCompany.AuthPlatform.Api.IntegrationTests;

internal static class TestHostBuilderExtensions
{
    public static IWebHostBuilder DisableWindowsEventLog(this IWebHostBuilder builder)
    {
        builder.ConfigureLogging(logging =>
        {
            logging.ClearProviders();
        });

        return builder;
    }
}
