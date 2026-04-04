using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using MyCompany.AuthPlatform.Persistence.Abstractions;

namespace MyCompany.AuthPlatform.Persistence.SqlServer;

public static class SqlServerPersistenceServiceCollectionExtensions
{
    public static IServiceCollection AddAuthPlatformSqlServerPersistence(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        services.Configure<SqlServerPersistenceOptions>(options =>
        {
            var section = configuration.GetSection(SqlServerPersistenceOptions.SectionName);
            options.ConnectionString = section["ConnectionString"] ?? string.Empty;
            options.ApplyMigrationsOnStartup =
                bool.TryParse(section["ApplyMigrationsOnStartup"], out var applyMigrationsOnStartup) &&
                applyMigrationsOnStartup;
        });

        services.AddDbContext<AuthPlatformSqlServerDbContext>((serviceProvider, options) =>
        {
            var settings = serviceProvider.GetRequiredService<IOptions<SqlServerPersistenceOptions>>().Value;
            if (string.IsNullOrWhiteSpace(settings.ConnectionString))
            {
                throw new InvalidOperationException(
                    "Persistence:SqlServer:ConnectionString must be configured when Persistence:Provider is SqlServer.");
            }

            options.UseSqlServer(settings.ConnectionString);
        });

        services.AddScoped<IAuthPlatformUnitOfWork, SqlServerAuthPlatformUnitOfWork>();
        return services;
    }

    public static async Task ApplyAuthPlatformSqlServerMigrationsAsync(this IServiceProvider serviceProvider)
    {
        using var scope = serviceProvider.CreateScope();
        var options = scope.ServiceProvider.GetRequiredService<IOptions<SqlServerPersistenceOptions>>().Value;
        if (!options.ApplyMigrationsOnStartup)
        {
            return;
        }

        var dbContext = scope.ServiceProvider.GetRequiredService<AuthPlatformSqlServerDbContext>();
        await dbContext.Database.MigrateAsync();
    }
}
