using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using MyCompany.AuthPlatform.Persistence.Abstractions;

namespace MyCompany.AuthPlatform.Persistence.Postgres;

public static class PostgresPersistenceServiceCollectionExtensions
{
    public static IServiceCollection AddAuthPlatformPostgresPersistence(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        services.Configure<PostgresPersistenceOptions>(options =>
        {
            var section = configuration.GetSection(PostgresPersistenceOptions.SectionName);
            options.ConnectionString = section["ConnectionString"] ?? string.Empty;
            options.ApplyMigrationsOnStartup =
                bool.TryParse(section["ApplyMigrationsOnStartup"], out var applyMigrationsOnStartup) &&
                applyMigrationsOnStartup;
        });

        services.AddDbContext<AuthPlatformPostgresDbContext>((serviceProvider, options) =>
        {
            var settings = serviceProvider.GetRequiredService<IOptions<PostgresPersistenceOptions>>().Value;
            if (string.IsNullOrWhiteSpace(settings.ConnectionString))
            {
                throw new InvalidOperationException(
                    "Persistence:Postgres:ConnectionString must be configured when Persistence:Provider is Postgres.");
            }

            options.UseNpgsql(settings.ConnectionString);
        });

        services.AddScoped<IAuthPlatformUnitOfWork, PostgresAuthPlatformUnitOfWork>();
        return services;
    }

    public static async Task ApplyAuthPlatformPostgresMigrationsAsync(this IServiceProvider serviceProvider)
    {
        using var scope = serviceProvider.CreateScope();
        var options = scope.ServiceProvider.GetRequiredService<IOptions<PostgresPersistenceOptions>>().Value;
        if (!options.ApplyMigrationsOnStartup)
        {
            return;
        }

        var dbContext = scope.ServiceProvider.GetRequiredService<AuthPlatformPostgresDbContext>();
        await dbContext.Database.MigrateAsync();
    }
}
