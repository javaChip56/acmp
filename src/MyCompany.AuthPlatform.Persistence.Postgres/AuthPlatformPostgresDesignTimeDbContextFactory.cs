using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace MyCompany.AuthPlatform.Persistence.Postgres;

public sealed class AuthPlatformPostgresDesignTimeDbContextFactory
    : IDesignTimeDbContextFactory<AuthPlatformPostgresDbContext>
{
    public AuthPlatformPostgresDbContext CreateDbContext(string[] args)
    {
        var connectionString =
            Environment.GetEnvironmentVariable("ACMP_POSTGRES_MIGRATIONS_CONNECTION_STRING")
            ?? "Host=localhost;Port=5432;Database=acmp_migrations;Username=postgres;Password=postgres";

        var optionsBuilder = new DbContextOptionsBuilder<AuthPlatformPostgresDbContext>();
        optionsBuilder.UseNpgsql(connectionString);

        return new AuthPlatformPostgresDbContext(optionsBuilder.Options);
    }
}
