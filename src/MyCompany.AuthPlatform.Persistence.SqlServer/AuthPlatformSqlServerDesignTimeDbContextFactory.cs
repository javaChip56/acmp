using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace MyCompany.AuthPlatform.Persistence.SqlServer;

public sealed class AuthPlatformSqlServerDesignTimeDbContextFactory
    : IDesignTimeDbContextFactory<AuthPlatformSqlServerDbContext>
{
    public AuthPlatformSqlServerDbContext CreateDbContext(string[] args)
    {
        var connectionString =
            Environment.GetEnvironmentVariable("ACMP_SQLSERVER_MIGRATIONS_CONNECTION_STRING")
            ?? "Server=(localdb)\\MSSQLLocalDB;Database=Acmp.Migrations;Trusted_Connection=True;TrustServerCertificate=True";

        var optionsBuilder = new DbContextOptionsBuilder<AuthPlatformSqlServerDbContext>();
        optionsBuilder.UseSqlServer(connectionString);

        return new AuthPlatformSqlServerDbContext(optionsBuilder.Options);
    }
}
