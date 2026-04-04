# SQL Server Setup

The API host can now run against the SQL Server persistence provider instead of
the demo-only in-memory provider.

## Configuration

Set the persistence provider to `SqlServer` and configure
`Persistence:SqlServer`.

Example:

```json
{
  "Persistence": {
    "Provider": "SqlServer",
    "SqlServer": {
      "ConnectionString": "Server=(localdb)\\MSSQLLocalDB;Database=Acmp;Trusted_Connection=True;TrustServerCertificate=True",
      "EnsureCreatedOnStartup": true
    }
  }
}
```

## Notes

- `EnsureCreatedOnStartup = true` is intended for local bootstrap and development convenience.
- The host still seeds the configured embedded-identity bootstrap users when `DemoMode:SeedOnStartup = true`.
- With SQL Server enabled, persisted admin users, clients, credentials, and audit entries survive application restarts.
- The PostgreSQL provider is still pending implementation.

## Run

From the repository root:

```powershell
$env:Persistence__Provider = 'SqlServer'
$env:Persistence__SqlServer__ConnectionString = 'Server=(localdb)\\MSSQLLocalDB;Database=Acmp;Trusted_Connection=True;TrustServerCertificate=True'
$env:Persistence__SqlServer__EnsureCreatedOnStartup = 'true'
dotnet run --project .\src\MyCompany.AuthPlatform.Api
```
