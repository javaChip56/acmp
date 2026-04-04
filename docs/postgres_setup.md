# PostgreSQL Setup

The API host can now run against the PostgreSQL persistence provider instead of
the demo-only in-memory provider.

## Configuration

Set the persistence provider to `Postgres` and configure
`Persistence:Postgres`.

Example:

```json
{
  "Persistence": {
    "Provider": "Postgres",
    "Postgres": {
      "ConnectionString": "Host=localhost;Port=5432;Database=acmp;Username=postgres;Password=postgres",
      "ApplyMigrationsOnStartup": true
    }
  }
}
```

## Notes

- `ApplyMigrationsOnStartup = true` is intended for local bootstrap and development convenience.
- The host still seeds the configured embedded-identity bootstrap users when `DemoMode:SeedOnStartup = true`.
- With PostgreSQL enabled, persisted admin users, clients, credentials, and audit entries survive application restarts.
- The SQL Server provider remains available alongside PostgreSQL and demo mode.

## Run

From the repository root:

```powershell
$env:Persistence__Provider = 'Postgres'
$env:Persistence__Postgres__ConnectionString = 'Host=localhost;Port=5432;Database=acmp;Username=postgres;Password=postgres'
$env:Persistence__Postgres__ApplyMigrationsOnStartup = 'true'
dotnet run --project .\src\MyCompany.AuthPlatform.Api
```
