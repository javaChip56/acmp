# Persistence Scaffold

This repo now includes the first code scaffold for the persistence model described in
[auth_platform_ts.md](d:/Research/acmp/docs/auth_platform_ts.md).

## Projects

- `src/MyCompany.Shared.Contracts`
  Shared enums and domain entities for `ServiceClient`, `Credential`, `CredentialScope`,
  `HmacCredentialDetail`, `AuditLogEntry`, `AdminUser`, `AdminUserRoleAssignment`,
  and related shared types.
- `src/MyCompany.AuthPlatform.Persistence.Abstractions`
  Repository contracts and query objects that define the persistence boundary used by
  the application layer.
- `src/MyCompany.AuthPlatform.Persistence.InMemory`
  Demo-only in-memory implementation of the repository contracts for temporary
  non-persistent usage.

## Notes

- The in-memory provider is meant for demos and process-lifetime storage only.
- The contracts are intentionally persistence-agnostic so MSSQL and PostgreSQL
  providers can be added behind the same interfaces.
- `CredentialScope` is modeled as its own store to keep parity across SQL Server,
  PostgreSQL, and in-memory mode without relying on provider-specific array handling.
- Admin users and role assignments are now part of the shared logical schema so the
  embedded identity provider can read from the same persisted model across SQL Server,
  PostgreSQL, and demo in-memory mode.
