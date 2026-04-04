# Identity Provider Setup

The API host can now authenticate with either:

- `Authentication:Mode = EmbeddedIdentity`
- `Authentication:Mode = JwtBearer`

## Embedded Identity Mode

When `Authentication:Mode` is set to `EmbeddedIdentity`, the application acts as
its own local identity provider and issues bearer tokens from `POST /api/auth/token`.

Example configuration:

```json
{
  "Authentication": {
    "Mode": "EmbeddedIdentity",
    "EmbeddedIdentity": {
      "Issuer": "acmp-embedded-identity",
      "Audience": "acmp-api",
      "SigningKey": "AcmpEmbeddedIdentitySigningKey123456789!",
      "AccessTokenLifetimeMinutes": 60,
      "Users": [
        {
          "Username": "administrator.demo",
          "Password": "AdministratorPass!123",
          "DisplayName": "Demo Administrator",
          "Roles": [ "AccessAdministrator" ]
        }
      ]
    }
  }
}
```

Example token request:

```json
{
  "username": "administrator.demo",
  "password": "AdministratorPass!123"
}
```

The response contains a bearer token that can be sent to protected endpoints.

Configured bootstrap users are intended to seed the persisted admin-user store. After initial seeding, authentication should read from the stored user records rather than treating configuration as the long-term source of truth.

The embedded identity mode is intended to pair with the administrative user-management APIs:

- `GET /api/admin/users`
- `GET /api/admin/users/{userId}`
- `POST /api/admin/users`
- `POST /api/admin/users/{userId}/disable`
- `POST /api/admin/users/{userId}/reset-password`
- `PUT /api/admin/users/{userId}/roles`

Those endpoints require an `AccessAdministrator` bearer token and operate on the persisted admin-user store.

Administrative passwords currently require a minimum length of 12 characters.

## External JWT Bearer Mode

When `Authentication:Mode` is set to `JwtBearer`, configure these values in
[appsettings.json](d:/Research/acmp/src/MyCompany.AuthPlatform.Api/appsettings.json)
or environment-specific overrides:

```json
{
  "Authentication": {
    "Mode": "JwtBearer",
    "JwtBearer": {
      "Authority": "https://idp.example.com/realms/acmp",
      "Audience": "acmp-api",
      "RequireHttpsMetadata": true,
      "NameClaimType": "name",
      "RoleClaimTypes": [ "roles", "role", "groups" ],
      "ViewerRoles": [ "AccessViewer" ],
      "OperatorRoles": [ "AccessOperator" ],
      "AdministratorRoles": [ "AccessAdministrator" ]
    }
  }
}
```

## Role Mapping

The API keeps the same internal authorization policies:

- `AccessViewer`
- `AccessOperator`
- `AccessAdministrator`

In JWT mode, incoming role or group claims from the identity provider are mapped
to those internal roles before policy evaluation.

Examples:

- map an IdP group like `acmp-readers` into `ViewerRoles`
- map an IdP group like `acmp-operators` into `OperatorRoles`
- map an IdP group like `acmp-admins` into `AdministratorRoles`

If an identity provider already issues the same role names as the application,
the defaults can remain unchanged.

## Notes

- The current demo host still uses the in-memory persistence provider unless you change persistence configuration separately.
- In both `EmbeddedIdentity` and `JwtBearer` modes, the host expects a bearer token on protected endpoints.
- The endpoint authorization policies are unchanged between embedded and external JWT modes.
