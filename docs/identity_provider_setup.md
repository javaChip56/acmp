# Identity Provider Setup

The API host can now authenticate with either:

- `Authentication:Mode = DemoHeader`
- `Authentication:Mode = JwtBearer`

## JWT Bearer Mode

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
- In `JwtBearer` mode, the host expects a bearer token on protected endpoints instead of `X-Demo-Role`.
- The endpoint authorization policies are unchanged between demo and JWT modes.
