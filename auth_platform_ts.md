# Internal Service Authentication Credential Management Platform
## Technical Specification (TS)
### Initial Supported Authentication Mode: HMAC

---

## 1.0 Introduction

### 1.1 Purpose
This document defines the technical design for an internal authentication credential management platform used by IT Department services. The initial implementation supports HMAC-based authentication only and is designed for future expansion to additional authentication modes such as JWT.

### 1.2 Technical Goals
The solution shall:

- provide a shared platform for internal service credential management
- implement HMAC issuance and runtime authentication in the initial release
- protect HMAC secrets using MiniKMS
- avoid MiniKMS decryption on every authentication request through cache-first design
- support a locally hosted AdminLTE-based administration portal
- avoid all external/public runtime dependencies
- support both Microsoft SQL Server and PostgreSQL via provider-based persistence

---

## 2.0 Logical Architecture

### 2.1 Shared Platform Layer
The shared platform layer shall contain:

- Admin Web Portal
- Credential Management API
- Service/Client Management
- Credential Lifecycle Services
- Scope Management
- Audit Logging
- Persistence Abstractions
- Provider Registry
- Configuration / Policy Layer

### 2.2 Initial HMAC Provider Layer
The initial HMAC provider layer shall contain:

- HMAC Credential Issuer
- HMAC Authentication Handler / Middleware
- HMAC Canonical String Builder
- HMAC Signature Validator
- HMAC Secret Cache
- MiniKMS Adapter

### 2.3 Future Provider Layer Strategy
The architecture shall allow future addition of:

- JWT Provider
- mTLS Provider
- OAuth2 Client Credentials Provider
- Kerberos Provider

Provider-specific issuance, storage, validation, and policy logic shall be isolated from the shared platform layer.

---

## 3.0 Technology Stack

| Layer | Technology |
|---|---|
| Backend | ASP.NET Core (.NET 8 preferred) |
| Admin UI | ASP.NET Core MVC / Razor Pages with AdminLTE |
| Database | Microsoft SQL Server or PostgreSQL |
| Persistence | EF Core or Dapper with provider-specific implementations |
| Cache | IMemoryCache |
| Cryptography | System.Security.Cryptography |
| Logging | Microsoft.Extensions.Logging |
| Serialization | System.Text.Json |

---

## 4.0 Solution Structure

Recommended logical solution structure:

```text
src/
  MyCompany.AuthPlatform.Web/
  MyCompany.AuthPlatform.Api/
  MyCompany.AuthPlatform.Core/
  MyCompany.AuthPlatform.Persistence.Abstractions/
  MyCompany.AuthPlatform.Persistence.SqlServer/
  MyCompany.AuthPlatform.Persistence.Postgres/
  MyCompany.Security.MiniKms/
  MyCompany.Shared.Contracts/
tests/
  MyCompany.AuthPlatform.UnitTests/
  MyCompany.AuthPlatform.IntegrationTests/
```

### 4.1 Project Responsibilities

| Project | Responsibility |
|---|---|
| MyCompany.AuthPlatform.Web | Admin portal UI |
| MyCompany.AuthPlatform.Api | Management endpoints and protected API integration |
| MyCompany.AuthPlatform.Core | Shared business logic and provider orchestration |
| MyCompany.AuthPlatform.Persistence.Abstractions | Repository contracts and persistence interfaces |
| MyCompany.AuthPlatform.Persistence.SqlServer | SQL Server implementation |
| MyCompany.AuthPlatform.Persistence.Postgres | PostgreSQL implementation |
| MyCompany.Security.MiniKms | HMAC secret protection and envelope encryption |
| MyCompany.Shared.Contracts | DTOs, contracts, enums, constants |

---

## 5.0 Domain Model

### 5.1 Common Entities

#### ServiceClient
Represents an internal service or application.

Suggested fields:

- ClientId
- ClientCode
- ClientName
- Owner
- Environment
- Status
- CreatedAt
- CreatedBy
- UpdatedAt
- UpdatedBy

#### Credential
Represents a generic authentication credential.

Suggested fields:

- CredentialId
- ClientId
- AuthenticationMode
- Status
- Environment
- Scopes
- ExpiresAt
- RevokedAt
- CreatedAt
- CreatedBy
- UpdatedAt
- UpdatedBy

### 5.2 HMAC Detail Entity

#### HmacCredentialDetail
Represents HMAC-specific credential details.

Suggested fields:

- CredentialId
- KeyId
- EncryptedSecret
- EncryptedDataKey
- KeyVersion
- HmacAlgorithm
- EncryptionAlgorithm
- Iv
- Tag
- LastUsedAt

### 5.3 Future JWT Detail Entity
Reserved for future extension, such as:

- CredentialId
- KeyReference
- Issuer
- Audience
- JwtAlgorithm
- SigningKeyReference
- PublicKeyReference

---

## 6.0 Authentication Mode Abstraction

### 6.1 AuthenticationMode Enumeration
The platform should define an authentication mode enumeration such as:

- HMAC
- JWT
- MTLS
- OAUTH2_CLIENT_CREDENTIALS
- KERBEROS
- API_KEY
- ASYMMETRIC_SIGNATURE

Only `HMAC` shall be enabled in the initial release.

### 6.2 Provider Abstraction
The shared platform layer shall depend on authentication provider abstractions rather than HMAC-specific services directly.

Example conceptual interfaces:

```csharp
public interface IAuthenticationProvider
{
    string Mode { get; }
}
```

```csharp
public interface ICredentialIssuer
{
    Task<IssueCredentialResult> IssueAsync(IssueCredentialRequest request, CancellationToken cancellationToken);
}
```

```csharp
public interface ICredentialValidator
{
    Task<ValidationResult> ValidateAsync(ValidationContext context, CancellationToken cancellationToken);
}
```

The initial implementation may keep the provider model lightweight, but naming and layering shall allow future expansion.

---

## 7.0 MiniKMS Technical Design

### 7.1 Initial Scope
MiniKMS is initially responsible for HMAC secret protection only.

### 7.2 Responsibilities
MiniKMS shall:

- generate random secret values
- perform envelope encryption
- decrypt protected HMAC secret material when required
- version master keys
- abstract master-key access

### 7.3 Master Key Handling
The master key shall not be stored in source code, repository, or database tables.

The initial implementation may use:

- Windows Certificate Store
- DPAPI-protected local secret source

### 7.4 Interfaces

```csharp
public interface IMiniKms
{
    EncryptedSecretPackage Encrypt(byte[] plaintext);
    byte[] Decrypt(EncryptedSecretPackage package);
    byte[] GenerateRandomSecret(int sizeInBytes = 32);
}
```

```csharp
public sealed class EncryptedSecretPackage
{
    public byte[] EncryptedSecret { get; init; } = default!;
    public byte[] EncryptedDataKey { get; init; } = default!;
    public string KeyVersion { get; init; } = default!;
    public string EncryptionAlgorithm { get; init; } = default!;
    public byte[]? Iv { get; init; }
    public byte[]? Tag { get; init; }
}
```

```csharp
public interface IMasterKeyProvider
{
    string GetActiveKeyVersion();
    byte[] EncryptDataKey(byte[] dataKey, string keyVersion);
    byte[] DecryptDataKey(byte[] encryptedDataKey, string keyVersion);
}
```

### 7.5 Envelope Encryption Flow
1. Generate plaintext HMAC secret.
2. Generate random data key.
3. Encrypt secret with data key.
4. Encrypt data key with master key.
5. Persist encrypted values and metadata only.

---

## 8.0 HMAC Issuance Design

### 8.1 Issuance Flow
1. Admin requests HMAC credential issuance for a client.
2. System generates a unique `KeyId`.
3. System generates a random secret using MiniKMS or secure RNG abstraction.
4. System encrypts the secret using MiniKMS envelope encryption.
5. System persists generic credential metadata and HMAC detail record.
6. System returns the plaintext secret once in the issuance response.
7. System writes an audit event.

### 8.2 Issuance Constraints
- Plaintext secret shall not be persisted.
- Plaintext secret shall not be retrievable later.
- Issuance response shall be the only time the secret is shown.

---

## 9.0 HMAC Runtime Authentication Design

### 9.1 Request Headers
Recommended initial HMAC headers:

- X-Key-Id
- X-Timestamp
- X-Nonce
- X-Signature

Optional future headers:

- X-Signed-Headers
- X-Content-SHA256

### 9.2 Canonical String Model
The HMAC canonical string shall be deterministic and shall include at minimum:

1. HTTP method
2. path
3. query string
4. body hash
5. timestamp
6. nonce
7. KeyId

Example:

```text
POST
/api/orders/create
account=123&mode=full
0f1a...
2026-04-01T10:15:00Z
nonce-123
key-prod-001
```

### 9.3 Runtime Validation Flow
1. Extract HMAC headers.
2. Validate required headers.
3. Resolve HMAC credential by `KeyId`.
4. Validate credential status and expiry.
5. Retrieve decrypted secret from cache if present.
6. On cache miss, decrypt using MiniKMS and populate cache.
7. Reconstruct canonical string.
8. Recompute signature using HMACSHA256.
9. Compare signatures using constant-time comparison.
10. Validate timestamp window.
11. Optionally validate nonce in future phase.
12. Validate scopes after successful authentication.
13. Establish authenticated principal or reject request.

---

## 10.0 Runtime Secret Cache Design

### 10.1 Objective
The API shall not require MiniKMS decryption on every authentication request.

### 10.2 Cache Technology
Initial implementation shall use `IMemoryCache`.

### 10.3 Cache Key
Recommended key format:

```text
hmac-secret:{KeyId}:{KeyVersion}
```

### 10.4 Cache Value
Cache entries may contain:

- decrypted secret bytes
- key version
- expiration timestamp
- optional supporting metadata needed for validation

### 10.5 Cache TTL
The TTL shall be configurable. A reasonable initial default is 5 to 15 minutes.

### 10.6 Invalidation Events
Cache entries shall be invalidated when:

- credential is revoked
- credential is rotated
- credential is disabled
- credential metadata affecting validity changes

### 10.7 Security Constraints
- Cache shall be memory-only.
- Decrypted secrets shall not be persisted to disk.
- Decrypted secrets shall not be logged.

### 10.8 Availability Behavior
If MiniKMS is unavailable:
- cache hit authentication may continue
- cache miss authentication shall fail securely

---

## 11.0 Web Application Design

### 11.1 UI Framework
The admin portal shall use AdminLTE.

### 11.2 No External Runtime Dependencies
The web application shall not call external/public internet resources at runtime.

### 11.3 Local Asset Hosting
All CSS, JavaScript, icons, fonts, and images required by the UI shall be hosted locally under the application or approved internal infrastructure.

Suggested local static asset structure:

```text
wwwroot/
  lib/
    adminlte/
    bootstrap/
    fontawesome/
  css/
  js/
  img/
  fonts/
```

### 11.4 Content Security Policy
The application shall be compatible with a restrictive Content Security Policy based primarily on `self`.

---

## 12.0 Persistence Design

### 12.1 Database Portability
The solution shall support Microsoft SQL Server and PostgreSQL.

### 12.2 Provider Separation
Database-specific logic shall be isolated to persistence projects.

### 12.3 Persistence Abstractions
The shared platform and MiniKMS integration shall depend on repository abstractions rather than provider-specific persistence code.

### 12.4 Schema Strategy
The schema shall preserve equivalent functional behavior across MSSQL and PostgreSQL.

Portable mapping considerations include:

- GUID / UUID
- varbinary(max) / bytea
- datetime2 / timestamptz
- JSON field handling

### 12.5 Suggested Tables

#### ServiceClient
Stores generic service/client records.

#### Credential
Stores generic credential metadata.

#### HmacCredentialDetail
Stores HMAC-specific encrypted secret material and related metadata.

#### AuditLog
Stores administrative and security events.

#### OptionalNonce
Reserved for future replay protection persistence.

---

## 13.0 API Design

### 13.1 Management APIs
Suggested initial endpoints:

- POST /api/clients
- PUT /api/clients/{clientId}
- POST /api/clients/{clientId}/credentials/hmac
- POST /api/credentials/{credentialId}/rotate
- POST /api/credentials/{credentialId}/revoke
- GET /api/clients/{clientId}/credentials
- GET /api/audit

### 13.2 Protected Business APIs
Business APIs shall use HMAC authentication middleware rather than exposing a separate validation endpoint.

### 13.3 Example HMAC Issue Response

```json
{
  "clientId": "c-1001",
  "credentialId": "cred-2001",
  "authenticationMode": "HMAC",
  "keyId": "key-prod-001",
  "secret": "base64-secret-value",
  "shownOnce": true,
  "expiresAt": "2027-04-01T00:00:00Z"
}
```

---

## 14.0 Security Design Considerations

### 14.1 Secret Handling
- No plaintext secret persistence
- No plaintext secret retrieval after issuance
- No plaintext secret logging

### 14.2 Transport Security
All admin and API endpoints shall use HTTPS.

### 14.3 Access Control
The administration portal shall enforce authenticated access and role-based authorization.

### 14.4 Environment Isolation
Separate keys, policies, and configuration shall be maintained by environment.

### 14.5 Constant-Time Comparison
Signature comparison shall use a constant-time mechanism.

---

## 15.0 Logging and Audit Design

### 15.1 Administrative Audit Events
Capture:

- client creation
- client update
- credential issuance
- credential rotation
- credential revocation
- credential disablement
- scope changes
- expiry changes

### 15.2 Security Events
Capture:

- unknown KeyId
- invalid signature
- expired credential attempt
- revoked credential attempt
- decryption failure
- cache miss surge
- timestamp failure

### 15.3 Redaction
Logs shall not contain plaintext or decrypted secret values.

---

## 16.0 Testing Strategy

### 16.1 Unit Tests
Cover:

- secret generation
- envelope encryption and decryption
- canonical string generation
- signature validation
- cache hit and miss behavior
- revoke and rotate rules

### 16.2 Integration Tests
Cover:

- issue HMAC credential
- authenticate valid request
- reject invalid signature
- reject revoked credential
- reject expired credential
- cache invalidation on revoke and rotate
- MSSQL provider behavior
- PostgreSQL provider behavior

### 16.3 Security Tests
Cover:

- timestamp skew rejection
- one-time secret reveal behavior
- no plaintext secret retrieval
- no secret leakage through logs

---

## 17.0 Out of Scope for Initial Release

The initial release shall not implement:

- JWT issuance or validation
- JWKS endpoint
- mTLS certificate lifecycle
- OAuth2 authorization server features
- Kerberos support
- distributed cache
- external KMS integration
- standalone MiniKMS service
- replay nonce persistence
- maker-checker workflow

---

## 18.0 Conclusion

This technical design defines a shared internal authentication credential management platform with an initial HMAC implementation. It provides a future-ready architecture for additional authentication modes while delivering a practical first release with MiniKMS-backed HMAC secret protection, cache-first runtime authentication, an AdminLTE internal portal with no external/public dependencies, and provider-based persistence supporting both Microsoft SQL Server and PostgreSQL.
