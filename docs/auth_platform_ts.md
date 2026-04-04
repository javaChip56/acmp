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
- HMAC Encrypted Credential Package Issuer
- HMAC Encrypted Client Package Issuer
- HMAC Authentication Handler / Middleware
- HMAC Service Integration Library
- HMAC Client Signing Library
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
  MyCompany.AuthPlatform.Hmac/
  MyCompany.AuthPlatform.Hmac.Client/
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
| MyCompany.AuthPlatform.Api | Management endpoints and protected API hosting |
| MyCompany.AuthPlatform.Core | Shared business logic and provider orchestration |
| MyCompany.AuthPlatform.Hmac | Reusable HMAC service integration library, middleware, dual validation modes, encrypted package handling, preload policy, and runtime cache coordination |
| MyCompany.AuthPlatform.Hmac.Client | Reusable client-side HMAC signing library, encrypted client package handling, canonical request signing, and runtime cache coordination |
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
- Scopes (for example `read`, `write`, `delete`, `admin`, or equivalent business-defined permissions)
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

#### HmacCredentialPackage
Represents the encrypted file artifact issued for service-side validation.

Suggested fields:

- KeyId
- KeyVersion
- CredentialStatus
- Environment
- Scopes
- ExpiresAt
- EncryptedSecret
- PackageEncryptionMetadata
- IntegritySignature or AuthenticatedTag
- IssuedAt

#### HmacClientCredentialPackage
Represents the encrypted file artifact issued for client-side outbound signing.

Suggested fields:

- KeyId
- KeyVersion
- CredentialStatus
- Environment
- Scopes
- ExpiresAt
- HmacAlgorithm
- CanonicalSigningProfile
- EncryptedSecret
- PackageEncryptionMetadata
- IntegritySignature or AuthenticatedTag
- IssuedAt

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
The initial HMAC protocol shall use these request headers:

- X-Key-Id
- X-Timestamp
- X-Nonce
- X-Signature

Optional future headers:

- X-Signed-Headers
- X-Content-SHA256

Header names are case-insensitive in HTTP processing, but the platform documentation and .NET libraries shall emit the canonical names exactly as shown above.

### 9.2 Canonical String Model
The HMAC canonical string shall be deterministic and shall consist of exactly seven UTF-8 text lines separated by line-feed (`\n`) characters:

1. HTTP method
2. canonical path
3. canonical query string
4. body hash
5. timestamp
6. nonce
7. KeyId

Canonical template:

```text
{HTTP_METHOD}
{CANONICAL_PATH}
{CANONICAL_QUERY}
{BODY_SHA256_HEX}
{TIMESTAMP_UTC}
{NONCE}
{KEY_ID}
```

### 9.3 Normalization Rules

#### 9.3.1 HTTP Method
Use the uppercase HTTP method value exactly as sent, for example `GET`, `POST`, `PUT`, or `DELETE`.

#### 9.3.2 Canonical Path
The canonical path shall:

- include only the absolute path component
- exclude scheme, host, port, and fragment
- preserve case
- preserve trailing slash when present
- use `/` when the effective path is empty
- use UTF-8 based URI escaping with uppercase hexadecimal percent-encoding for any newly encoded bytes

No dot-segment normalization, route rewriting, or case folding shall be applied during canonicalization.

#### 9.3.3 Canonical Query String
The canonical query string shall:

- exclude the leading `?`
- preserve duplicate parameters as separate key-value pairs
- represent parameters without an explicit value as `name=`
- sort pairs by name using ordinal comparison and then by value using ordinal comparison
- percent-encode names and values using UTF-8 with uppercase hexadecimal percent-encoding
- join pairs using `&`

If no query parameters exist, the canonical query-string line is empty.

Examples:

```text
Original query: ?b=2&a=1&a=0
Canonical query: a=0&a=1&b=2
```

```text
Original query: ?flag&name=alice%20lee
Canonical query: flag=&name=alice%20lee
```

#### 9.3.4 Body Hash
The body-hash line shall be the lowercase hexadecimal SHA-256 hash of the raw request-body bytes.

For an empty or zero-length body, use the SHA-256 hash of zero bytes:

```text
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

#### 9.3.5 Timestamp
`X-Timestamp` shall use UTC formatted as `yyyy-MM-ddTHH:mm:ssZ` with no fractional seconds.

Example:

```text
2026-04-01T10:15:00Z
```

#### 9.3.6 Nonce
`X-Nonce` is included in the canonical string. If a nonce is omitted, the nonce line is empty.

The initial release does not persist nonces for replay detection, but the wire contract reserves the field so a replay store can be introduced later without changing the signing model.

#### 9.3.7 KeyId
`X-Key-Id` supplies the credential lookup key and shall be copied into the seventh line of the canonical string exactly as transmitted after header-value trimming.

### 9.4 Signature Calculation
The server and client libraries shall:

1. Build the canonical string using the rules above.
2. Encode the canonical string as UTF-8 bytes.
3. Compute `HMACSHA256` using the credential secret.
4. Encode the resulting signature bytes as lowercase hexadecimal.
5. Transmit the value in the `X-Signature` header.

Worked example:

```text
POST
/api/orders/create
account=123&mode=full
6dff39006bfd7895ec3ef56f233bcf5977a4cb6bd10e6aeb44d2169a773a886d
2026-04-01T10:15:00Z
nonce-123
key-prod-001
```

The request above is the exact canonical string payload that is converted to UTF-8 and signed.

### 9.5 Runtime Validation Flow
1. Extract HMAC headers.
2. Validate required headers.
3. Determine configured validation mode: `KmsBacked` or `EncryptedFile`.
4. Resolve HMAC credential by `KeyId`, using the service integration library cache when present.
5. In `KmsBacked` mode, on cache miss, load credential metadata from the platform and decrypt using MiniKMS.
6. In `EncryptedFile` mode, on cache miss, locate the encrypted credential package file in the configured accessible directory and decrypt/verify it using approved service-side protection material.
7. Populate the cache entry with credential metadata and decrypted secret material.
8. Validate credential status and expiry from cached or freshly loaded metadata.
9. Reconstruct canonical string.
10. Recompute signature using HMACSHA256.
11. Compare signatures using constant-time comparison.
12. Validate timestamp window.
13. Validate nonce presence and format if required by configuration; replay detection may be added in a future phase.
14. Validate assigned scopes/permissions after successful authentication.
15. Reject requests that are authenticated but do not have the required scope/permission for the requested operation.
16. Establish authenticated principal for authorized requests.

---

## 10.0 Runtime Secret Cache Design

### 10.1 Objective
The API and reusable HMAC service integration library shall not require database access and MiniKMS decryption on every authentication request.

### 10.2 Service Integration Library
The initial implementation shall provide a reusable .NET library/DLL for recipient services that:

- supports `KmsBacked` and `EncryptedFile` validation modes
- supports optional startup preload of configured active frequently-used credentials
- lazy loads credentials that are not preloaded
- uses in-memory cache for runtime authentication and authorization checks
- fails closed if required credential state cannot be loaded or refreshed

### 10.3 Encrypted File Mode
In `EncryptedFile` mode, the library shall:

- read encrypted credential package files from a configured service-accessible directory
- decrypt and integrity-check package contents using approved local protection material, such as registered service certificate or equivalent protected key material
- reject missing, tampered, expired, or unreadable package files securely
- support reload when package files are replaced or refreshed

### 10.4 Client Signing Library
The initial implementation shall provide a reusable .NET client library/DLL that:

- loads encrypted client credential package files from a configured client-accessible directory
- decrypts and integrity-checks package contents using approved local protection material
- constructs the defined canonical string model for outbound requests
- generates HMAC headers, including `KeyId`, timestamp, and optional nonce
- caches decrypted client package state in memory
- fails signing securely if required client package state cannot be loaded or refreshed

### 10.5 Cache Technology
Initial implementation shall use `IMemoryCache`.

### 10.6 Cache Key
Recommended key format:

```text
hmac-secret:{KeyId}:{KeyVersion}
```

### 10.7 Cache Value
Cache entries may contain:

- credential identifier
- credential status
- environment
- assigned scopes/permissions
- expiry timestamp
- decrypted secret bytes
- key version
- optional supporting metadata needed for validation

### 10.8 Cache TTL
The TTL shall be short and configurable. A reasonable initial default is 5 to 15 minutes.

### 10.9 Invalidation Events
Cache entries shall be invalidated when:

- credential is revoked
- credential is rotated
- credential is disabled
- credential metadata affecting validity changes
- encrypted credential package file is replaced or refreshed
- encrypted client credential package file is replaced or refreshed

### 10.10 Security Constraints
- Cache shall be memory-only.
- Decrypted secrets shall not be persisted to disk.
- Decrypted secrets shall not be logged.
- Encrypted credential package files shall be integrity-protected.
- Encrypted client credential package files shall be integrity-protected.

### 10.11 Availability Behavior
If MiniKMS is unavailable:
- cache hit authentication may continue
- cache miss authentication shall fail securely

In `EncryptedFile` mode:
- cache hit authentication may continue while cached data remains valid
- file read, decrypt, or integrity-check failure shall fail securely

In client package mode:
- cached signing operations may continue while cached data remains valid
- file read, decrypt, integrity-check, or expiry validation failure shall fail signing securely

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
- POST /api/credentials/{credentialId}/issue-encrypted-package
- POST /api/credentials/{credentialId}/issue-client-package
- GET /api/clients/{clientId}/credentials
- GET /api/audit

### 13.2 Protected Business APIs
Business APIs shall use HMAC authentication middleware rather than exposing a separate validation endpoint.

### 13.3 Client Signing Integration
Client services may use the client-side HMAC signing library rather than implementing canonical string construction and header generation directly.

### 13.4 Example HMAC Issue Response

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
- issue encrypted credential package file for `KeyId`
- issue encrypted client credential package file for `KeyId`
- authenticate valid request
- reject invalid signature
- reject revoked credential
- reject expired credential
- validate request successfully in `KmsBacked` mode
- validate request successfully in `EncryptedFile` mode
- sign outbound request successfully using client package mode
- preload configured active credentials at startup
- lazy load credentials that are not preloaded
- cache invalidation on revoke and rotate
- reload encrypted credential package file after replacement
- reload encrypted client credential package file after replacement
- reject tampered encrypted credential package file
- reject tampered encrypted client credential package file
- reject requests securely when credential state cannot be resolved on cache miss
- fail signing securely when client package state cannot be resolved
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
