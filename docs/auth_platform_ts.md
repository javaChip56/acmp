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
  MyCompany.AuthPlatform.Persistence.InMemory/
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
| MyCompany.AuthPlatform.Persistence.InMemory | Demo-only non-persistent in-memory implementation of repository contracts |
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
- DisabledAt
- RevokedAt
- ReplacedByCredentialId
- RotationGraceEndsAt
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

Required envelope fields:

- SchemaVersion
- PackageType
- PackageId
- CredentialId
- KeyId
- KeyVersion
- CredentialStatus
- Environment
- ExpiresAt
- IssuedAt
- ProtectionBinding
- CryptoMetadata
- Ciphertext
- AuthTag

#### HmacClientCredentialPackage
Represents the encrypted file artifact issued for client-side outbound signing.

Required envelope fields:

- SchemaVersion
- PackageType
- PackageId
- CredentialId
- KeyId
- KeyVersion
- CredentialStatus
- Environment
- ExpiresAt
- IssuedAt
- ProtectionBinding
- CryptoMetadata
- Ciphertext
- AuthTag

The decrypted client package payload shall additionally contain:

- HmacAlgorithm
- CanonicalSigningProfileId

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

### 8.3 Credential Lifecycle State Model
The initial release should use the following persisted credential states:

- `Active`
- `Disabled`
- `Revoked`

`Expired` is an effective runtime condition derived from `ExpiresAt`, not a separate persisted status value.

#### 8.3.1 Effective Validity Rule
A credential is valid for authentication only when:

- the parent client/service is active
- the credential status is `Active`
- `RevokedAt` is not set
- `ExpiresAt` is null or later than the current UTC time
- `RotationGraceEndsAt` is null or later than the current UTC time when the credential has been superseded by a replacement

#### 8.3.2 State Transition Rules

| Operation | From State | To State | Notes |
|---|---|---|---|
| Issue credential | none | `Active` | New credentials are active on successful issuance. |
| Disable credential | `Active` | `Disabled` | Authentication fails while disabled. |
| Reactivate credential | `Disabled` | `Active` | Allowed only when the credential is not revoked and not expired. |
| Revoke credential | `Active`, `Disabled` | `Revoked` | Immediate and irreversible in the initial release. |
| Expiry reached | `Active`, `Disabled` | no stored status change | Credential becomes operationally invalid once `ExpiresAt` is in the past. |
| Rotate credential without grace | `Active`, `Disabled` | old credential becomes `Revoked`; new credential becomes `Active` | Rotation creates a replacement credential and revokes the previous one immediately. |
| Rotate credential with grace | `Active`, `Disabled` | both credentials remain `Active` until grace end; old credential is then revoked or treated as no longer valid | Rotation creates a replacement credential and allows bounded overlap for client rollout. |

#### 8.3.3 Expiry Semantics
If a credential has passed `ExpiresAt`, authentication shall reject it even if the stored status is still `Active`.

The initial release should not allow administrators to reactivate an expired credential by extending `ExpiresAt` after expiry has already occurred. A new credential should be issued or the existing credential should be rotated before expiry.

#### 8.3.4 Rotation Semantics
Rotation shall:

1. create a new credential record with a new `CredentialId`, `KeyId`, and protected secret
2. return the new secret once as part of the rotation result
3. record linkage from old credential to replacement credential where supported
4. either revoke the old credential immediately or assign a bounded `RotationGraceEndsAt` value for overlap
5. invalidate caches associated with the old credential when immediate revocation occurs, or at grace-period completion for deferred cutover
6. invalidate caches associated with the new credential package whenever replacement material is issued

If a grace period is configured:

- the replacement credential becomes valid immediately
- the superseded credential remains valid only until `RotationGraceEndsAt`
- the default grace period should be 7 days
- routine grace periods should not exceed 14 days
- the maximum permitted grace period in the initial release shall be 30 days
- grace periods longer than 14 days should require an explicit operational reason and clear audit traceability
- the superseded credential shall be rejected after the grace period ends even if its stored status is still `Active`

If no grace period is configured, the old credential shall be revoked immediately during rotation.

#### 8.3.5 Parent Client Disable Effect
If a client/service is disabled, all of its credentials shall be treated as authentication-ineligible until the parent client/service is re-enabled.

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

#### 10.4.1 Package Format Overview
The initial release should standardize both service-side and client-side HMAC package files as UTF-8 JSON envelopes containing authenticated encrypted payloads.

Recommended package file names:

- service-side validation package: `{KeyId}.service.acmppkg.json`
- client-side signing package: `{KeyId}.client.acmppkg.json`

Recommended package media types:

- service-side validation package: `application/vnd.acmp.hmac-service-package+json`
- client-side signing package: `application/vnd.acmp.hmac-client-package+json`

#### 10.4.2 Package Envelope Structure
Recommended service-side package envelope:

```json
{
  "schemaVersion": "acmp.hmac.package.v1",
  "packageType": "ServiceValidation",
  "packageId": "pkg-3001",
  "credentialId": "cred-2001",
  "keyId": "key-uat-001",
  "keyVersion": "kms-v1",
  "credentialStatus": "Active",
  "environment": "UAT",
  "expiresAt": "2027-04-01T00:00:00Z",
  "issuedAt": "2026-04-04T10:05:00Z",
  "protectionBinding": {
    "bindingType": "X509Thumbprint",
    "certificateThumbprint": "ABCD1234EF567890ABCD1234EF567890ABCD1234",
    "storeLocation": "LocalMachine",
    "storeName": "My"
  },
  "cryptoMetadata": {
    "contentEncryptionAlgorithm": "A256GCM",
    "keyEncryptionAlgorithm": "RSA-OAEP-256",
    "payloadNonce": "base64-nonce",
    "encryptedDataKey": "base64-wrapped-key"
  },
  "ciphertext": "base64-ciphertext",
  "authTag": "base64-auth-tag"
}
```

Recommended client-side package envelope:

```json
{
  "schemaVersion": "acmp.hmac.package.v1",
  "packageType": "ClientSigning",
  "packageId": "pkg-3002",
  "credentialId": "cred-2001",
  "keyId": "key-uat-001",
  "keyVersion": "kms-v1",
  "credentialStatus": "Active",
  "environment": "UAT",
  "expiresAt": "2027-04-01T00:00:00Z",
  "issuedAt": "2026-04-04T10:05:00Z",
  "protectionBinding": {
    "bindingType": "X509Thumbprint",
    "certificateThumbprint": "ABCD1234EF567890ABCD1234EF567890ABCD1234",
    "storeLocation": "LocalMachine",
    "storeName": "My"
  },
  "cryptoMetadata": {
    "contentEncryptionAlgorithm": "A256GCM",
    "keyEncryptionAlgorithm": "RSA-OAEP-256",
    "payloadNonce": "base64-nonce",
    "encryptedDataKey": "base64-wrapped-key"
  },
  "ciphertext": "base64-ciphertext",
  "authTag": "base64-auth-tag"
}
```

#### 10.4.3 Decrypted Payload Structure
The package envelope metadata remains outside the encrypted payload for routing and binding checks.

Recommended decrypted service-side payload:

```json
{
  "secretBase64": "base64-secret-value",
  "hmacAlgorithm": "HMACSHA256",
  "scopes": [
    "orders.read",
    "orders.write"
  ]
}
```

Recommended decrypted client-side payload:

```json
{
  "secretBase64": "base64-secret-value",
  "hmacAlgorithm": "HMACSHA256",
  "canonicalSigningProfileId": "acmp-hmac-v1",
  "scopes": [
    "orders.read",
    "orders.write"
  ]
}
```

#### 10.4.4 Package Protection Mechanism
The initial release should use this package protection mechanism:

1. Generate a random AES-256 content-encryption key.
2. Serialize the package payload as UTF-8 JSON.
3. Encrypt the payload using AES-GCM.
4. Wrap the AES key using RSA-OAEP-256 with the public key of the configured X.509 certificate.
5. Store certificate binding metadata in `ProtectionBinding`.
6. Store the AES-GCM ciphertext and authentication tag in the package envelope.

The DLL consumer shall:

1. locate the configured X.509 certificate from the specified certificate store
2. confirm that the certificate thumbprint matches the package binding metadata
3. unwrap the content-encryption key using the certificate private key
4. verify the AES-GCM authentication tag
5. deserialize the decrypted payload only after integrity verification succeeds

#### 10.4.5 Binding and Validation Rules
The DLL shall reject a package if any of the following is true:

- `schemaVersion` is unsupported
- `packageType` does not match the expected DLL usage mode
- required envelope fields are missing
- `credentialStatus` is not valid for use
- `expiresAt` is in the past
- the configured certificate cannot be found
- the certificate thumbprint or store metadata does not match the expected protection binding
- key unwrap or AES-GCM authentication fails
- `keyId` or `keyVersion` is inconsistent with the expected package file identity

#### 10.4.6 Package Replacement and Refresh Workflow
Recommended package replacement workflow:

1. The management API generates a new package file for the target `KeyId`.
2. The deployment or distribution process writes the new file to the target directory using a temporary file name in the same directory, such as `{KeyId}.service.acmppkg.json.tmp`.
3. After the file is fully written and flushed, the temporary file is atomically renamed or replaced over the active package file.
4. The DLL detects the file change by filesystem watcher, timestamp check, or periodic polling.
5. The DLL validates and decrypts the replacement package before promoting it to active in-memory state.
6. If validation succeeds, the DLL swaps the in-memory package state to the new package version.

#### 10.4.7 Replacement Failure Behavior
If a replacement package file is detected but fails validation, the DLL shall not promote it to active state.

If a previously loaded in-memory package state is still valid, the DLL may continue using that last known-good state until its cache entry expires or becomes invalid.

If no valid package state is available after replacement validation fails, the DLL shall fail closed.

#### 10.4.8 Rotation and Package Refresh Interaction
When a credential is rotated:

- the replacement credential package shall be issued with the new `KeyId`
- the superseded package may continue to validate only as long as the old credential remains valid under the configured grace-period rules
- after grace-period expiry or immediate revocation, the old package shall no longer be accepted even if the file remains present

#### 10.4.9 Canonical Signing Profile Identifier
The initial client package format should use `acmp-hmac-v1` as the canonical signing profile identifier.

This identifier binds the client package to the HMAC request canonicalization rules defined in section 9.

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

### 12.1.1 Demo In-Memory Mode
The solution may additionally support a demo-only in-memory persistence provider.

The in-memory provider shall:

- implement the same repository contracts as the persistent providers
- keep all data in process memory only
- be cleared on application restart or process recycle
- not be used as a production deployment target
- preserve logical behavior for demos where practical, without claiming restart durability or full database-engine equivalence

### 12.2 Provider Separation
Database-specific logic shall be isolated to persistence projects.

The in-memory demo implementation shall be isolated in its own persistence project and selected through the same abstraction boundary.

### 12.3 Persistence Abstractions
The shared platform and MiniKMS integration shall depend on repository abstractions rather than provider-specific persistence code.

### 12.4 Schema Strategy
The schema shall preserve equivalent functional behavior across MSSQL and PostgreSQL.

Portable mapping considerations include:

- GUID / UUID
- varbinary(max) / bytea
- datetime2 / timestamptz
- JSON field handling

This logical schema should be treated as the source-of-truth model for both persistent providers and the demo in-memory provider.

### 12.5 Logical Schema Overview
Recommended initial logical stores:

- `ServiceClient`
- `Credential`
- `CredentialScope`
- `HmacCredentialDetail`
- `AuditLog`
- `AdminUser`
- `AdminUserRoleAssignment`
- `OptionalNonce` reserved for future replay protection persistence

### 12.6 Logical Table Definitions

#### 12.6.1 ServiceClient
Stores generic service/client records.

| Column | Type Direction | Required | Notes |
|---|---|---|---|
| `ClientId` | GUID / UUID | Yes | Primary key. |
| `ClientCode` | string | Yes | Human-meaningful stable code; unique within environment. |
| `ClientName` | string | Yes | Display name. |
| `Owner` | string | Yes | Accountable team or function. |
| `Environment` | string | Yes | `DEV`, `TEST`, `UAT`, or `PROD`. |
| `Status` | string | Yes | Recommended values: `Active`, `Disabled`. |
| `Description` | string | No | Free-text description. |
| `MetadataJson` | JSON / text | No | Extensible descriptive metadata. |
| `DisabledAt` | UTC timestamp | No | Set when client/service is disabled. |
| `CreatedAt` | UTC timestamp | Yes | Creation timestamp. |
| `CreatedBy` | string | Yes | Actor identifier. |
| `UpdatedAt` | UTC timestamp | Yes | Last update timestamp. |
| `UpdatedBy` | string | Yes | Last update actor. |
| `ConcurrencyToken` | rowversion / xmin / opaque token | No | Optimistic concurrency support. |

Recommended constraints and indexes:

- primary key on `ClientId`
- unique index on (`Environment`, `ClientCode`)
- index on (`Environment`, `Status`)

#### 12.6.2 Credential
Stores generic credential metadata and lifecycle state.

| Column | Type Direction | Required | Notes |
|---|---|---|---|
| `CredentialId` | GUID / UUID | Yes | Primary key. |
| `ClientId` | GUID / UUID | Yes | Foreign key to `ServiceClient.ClientId`. |
| `AuthenticationMode` | string | Yes | Initial value `HMAC`. |
| `Status` | string | Yes | Persisted states: `Active`, `Disabled`, `Revoked`. |
| `Environment` | string | Yes | Should match parent client environment. |
| `ExpiresAt` | UTC timestamp | No | Effective expiry boundary. |
| `DisabledAt` | UTC timestamp | No | Set when credential is disabled. |
| `RevokedAt` | UTC timestamp | No | Set when revoked. |
| `ReplacedByCredentialId` | GUID / UUID | No | Self-reference to replacement credential after rotation. |
| `RotationGraceEndsAt` | UTC timestamp | No | Grace overlap end for superseded credential. |
| `Notes` | string | No | Administrative note or issuance reason. |
| `CreatedAt` | UTC timestamp | Yes | Creation timestamp. |
| `CreatedBy` | string | Yes | Actor identifier. |
| `UpdatedAt` | UTC timestamp | Yes | Last update timestamp. |
| `UpdatedBy` | string | Yes | Last update actor. |
| `ConcurrencyToken` | rowversion / xmin / opaque token | No | Optimistic concurrency support. |

Recommended constraints and indexes:

- primary key on `CredentialId`
- foreign key from `ClientId` to `ServiceClient.ClientId`
- foreign key from `ReplacedByCredentialId` to `Credential.CredentialId`
- index on (`ClientId`, `Status`)
- index on (`Environment`, `AuthenticationMode`, `Status`)
- index on (`ExpiresAt`)
- check rule that `RotationGraceEndsAt`, when present, is later than `CreatedAt`

#### 12.6.3 CredentialScope
Stores assigned scopes or permissions for a credential as individual rows rather than embedded database-specific arrays.

| Column | Type Direction | Required | Notes |
|---|---|---|---|
| `CredentialId` | GUID / UUID | Yes | Foreign key to `Credential.CredentialId`. |
| `ScopeName` | string | Yes | For example `orders.read`. |
| `CreatedAt` | UTC timestamp | Yes | Assignment timestamp. |
| `CreatedBy` | string | Yes | Actor identifier. |

Recommended constraints and indexes:

- composite primary key on (`CredentialId`, `ScopeName`)
- foreign key from `CredentialId` to `Credential.CredentialId`
- index on (`ScopeName`)

#### 12.6.4 HmacCredentialDetail
Stores HMAC-specific encrypted secret material and related metadata.

| Column | Type Direction | Required | Notes |
|---|---|---|---|
| `CredentialId` | GUID / UUID | Yes | Primary key and foreign key to `Credential.CredentialId`. |
| `KeyId` | string | Yes | Public lookup key used at runtime. |
| `EncryptedSecret` | binary | Yes | Encrypted HMAC secret bytes. |
| `EncryptedDataKey` | binary | Yes | Envelope-encrypted data key. |
| `KeyVersion` | string | Yes | Master-key version identifier. |
| `HmacAlgorithm` | string | Yes | Initial value `HMACSHA256`. |
| `EncryptionAlgorithm` | string | Yes | Envelope-encryption algorithm identifier. |
| `Iv` | binary | No | IV or nonce for encryption mode when required. |
| `Tag` | binary | No | Authenticated encryption tag when required. |
| `LastUsedAt` | UTC timestamp | No | Operational telemetry field. |

Recommended constraints and indexes:

- primary key on `CredentialId`
- foreign key from `CredentialId` to `Credential.CredentialId`
- unique index on `KeyId`
- index on (`KeyVersion`)

#### 12.6.5 AdminUser
Stores local administrative identities for the embedded identity provider and management operations.

| Column | Type Direction | Required | Notes |
|---|---|---|---|
| `UserId` | GUID / UUID | Yes | Primary key. |
| `Username` | string | Yes | Stable login name; unique across the platform. |
| `DisplayName` | string | Yes | Friendly display name shown in audit and admin UI. |
| `Status` | string | Yes | Recommended values: `Active`, `Disabled`. |
| `PasswordHash` | binary | Yes | Password-derived hash bytes; plaintext passwords shall not be stored. |
| `PasswordSalt` | binary | Yes | Random salt used for password hashing. |
| `PasswordHashAlgorithm` | string | Yes | Initial value `PBKDF2-SHA256`. |
| `PasswordIterations` | integer | Yes | Hashing work factor. |
| `LastLoginAt` | UTC timestamp | No | Last successful token issuance/login time. |
| `CreatedAt` | UTC timestamp | Yes | Creation timestamp. |
| `CreatedBy` | string | Yes | Actor identifier. |
| `UpdatedAt` | UTC timestamp | Yes | Last update timestamp. |
| `UpdatedBy` | string | Yes | Last update actor. |
| `ConcurrencyToken` | rowversion / xmin / opaque token | No | Optimistic concurrency support. |

Recommended constraints and indexes:

- primary key on `UserId`
- unique index on `Username`
- index on (`Status`, `Username`)

#### 12.6.6 AdminUserRoleAssignment
Stores assigned administrative roles as individual rows to preserve portability across SQL Server, PostgreSQL, and in-memory mode.

| Column | Type Direction | Required | Notes |
|---|---|---|---|
| `UserId` | GUID / UUID | Yes | Foreign key to `AdminUser.UserId`. |
| `RoleName` | string | Yes | Expected values include `AccessViewer`, `AccessOperator`, and `AccessAdministrator`. |
| `CreatedAt` | UTC timestamp | Yes | Assignment timestamp. |
| `CreatedBy` | string | Yes | Actor identifier. |

Recommended constraints and indexes:

- composite primary key on (`UserId`, `RoleName`)
- foreign key from `UserId` to `AdminUser.UserId`
- index on (`RoleName`)

#### 12.6.7 AuditLog
Stores administrative and security events.

| Column | Type Direction | Required | Notes |
|---|---|---|---|
| `AuditId` | GUID / UUID | Yes | Primary key. |
| `Timestamp` | UTC timestamp | Yes | Event time. |
| `Actor` | string | Yes | User, service, or system actor. |
| `Action` | string | Yes | For example `CredentialIssued`, `CredentialRotated`, `InvalidSignature`. |
| `TargetType` | string | Yes | For example `Client`, `Credential`, `Package`. |
| `TargetId` | string | No | Related entity identifier. |
| `Environment` | string | No | Event environment context. |
| `Reason` | string | No | Administrative reason when supplied. |
| `Outcome` | string | No | Recommended values such as `Succeeded`, `Rejected`, `Failed`. |
| `CorrelationId` | string | No | Cross-request trace identifier. |
| `MetadataJson` | JSON / text | No | Structured non-secret event details. |

Recommended constraints and indexes:

- primary key on `AuditId`
- index on (`Timestamp`)
- index on (`TargetType`, `TargetId`)
- index on (`Actor`, `Timestamp`)
- index on (`Action`, `Timestamp`)

#### 12.6.8 OptionalNonce
Reserved for future replay protection persistence and not required for the initial release implementation.

Suggested future fields:

- `NonceId`
- `KeyId`
- `NonceValue`
- `SeenAt`
- `ExpiresAt`

### 12.7 Relationship Rules
Recommended relationship rules:

- one `ServiceClient` may have many `Credential` rows
- one `Credential` may have many `CredentialScope` rows
- one `Credential` in `HMAC` mode shall have exactly one `HmacCredentialDetail` row
- one `Credential` may reference one replacement credential through `ReplacedByCredentialId`
- one `AdminUser` may have many `AdminUserRoleAssignment` rows
- audit events may reference clients, credentials, packages, or platform operations without strict foreign-key coupling for all target types

### 12.8 Logical Integrity Rules
Recommended initial integrity rules:

- `Credential.Environment` should equal the parent `ServiceClient.Environment`
- `RevokedAt` should be set when `Status = Revoked`
- `DisabledAt` should be set when `Status = Disabled`
- `ReplacedByCredentialId` should not equal `CredentialId`
- `RotationGraceEndsAt` should be null unless the credential has been superseded by a replacement
- scopes should be unique per credential
- admin usernames should be unique platform-wide
- embedded-identity password hashes and salts should always be stored together and never as plaintext
- no table or column shall store plaintext secrets

Some of these rules may be enforced partly in application services rather than only in database constraints to preserve portability.

### 12.9 Demo In-Memory Provider Behavior
The demo in-memory provider should model the same logical collections as the persistent schema:

- service clients keyed by `ClientId`
- credentials keyed by `CredentialId`
- credential scopes keyed by (`CredentialId`, `ScopeName`)
- HMAC details keyed by `CredentialId`
- admin users keyed by `UserId`
- admin user roles keyed by (`UserId`, `RoleName`)
- audit events keyed by `AuditId`

Additional demo-mode rules:

- data exists only for the current process lifetime
- startup state may be empty or seeded from static demo fixtures
- bootstrap admin users may be seeded from configuration into the in-memory store during startup
- restart durability, migration history, and provider-specific SQL behavior do not apply
- the provider should still enforce uniqueness, lifecycle rules, and secret-handling rules in memory

### 12.10 Persistence Technology Direction
If EF Core is selected, the SQL Server, PostgreSQL, and in-memory demo providers should share the same logical entity model while keeping provider-specific configuration isolated.

If Dapper is selected, the repository contracts and SQL scripts should still preserve the schema and behavior described above.

---

## 13.0 API Design

### 13.1 API Conventions
The management API should use JSON request and response bodies encoded as UTF-8.

Recommended initial conventions:

- use `application/json` for request and response payloads
- use `camelCase` for JSON property names
- use ISO 8601 UTC timestamps in the format `yyyy-MM-ddTHH:mm:ssZ`
- use stable string enums for externally visible values such as credential status and authentication mode
- use `id` values as opaque identifiers rather than client-derived meaning
- include a correlation identifier header such as `X-Correlation-Id` when available

### 13.2 Management APIs
Suggested initial endpoints:

- POST /api/auth/token
- GET /api/admin/users
- GET /api/admin/users/{userId}
- POST /api/admin/users
- POST /api/admin/users/{userId}/disable
- POST /api/admin/users/{userId}/reset-password
- PUT /api/admin/users/{userId}/roles
- POST /api/clients
- PUT /api/clients/{clientId}
- POST /api/clients/{clientId}/disable
- POST /api/clients/{clientId}/credentials/hmac
- PUT /api/credentials/{credentialId}
- POST /api/credentials/{credentialId}/disable
- POST /api/credentials/{credentialId}/rotate
- POST /api/credentials/{credentialId}/revoke
- POST /api/credentials/{credentialId}/issue-encrypted-package
- POST /api/credentials/{credentialId}/issue-client-package
- GET /api/clients/{clientId}/credentials
- GET /api/audit

### 13.3 Example DTOs

#### 13.3.1 Administrative Token Request

```json
{
  "username": "administrator.demo",
  "password": "AdministratorPass!123"
}
```

#### 13.3.2 Administrative Token Response

```json
{
  "accessToken": "eyJhbGciOi...",
  "tokenType": "Bearer",
  "expiresAt": "2026-04-04T12:00:00Z",
  "username": "administrator.demo",
  "displayName": "Demo Administrator",
  "roles": [
    "AccessAdministrator"
  ]
}
```

#### 13.3.3 Create Administrative User Request

```json
{
  "username": "auditor.demo",
  "displayName": "Demo Auditor",
  "password": "AuditorPass!123",
  "roles": [
    "AccessViewer"
  ]
}
```

Validation notes:

- `username` should be unique across persisted administrative users
- `password` should satisfy the configured password policy
- `roles` should contain one or more supported administrative roles

#### 13.3.4 Administrative User Response

```json
{
  "userId": "u-1001",
  "username": "auditor.demo",
  "displayName": "Demo Auditor",
  "status": "Active",
  "lastLoginAt": null,
  "roles": [
    "AccessViewer"
  ],
  "createdAt": "2026-04-04T11:00:00Z",
  "updatedAt": "2026-04-04T11:00:00Z"
}
```

#### 13.3.5 Administrative User List Response

```json
[
  {
    "userId": "u-1001",
    "username": "auditor.demo",
    "displayName": "Demo Auditor",
    "status": "Active",
    "lastLoginAt": null,
    "roles": [
      "AccessViewer"
    ],
    "createdAt": "2026-04-04T11:00:00Z",
    "updatedAt": "2026-04-04T11:00:00Z"
  }
]
```

#### 13.3.6 Disable Administrative User Request

```json
{
  "reason": "Demo access no longer required"
}
```

#### 13.3.7 Reset Administrative User Password Request

```json
{
  "newPassword": "UpdatedPass!123",
  "reason": "Temporary credential reset during onboarding"
}
```

#### 13.3.8 Assign Administrative User Roles Request

```json
{
  "roles": [
    "AccessViewer",
    "AccessOperator"
  ],
  "reason": "Expanded platform support duties"
}
```

#### 13.3.9 Create Client Request

```json
{
  "clientCode": "orders-api",
  "clientName": "Orders API",
  "owner": "Integration Team",
  "environment": "UAT",
  "description": "Internal order-processing API",
  "metadata": {
    "businessUnit": "Operations",
    "contactEmail": "orders-team@example.internal"
  }
}
```

Validation notes:

- `clientCode` should be unique within an environment
- `environment` should be one of `DEV`, `TEST`, `UAT`, or `PROD`
- `owner` should capture the accountable support team or function

#### 13.3.8 Create Client Response

```json
{
  "clientId": "c-1001",
  "clientCode": "orders-api",
  "clientName": "Orders API",
  "owner": "Integration Team",
  "environment": "UAT",
  "status": "Active",
  "description": "Internal order-processing API",
  "metadata": {
    "businessUnit": "Operations",
    "contactEmail": "orders-team@example.internal"
  },
  "createdAt": "2026-04-04T09:30:00Z",
  "createdBy": "admin.user"
}
```

#### 13.3.9 Update Client Request

```json
{
  "clientName": "Orders API",
  "owner": "Integration Platform Team",
  "description": "Internal order-processing API for service-to-service calls",
  "metadata": {
    "businessUnit": "Operations",
    "contactEmail": "integration-platform@example.internal"
  }
}
```

#### 13.3.10 Issue HMAC Credential Request

```json
{
  "expiresAt": "2027-04-01T00:00:00Z",
  "scopes": [
    "orders.read",
    "orders.write"
  ],
  "issueEncryptedValidationPackage": true,
  "issueEncryptedClientPackage": false,
  "hmacAlgorithm": "HMACSHA256",
  "notes": "Primary UAT credential"
}
```

Validation notes:

- `scopes` should contain unique values
- `expiresAt` should be in the future when supplied
- `hmacAlgorithm` should initially allow only `HMACSHA256`

#### 13.3.11 Issue HMAC Credential Response

```json
{
  "clientId": "c-1001",
  "credentialId": "cred-2001",
  "authenticationMode": "HMAC",
  "status": "Active",
  "keyId": "key-uat-001",
  "keyVersion": "kms-v1",
  "secret": "base64-secret-value",
  "shownOnce": true,
  "scopes": [
    "orders.read",
    "orders.write"
  ],
  "expiresAt": "2027-04-01T00:00:00Z",
  "issuedAt": "2026-04-04T10:00:00Z"
}
```

The `secret` field is returned only during issuance and shall not be returned by later read or list operations.

#### 13.3.12 Update Credential Request

```json
{
  "status": "Active",
  "expiresAt": "2027-06-30T00:00:00Z",
  "scopes": [
    "orders.read"
  ],
  "reason": "Scope reduction after access review"
}
```

#### 13.3.13 Rotate Credential Request

```json
{
  "expiresAt": "2027-10-01T00:00:00Z",
  "gracePeriodEndsAt": "2026-04-11T00:00:00Z",
  "issueEncryptedValidationPackage": true,
  "issueEncryptedClientPackage": true,
  "reason": "Scheduled quarterly rotation"
}
```

Validation notes:

- `gracePeriodEndsAt` is optional
- when supplied, `gracePeriodEndsAt` should be later than the current UTC time
- `gracePeriodEndsAt` should be earlier than the old credential expiry time when the old credential has an expiry
- if omitted, the platform should apply the default overlap policy of 7 days only when overlap is requested by the rotation workflow; otherwise immediate revocation applies
- routine grace periods should not exceed 14 days
- the maximum allowed grace-period duration in the initial release should be 30 days
- requests exceeding 14 days should require an explicit operational reason

#### 13.3.14 Revoke Credential Request

```json
{
  "reason": "Suspected credential exposure"
}
```

#### 13.3.15 Encrypted Package Issuance Response

```json
{
  "credentialId": "cred-2001",
  "keyId": "key-uat-001",
  "packageType": "ServiceValidation",
  "fileName": "key-uat-001.service.acmppkg.json",
  "contentType": "application/vnd.acmp.hmac-service-package+json",
  "issuedAt": "2026-04-04T10:05:00Z",
  "keyVersion": "kms-v1"
}
```

For browser-based admin workflows, the binary file may be returned as a download stream with metadata reflected in response headers.

#### 13.3.16 Credential Metadata List Response

```json
{
  "clientId": "c-1001",
  "items": [
    {
      "credentialId": "cred-2001",
      "authenticationMode": "HMAC",
      "status": "Active",
      "keyId": "key-uat-001",
      "keyVersion": "kms-v1",
      "replacedByCredentialId": "cred-2002",
      "rotationGraceEndsAt": "2026-04-11T00:00:00Z",
      "scopes": [
        "orders.read",
        "orders.write"
      ],
      "expiresAt": "2027-04-01T00:00:00Z",
      "revokedAt": null,
      "updatedAt": "2026-04-04T10:00:00Z"
    }
  ],
  "page": 1,
  "pageSize": 50,
  "totalCount": 1
}
```

List operations shall not include plaintext secret values.

#### 13.3.11 Audit List Response

```json
{
  "items": [
    {
      "auditId": "aud-9001",
      "timestamp": "2026-04-04T10:00:00Z",
      "actor": "admin.user",
      "action": "CredentialIssued",
      "targetType": "Credential",
      "targetId": "cred-2001",
      "reason": "Primary UAT credential",
      "environment": "UAT"
    }
  ],
  "page": 1,
  "pageSize": 100,
  "totalCount": 1
}
```

### 13.4 Error Model
Management APIs should return structured error responses for validation, authorization, state, and infrastructure failures.

Recommended error payload:

```json
{
  "errorCode": "credential_not_found",
  "message": "The specified credential could not be found.",
  "correlationId": "3f5d8e4b2dfc4f2d8c4d511e4ab2ab0a",
  "details": [
    {
      "field": "credentialId",
      "issue": "No matching credential exists."
    }
  ]
}
```

Recommended initial error codes:

| HTTP Status | Error Code | Meaning |
|---|---|---|
| 400 | `invalid_request` | Request payload or parameters are malformed. |
| 400 | `validation_error` | Required authentication or administrative input is missing. |
| 400 | `invalid_timestamp_format` | Timestamp value does not match the required UTC format. |
| 400 | `invalid_scope_assignment` | Scope list is empty, duplicated, or contains unsupported values. |
| 400 | `invalid_admin_role_assignment` | Administrative role list is empty or contains unsupported values. |
| 400 | `password_policy_invalid` | Administrative password does not satisfy the configured password policy. |
| 401 | `admin_authentication_required` | Caller is not authenticated to use the management API. |
| 401 | `invalid_credentials` | Administrative username or password is invalid. |
| 403 | `admin_access_denied` | Caller is authenticated but lacks required administrative permission. |
| 403 | `audit_access_denied` | Caller is authenticated but is not permitted to view audit data. |
| 403 | `extended_grace_period_not_allowed` | Caller is authenticated but is not permitted to request a grace period longer than 14 days. |
| 403 | `forbidden` | Administrative identity is authenticated but has no usable assigned roles. |
| 404 | `admin_user_not_found` | Requested administrative user does not exist. |
| 404 | `client_not_found` | Requested client record does not exist. |
| 404 | `credential_not_found` | Requested credential does not exist. |
| 409 | `admin_username_conflict` | An administrative user with the same username already exists. |
| 409 | `admin_user_already_disabled` | Requested disable operation targets an already disabled administrative user. |
| 409 | `client_code_conflict` | A client with the same code already exists in the target environment. |
| 409 | `credential_state_conflict` | Requested lifecycle operation is not valid for the current credential state. |
| 409 | `credential_already_revoked` | Requested operation cannot be completed because the credential is already revoked. |
| 409 | `credential_already_disabled` | Requested disable operation targets an already disabled credential. |
| 409 | `credential_expired_cannot_activate` | Requested activation or update would attempt to reactivate an already expired credential. |
| 409 | `key_id_conflict` | Generated or supplied `KeyId` conflicts with an existing credential. |
| 422 | `rotation_grace_period_invalid` | Requested grace period violates ordering or policy rules. |
| 422 | `unsupported_authentication_mode` | Requested authentication mode is not enabled in the current release. |
| 422 | `unsupported_hmac_algorithm` | Requested HMAC algorithm is not supported. |
| 422 | `credential_expiry_invalid` | Credential expiry value violates policy. |
| 500 | `kms_operation_failed` | Secret generation, encryption, or decryption failed. |
| 500 | `package_issuance_failed` | Encrypted package could not be created or streamed securely. |
| 503 | `persistence_unavailable` | Required database or persistence dependency is unavailable. |

The API should avoid leaking sensitive internal details in error messages. Detailed diagnostics may be written to protected logs with the correlation identifier.

### 13.5 Protected Business APIs
Business APIs shall use HMAC authentication middleware rather than exposing a separate validation endpoint.

### 13.6 Client Signing Integration
Client services may use the client-side HMAC signing library rather than implementing canonical string construction and header generation directly.

### 13.7 Example HMAC Issue Response

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

#### 14.3.1 Administrative Identity Requirement
The administration portal and management API should rely on authenticated internal administrative identities.

The initial release may satisfy this either through an embedded identity provider backed by persisted administrative users or through an external JWT bearer identity provider when one is available.

In embedded mode, administrative authentication should issue bearer tokens from `POST /api/auth/token` against the persisted `AdminUser` and `AdminUserRoleAssignment` records.

#### 14.3.2 Administrative Roles
The initial release should implement the following administrative roles:

| Role | Purpose |
|---|---|
| `AccessViewer` | Read-only access to service/client access listings and credential metadata listings. |
| `AccessOperator` | Credential lifecycle operator for standard issuance, rotation, revocation, and package issuance with normal grace periods. |
| `AccessAdministrator` | Elevated operator role that can authorize extended grace periods and view audit data. |

#### 14.3.3 Role Capability Matrix

| Capability | AccessViewer | AccessOperator | AccessAdministrator |
|---|---|---|---|
| View service/client access listings | Yes | Yes | Yes |
| View credential metadata listings | Yes | Yes | Yes |
| Issue credentials | No | Yes | Yes |
| Rotate credentials | No | Yes | Yes |
| Revoke credentials | No | Yes | Yes |
| Disable credentials | No | Yes | Yes |
| Issue encrypted packages | No | Yes | Yes |
| Configure grace period from 7 to 14 days | No | Yes | Yes |
| Configure grace period longer than 14 days up to 30 days | No | No | Yes |
| View audit data | No | No | Yes |
| List and view administrative users | No | No | Yes |
| Create administrative users | No | No | Yes |
| Disable administrative users | No | No | Yes |
| Reset administrative passwords | No | No | Yes |
| Assign or replace administrative roles | No | No | Yes |

#### 14.3.4 Endpoint Authorization Direction
Recommended initial endpoint authorization:

- `POST /api/auth/token`: anonymous caller in embedded-identity mode only
- `GET /api/admin/users`: `AccessAdministrator` only
- `GET /api/admin/users/{userId}`: `AccessAdministrator` only
- `POST /api/admin/users`: `AccessAdministrator` only
- `POST /api/admin/users/{userId}/disable`: `AccessAdministrator` only
- `POST /api/admin/users/{userId}/reset-password`: `AccessAdministrator` only
- `PUT /api/admin/users/{userId}/roles`: `AccessAdministrator` only
- `GET /api/clients`: `AccessViewer`, `AccessOperator`, or `AccessAdministrator`
- `GET /api/clients/{clientId}`: `AccessViewer`, `AccessOperator`, or `AccessAdministrator`
- `GET /api/clients/{clientId}/credentials`: `AccessViewer`, `AccessOperator`, or `AccessAdministrator`
- `GET /api/credentials/{credentialId}`: `AccessViewer`, `AccessOperator`, or `AccessAdministrator`
- `POST /api/clients`: `AccessOperator` or `AccessAdministrator`
- `POST /api/clients/{clientId}/credentials/hmac`: `AccessOperator` or `AccessAdministrator`
- `PUT /api/credentials/{credentialId}`: `AccessOperator` or `AccessAdministrator`
- `POST /api/credentials/{credentialId}/disable`: `AccessOperator` or `AccessAdministrator`
- `POST /api/credentials/{credentialId}/rotate`: `AccessOperator` or `AccessAdministrator`, with `AccessAdministrator` required for grace periods longer than 14 days
- `POST /api/credentials/{credentialId}/revoke`: `AccessOperator` or `AccessAdministrator`
- `POST /api/credentials/{credentialId}/issue-encrypted-package`: `AccessOperator` or `AccessAdministrator`
- `POST /api/credentials/{credentialId}/issue-client-package`: `AccessOperator` or `AccessAdministrator`
- `GET /api/audit`: `AccessAdministrator` only

#### 14.3.5 Extended Grace-Period Authorization
Requests for a grace period longer than 14 days should require:

- an authenticated caller in the `AccessAdministrator` role
- an explicit operational reason recorded with the rotation request
- audit logging of the acting role, requested grace period, and outcome

Because maker-checker workflow is out of scope for the initial release, no separate approval queue is required. The `AccessAdministrator` authorization decision acts as the approval for grace periods longer than 14 days.

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
- extended grace-period requests and outcomes
- acting administrative role for privileged credential lifecycle operations

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
- reject disabled credential
- reject revoked credential
- reject expired credential
- reject requests for a disabled client/service
- validate request successfully in `KmsBacked` mode
- validate request successfully in `EncryptedFile` mode
- sign outbound request successfully using client package mode
- preload configured active credentials at startup
- lazy load credentials that are not preloaded
- reactivate disabled credential successfully before expiry
- reject reactivation of revoked credential
- reject reactivation of expired credential
- cache invalidation on revoke and rotate
- rotate credential with no grace period and reject the old credential immediately
- rotate credential with grace period and accept both credentials until grace-period expiry
- reject grace periods longer than 14 days for `AccessOperator`
- allow grace periods longer than 14 days up to 30 days for `AccessAdministrator`
- reject audit access for non-administrative roles
- allow audit access for `AccessAdministrator`
- authenticate persisted administrative user and issue token
- create administrative user and persist assigned roles
- reject duplicate administrative username
- reset administrative user password and invalidate old password
- disable administrative user and reject subsequent login
- replace administrative role assignments successfully
- reject the superseded credential after grace-period expiry
- reject package with unsupported schema version
- reject package bound to the wrong certificate protection context
- load replacement package only after successful validation and decryption
- reload encrypted credential package file after replacement
- reload encrypted client credential package file after replacement
- reject tampered encrypted credential package file
- reject tampered encrypted client credential package file
- reject requests securely when credential state cannot be resolved on cache miss
- fail signing securely when client package state cannot be resolved
- in-memory demo provider behavior
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
