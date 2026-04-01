# Internal Service Authentication Credential Management Platform
## Realigned Requirements Baseline

## 1. Purpose

The platform shall provide a centralized internal system for managing authentication credentials used between IT Department services.

The platform shall standardize:

- service/client registration
- credential issuance and lifecycle
- authentication policy enforcement
- audit and governance
- provider-specific authentication extensions

The initial release shall support **HMAC-based authentication only**.

The platform shall be designed so that additional authentication modes, including **JWT**, can be added later without major redesign of the core platform.

---

## 2. Scope

### 2.1 Initial Release Scope
The initial release shall implement:

- internal service/client registration
- HMAC credential issuance
- HMAC secret protection using .NET MiniKMS
- HMAC credential rotation, revocation, disablement, and expiry
- HMAC request authentication
- cache-first authentication flow so runtime auth does not require MiniKMS decryption on every request
- scope and authorization metadata
- audit logging
- AdminLTE-based admin web portal
- zero dependency on external/public internet resources
- persistence portability for MSSQL and PostgreSQL

### 2.2 Future Expansion Scope
The platform architecture shall support future addition of:

- JWT
- mTLS
- OAuth2 Client Credentials
- Kerberos / Windows Integrated Authentication
- API Key
- Asymmetric request signing

These are out of scope for the initial release, but the design shall allow them to be introduced through provider-specific extensions.

---

## 3. Product Principles

The platform shall follow these principles:

- **HMAC-first, not HMAC-only**
- **shared platform capabilities separated from auth-mode-specific logic**
- **secure by default**
- **no plaintext secret persistence**
- **no public internet dependency**
- **provider-agnostic core design**
- **database-agnostic persistence model**
- **future extensibility for JWT and other modes**

---

## 4. Authentication Scope

### 4.1 Initial Authentication Mode
The platform shall initially support:

- `HMAC`

### 4.2 Future Authentication Modes
The platform should be designed to support future modes such as:

- `JWT`
- `MTLS`
- `OAUTH2_CLIENT_CREDENTIALS`
- `KERBEROS`
- `API_KEY`
- `ASYMMETRIC_SIGNATURE`

### 4.3 Extensibility Requirement
Authentication-method-specific logic shall be isolated behind provider abstractions so that new modes can be added later with minimal change to the shared platform layer.

---

## 5. Shared Platform Capabilities

These capabilities shall be generic and not tightly coupled to HMAC.

### 5.1 Service / Client Registration
The platform shall support:

- create service/client
- update service/client metadata
- disable service/client
- assign environment
- assign owner
- assign descriptive metadata

### 5.2 Credential Lifecycle Management
The platform shall support:

- create credential
- activate / disable credential
- rotate credential
- revoke credential
- expire credential
- list credential metadata
- support multiple credentials per client where applicable

### 5.3 Scope / Authorization Metadata
The platform shall support:

- assigning scopes/permissions to credentials
- assigning scopes/permissions to HMAC credentials in the initial release
- supporting operation-level permissions such as `read`, `write`, `delete`, or equivalent business-defined permissions
- enforcing authorization after successful authentication
- rejecting requests that authenticate successfully but do not have the required scope/permission
- future provider-specific policy extension

### 5.4 Audit and Governance
The platform shall support:

- audit logging of administrative actions
- audit logging of security events
- traceability by actor, action, target, timestamp, and reason
- no logging of plaintext secrets or decrypted sensitive values

### 5.5 Environment Segregation
The platform shall support separate environments such as:

- DEV
- TEST
- UAT
- PROD

Credentials, keys, policies, and secrets must be segregated by environment.

---

## 6. HMAC-Specific Initial Requirements

These requirements apply to the initial release.

### 6.1 HMAC Credential Issuance
When issuing an HMAC credential, the platform shall:

- generate a unique `KeyId`
- generate a cryptographically secure random secret
- protect the secret using MiniKMS before persistence
- store only encrypted secret material and related metadata
- show the plaintext secret once only at issuance time

The platform shall not support later retrieval of the plaintext secret.

### 6.2 HMAC Verification
The platform shall support runtime HMAC authentication by:

- reading HMAC request headers
- resolving the credential by `KeyId`
- validating status and expiry
- reconstructing a canonical string
- recomputing HMAC using the protected secret
- comparing signatures using constant-time comparison
- validating timestamp
- supporting future nonce validation

### 6.3 HMAC Runtime Performance
The platform shall not require MiniKMS decryption on every authentication request.

It shall support:

- a service-consumable .NET library for HMAC authentication integration
- optional startup preload of configured active frequently-used credentials
- lazy loading of credentials that are not preloaded
- in-memory cache of decrypted HMAC secrets
- in-memory cache entries that store credential metadata and decrypted secret material together
- cache key based on `KeyId` and `KeyVersion`
- short configurable TTL
- invalidation on revoke, rotate, disable, or credential update
- memory-only secret caching with no disk persistence
- fail-closed behavior when credential state cannot be resolved, refreshed, or validated

### 6.4 HMAC Canonical Signing
The HMAC implementation shall define a deterministic canonical signing model including:

- HTTP method
- path
- query string
- body hash
- timestamp
- nonce
- KeyId

---

## 7. MiniKMS Requirements

MiniKMS is initially used for **HMAC secret protection**.

### 7.1 MiniKMS Responsibilities
MiniKMS shall:

- generate secure random secret values
- perform envelope encryption
- decrypt protected secret values when required
- support key versioning
- abstract master-key access

### 7.2 MiniKMS Scope
MiniKMS shall initially be scoped for HMAC secret protection.

Future authentication modes such as JWT may use different key-management approaches, so the platform shall not assume MiniKMS is the only future cryptographic mechanism.

### 7.3 Master Key Protection
The master key must not be stored in:

- source code
- repository
- plaintext config
- application code constants
- database tables

---

## 8. Web Application Requirements

### 8.1 UI Framework
The admin web portal shall use **AdminLTE**.

### 8.2 No External Resource Policy
The web application shall not call or depend on any external/public internet resources at runtime.

This includes no use of:

- public CDN CSS
- public CDN JavaScript
- Google Fonts
- public icon/font providers
- public analytics or telemetry scripts

### 8.3 Local Asset Hosting
All UI assets shall be hosted locally by the application or approved internal infrastructure.

### 8.4 CSP Compatibility
The web application shall be compatible with a restrictive Content Security Policy based primarily on `self`.

---

## 9. Persistence Portability Requirements

### 9.1 Supported Databases
The platform shall support:

- Microsoft SQL Server
- PostgreSQL

### 9.2 Database-Agnostic Core
The platform’s core business logic and cryptographic logic shall be independent from database engine specifics.

### 9.3 Provider-Based Persistence
Persistence shall be abstracted so that separate implementations can be provided for:

- MSSQL
- PostgreSQL

### 9.4 Schema Parity
Equivalent functional behavior shall be maintained across both supported database platforms.

---

## 10. Recommended Logical Architecture

### 10.1 Shared Platform Layer
The shared platform layer should include:

- Admin Web Portal
- Credential Management API
- Service/Client Management
- Credential Lifecycle Management
- Scope Management
- Audit Logging
- Provider Registry
- Persistence Abstractions
- Configuration / Policy Layer

### 10.2 HMAC Provider Layer
The initial HMAC provider layer should include:

- HMAC Credential Issuer
- HMAC Authentication Handler / Middleware
- HMAC Service Integration Library
- HMAC Signature Validator
- HMAC Canonical String Builder
- HMAC Secret Cache
- MiniKMS Integration

### 10.3 Future Provider Layers
Future provider layers may include:

- JWT Provider
- mTLS Provider
- OAuth2 Client Credentials Provider
- Kerberos Provider

---

## 11. Recommended Data Model Direction

### 11.1 Common Credential Model
The platform should maintain a generic credential entity with fields such as:

- CredentialId
- ClientId
- AuthenticationMode
- Status
- Environment
- Scopes
- CreatedAt
- CreatedBy
- UpdatedAt
- UpdatedBy
- ExpiresAt
- RevokedAt

### 11.2 HMAC Credential Detail
HMAC-specific details should be stored separately or logically isolated, such as:

- CredentialId
- KeyId
- EncryptedSecret
- EncryptedDataKey
- KeyVersion
- HmacAlgorithm
- EncryptionAlgorithm

### 11.3 Future JWT Detail
JWT-specific details may later include:

- CredentialId
- KeyReference
- Issuer
- Audience
- JwtAlgorithm
- PublicKeyReference or SigningKeyReference

---

## 12. Initial Release Out of Scope

The initial release shall not implement:

- JWT issuance
- JWT validation
- JWKS endpoint
- mTLS certificate lifecycle
- OAuth2 authorization server features
- Kerberos integration
- distributed cache
- external KMS integration
- standalone MiniKMS service
- replay nonce persistence store
- maker-checker workflow

These may be added later through provider-specific expansion.

---

## 13. Recommended Project Title

**Internal Service Authentication Credential Management Platform**  
**Initial Supported Mode: HMAC**

---

## 14. Summary

This platform shall be designed as a **generic internal authentication credential management platform** with:

- **initial implementation focused on HMAC**
- **future extensibility for JWT and other internal auth modes**
- **AdminLTE internal portal**
- **no external/public resource dependency**
- **MiniKMS for HMAC secret protection**
- **MSSQL and PostgreSQL portability**
- **cache-first runtime authentication**
