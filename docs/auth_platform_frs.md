# Internal Service Authentication Credential Management Platform
## Functional Requirements Specification (FRS)
### Initial Supported Authentication Mode: HMAC

---

## 1.0 Introduction

### 1.1 Purpose
This document defines the functional requirements for an internal platform used to manage authentication credentials for IT Department service-to-service communication.

The initial release supports HMAC-based authentication only. The platform shall be designed for future expansion to additional authentication modes, including JWT.

### 1.2 Scope
The system shall provide:

- service/client registration
- credential lifecycle management
- HMAC secret issuance and protection
- HMAC request authentication
- scope and authorization metadata
- audit logging
- AdminLTE-based internal administration portal
- database portability across Microsoft SQL Server and PostgreSQL

### 1.3 Definitions

| Term | Description |
|---|---|
| Client / Service | An internal system, application, or service that consumes or exposes protected APIs |
| Credential | Authentication material associated with a client or service |
| Authentication Mode | The authentication mechanism used by a credential, such as HMAC or JWT |
| MiniKMS | Internal cryptographic component used initially for HMAC secret protection |
| KeyId | Public identifier used to locate an HMAC credential |
| Scope | Permission or access boundary assigned to a credential |

---

## 2.0 Product Scope

### 2.1 Initial Release Scope
The initial release shall support HMAC authentication only.

### 2.2 Future Expansion
The architecture shall support future addition of:

- JWT
- mTLS
- OAuth2 Client Credentials
- Kerberos / Windows Integrated Authentication
- API Key
- Asymmetric request signing

These future modes are out of scope for the initial release.

---

## 3.0 Functional Requirements

## 3.1 Service / Client Management

### FRS-3.1.1 Create Client
The system shall allow an authorized administrator to create a client/service record.

### FRS-3.1.2 Update Client
The system shall allow an authorized administrator to update client/service metadata.

### FRS-3.1.3 Disable Client
The system shall allow an authorized administrator to disable a client/service record.

### FRS-3.1.4 Environment Assignment
The system shall allow a client/service to be assigned to an environment such as DEV, TEST, UAT, or PROD.

### FRS-3.1.5 Ownership Assignment
The system shall allow ownership metadata to be assigned to a client/service.

---

## 3.2 Credential Lifecycle Management

### FRS-3.2.1 Create Credential
The system shall allow creation of a credential for a client/service.

### FRS-3.2.2 Multiple Credentials
The system shall support multiple credentials for a client/service where applicable.

### FRS-3.2.3 Activate / Disable Credential
The system shall allow a credential to be activated or disabled.

### FRS-3.2.4 Rotate Credential
The system shall allow rotation of a credential.

### FRS-3.2.5 Revoke Credential
The system shall allow immediate revocation of a credential.

### FRS-3.2.6 Expire Credential
The system shall allow a credential to have an expiry date and shall reject expired credentials during authentication.

### FRS-3.2.7 List Credential Metadata
The system shall allow authorized users to list credential metadata without exposing plaintext secrets.

### FRS-3.2.8 Credential Status Model
The system shall maintain a credential status model with the following stored states:

- `Active`
- `Disabled`
- `Revoked`

Credential expiry shall be represented by `ExpiresAt` and enforced as an operational validity rule rather than as a separate persisted lifecycle status.

### FRS-3.2.9 Effective Validity Rules
A credential shall be accepted for authentication only when all of the following are true:

- the parent client/service is active
- the credential status is `Active`
- the credential is not revoked
- the credential is not expired

If any of these conditions are not met, authentication shall fail securely.

### FRS-3.2.10 Disable and Reactivate Rules
Disabling a credential shall place it in the `Disabled` state and authentication shall be rejected while the credential remains disabled.

A disabled credential may be returned to `Active` only if it has not been revoked and has not already expired.

### FRS-3.2.11 Revoke Rules
Revocation shall place the credential in the `Revoked` state immediately.

Revocation shall be irreversible in the initial release, and revoked credentials shall never return to an authenticated state.

### FRS-3.2.12 Expiry Rules
If the current time is later than `ExpiresAt`, the credential shall be treated as expired and rejected during authentication even if its stored status remains `Active` or `Disabled`.

The initial release shall not reactivate an already expired credential by editing `ExpiresAt`; a new credential shall be issued or rotated instead.

### FRS-3.2.13 Rotation Rules
Credential rotation shall issue a new replacement credential.

The initial release shall support an optional bounded grace-period overlap during rotation so that the prior credential may remain temporarily valid while dependent clients transition to the new credential package.

If a grace period is configured for rotation:

- the new credential shall become valid immediately
- the prior credential may remain valid only until the configured grace-period end time
- the prior credential shall be rejected after the grace period ends
- the system shall record that the prior credential has been superseded by the replacement credential
- the default grace period should be 7 days
- routine grace periods should not exceed 14 days
- the maximum permitted grace period in the initial release shall be 30 days
- grace periods longer than 14 days shall require an explicit operational reason and audit traceability

If no grace period is configured, the prior credential shall be revoked immediately as part of the rotation operation.

### FRS-3.2.14 Parent Client Disable Effect
If a client/service is disabled, all credentials belonging to that client/service shall be rejected for authentication regardless of individual credential status.

---

## 3.3 Authentication Mode Management

### FRS-3.3.1 Initial Supported Mode
The system shall initially support the `HMAC` authentication mode only.

### FRS-3.3.2 Extensibility
The system shall isolate authentication-method-specific logic behind provider abstractions so that future modes such as JWT can be added later without major redesign of the shared platform layer.

### FRS-3.3.3 Credential Type Metadata
The system shall maintain authentication mode metadata for credentials.

---

## 3.4 HMAC Credential Issuance

### FRS-3.4.1 Generate KeyId
The system shall generate a unique `KeyId` for each issued HMAC credential.

### FRS-3.4.2 Generate Secret
The system shall generate a cryptographically secure random secret for each issued HMAC credential.

### FRS-3.4.3 Protect Secret
The system shall protect the generated HMAC secret using MiniKMS before persistence.

### FRS-3.4.4 One-Time Secret Display
The system shall display the plaintext HMAC secret only once at issuance time.

### FRS-3.4.5 No Secret Retrieval
The system shall not support later retrieval of the plaintext HMAC secret after issuance.

### FRS-3.4.6 Store Encrypted Secret Material
The system shall store only encrypted secret material and related metadata in persistent storage.

### FRS-3.4.7 Encrypted Credential Package File
The system shall support optional issuance of an encrypted credential package file for a specific `KeyId` for service-side validation scenarios.

### FRS-3.4.8 Package Protection
The encrypted credential package file shall be protected so it can only be decrypted by the service-consumable .NET library under approved service-side protection context.

### FRS-3.4.9 Package Integrity
The encrypted credential package file shall include integrity protection so tampering is detected and validation fails securely.

### FRS-3.4.10 Encrypted Client Package File
The system shall support optional issuance of an encrypted client credential package file for a specific `KeyId` for outbound client-side signing scenarios.

### FRS-3.4.11 Client Package Protection
The encrypted client credential package file shall be protected so it can only be decrypted by the client-consumable .NET library under approved client-side protection context.

### FRS-3.4.12 Client Package Integrity
The encrypted client credential package file shall include integrity protection so tampering is detected and signing fails securely.

### FRS-3.4.13 Package Format Versioning
The encrypted service-side and client-side credential package files shall use a versioned package format with an explicit schema-version field.

The initial release shall define and support a single HMAC package format version for both package types.

### FRS-3.4.14 Package Structure
Each encrypted credential package file shall contain:

- package envelope metadata
- credential metadata required for runtime validation or signing
- protection-binding metadata
- authenticated encrypted package payload

The package structure shall be defined explicitly so both issuer and DLL consumers interpret the same file format.

### FRS-3.4.15 Package Protection Mechanism
The initial release shall protect encrypted credential package files using authenticated encryption for the package payload and public-key wrapping of the package data key.

The package shall be bound to an approved local X.509 certificate protection context so that only the intended DLL consumer with access to the corresponding private key can decrypt it.

### FRS-3.4.16 Required Package Metadata
At minimum, the package format shall define required metadata fields for:

- schema version
- package type
- package identifier
- credential identifier
- `KeyId`
- `KeyVersion`
- credential status
- environment
- expiry
- issuance timestamp
- protection-binding metadata
- package encryption algorithm metadata

The client-side package shall additionally define the canonical signing profile identifier and HMAC algorithm metadata.

### FRS-3.4.17 Package Replacement Workflow
The package specification shall define how recipient-side and client-side package files are replaced or refreshed.

The workflow shall include:

- deterministic file naming
- temporary-file write before activation
- atomic replacement of the active package file
- DLL detection of file replacement or refresh
- secure reload of the new package before it is used

### FRS-3.4.18 Replacement Failure Behavior
If a replacement package file is missing, unreadable, tampered, schema-incompatible, bound to the wrong protection context, or otherwise invalid, the DLL shall reject the new package and fail securely according to the package reload rules.

---

## 3.5 MiniKMS Integration

### FRS-3.5.1 Secret Generation Support
MiniKMS shall support secure random secret generation for HMAC credentials.

### FRS-3.5.2 Envelope Encryption
MiniKMS shall support envelope encryption for HMAC secret protection.

### FRS-3.5.3 Decryption
MiniKMS shall support decryption of protected HMAC secret values when required.

### FRS-3.5.4 Key Versioning
MiniKMS shall support master-key versioning.

### FRS-3.5.5 Master Key Abstraction
MiniKMS shall abstract master-key access from the rest of the application.

### FRS-3.5.6 Future Scope Flexibility
The system shall not assume MiniKMS is the mandatory cryptographic mechanism for all future authentication modes.

---

## 3.6 HMAC Request Authentication

### FRS-3.6.1 Header-Based Authentication
The system shall authenticate HMAC requests using request headers containing HMAC authentication data.

### FRS-3.6.2 Resolve Credential by KeyId
The system shall resolve the HMAC credential using `KeyId`.

### FRS-3.6.3 Status Validation
The system shall validate credential status before authenticating the request.

### FRS-3.6.4 Expiry Validation
The system shall validate credential expiry before authenticating the request.

### FRS-3.6.5 Canonical String Reconstruction
The system shall reconstruct a deterministic canonical string before signature validation.

### FRS-3.6.6 Signature Recalculation
The system shall recompute the HMAC signature using the protected secret.

### FRS-3.6.7 Constant-Time Comparison
The system shall compare expected and provided signatures using constant-time comparison.

### FRS-3.6.8 Timestamp Validation
The system shall validate request timestamp according to configured skew rules.

### FRS-3.6.9 Future Nonce Support
The system shall be designed to support nonce validation in a future phase.

### FRS-3.6.10 KMS-Backed Validation Mode
The service-consumable .NET library shall support a `KmsBacked` validation mode that resolves required credential state through runtime platform/KMS-backed access.

### FRS-3.6.11 Encrypted File Validation Mode
The service-consumable .NET library shall support an `EncryptedFile` validation mode that reads an encrypted credential package file from an accessible service directory.

### FRS-3.6.12 File Mode Validation Data
In `EncryptedFile` mode, the library shall validate HMAC requests using credential metadata and protected secret material from the encrypted credential package file.

### FRS-3.6.13 Client Signing Library
The system shall provide a reusable client-consumable .NET library/DLL that client services can use to generate HMAC authentication headers for outbound requests.

### FRS-3.6.14 Client Package Signing Mode
The client library shall support loading an encrypted client credential package file from an accessible client directory and using its protected secret material to sign outbound requests.

### FRS-3.6.15 Canonical Signing Support
The client library shall construct the defined canonical string model and generate required HMAC headers, including timestamp and `KeyId`, for outbound requests.

---

## 3.7 HMAC Runtime Secret Caching

### FRS-3.7.1 No Per-Request MiniKMS Decryption
The system shall not require MiniKMS decryption on every HMAC authentication request.

### FRS-3.7.2 In-Memory Cache
The system shall support in-memory caching of HMAC credential metadata and decrypted HMAC secrets.

### FRS-3.7.3 Cache Key
The system shall key cache entries using `KeyId` and `KeyVersion`.

### FRS-3.7.4 Configurable TTL
The system shall support short configurable cache time-to-live settings.

### FRS-3.7.5 Cache Invalidation
The system shall invalidate relevant cache entries on credential revoke, rotate, disable, or update.

### FRS-3.7.6 Memory-Only Secret Cache
The system shall keep decrypted secret cache entries in memory only and shall not persist them to disk.

### FRS-3.7.7 Service Integration Library
The system shall provide a reusable .NET library/DLL that recipient services can use to perform HMAC authentication and authorization.

### FRS-3.7.8 Optional Startup Preload
The library shall support optional startup preload of configured active frequently-used credentials.

### FRS-3.7.9 Lazy Loading
The library shall lazy load credentials that are not preloaded when requests are received.

### FRS-3.7.10 Combined Cache Entry
The library shall cache credential metadata and decrypted secret material together for each `KeyId` and `KeyVersion`.

### FRS-3.7.11 Fail-Closed Behavior
If the library cannot resolve, refresh, or validate required credential state, it shall reject the request securely.

### FRS-3.7.12 File Refresh and Replacement
The library shall support detecting replacement or refresh of encrypted credential package files and shall reload them securely.

### FRS-3.7.13 Client Library Runtime Cache
The client library shall support in-memory caching of decrypted client package state keyed by `KeyId` and `KeyVersion`.

### FRS-3.7.14 Client Package Reload
The client library shall support detecting replacement or refresh of encrypted client credential package files and shall reload them securely.

### FRS-3.7.15 Client Fail-Closed Behavior
If the client library cannot read, decrypt, refresh, or validate required client package state, it shall fail signing securely.

---

## 3.8 HMAC Canonical Signing Model

### FRS-3.8.1 Deterministic Canonical Model
The system shall define a deterministic HMAC canonical signing model.

### FRS-3.8.2 Canonical Components
The canonical model shall include, at minimum:

- HTTP method
- path
- query string
- body hash
- timestamp
- nonce
- KeyId

### FRS-3.8.3 Documentation Requirement
The canonical signing model shall be documented clearly for client developers.

### FRS-3.8.4 Header Contract
The initial HMAC request contract shall use the following headers:

- `X-Key-Id`
- `X-Timestamp`
- `X-Nonce`
- `X-Signature`

Header names shall be treated as case-insensitive during request processing, but client and server libraries shall emit and document the canonical header names exactly as listed above.

### FRS-3.8.5 Canonical String Layout
The canonical string shall consist of exactly seven lines in the following order, separated by line-feed (`\n`) characters:

1. HTTP method
2. canonical path
3. canonical query string
4. body hash
5. timestamp
6. nonce
7. `KeyId`

### FRS-3.8.6 HTTP Method Normalization
The HTTP method line shall use the uppercase request method value, for example `GET`, `POST`, `PUT`, or `DELETE`.

### FRS-3.8.7 Path Normalization
The canonical path shall:

- include only the absolute path component
- exclude scheme, host, port, and fragment
- preserve case
- preserve trailing slash when present
- use `/` when the effective path is empty
- use UTF-8 based URI escaping with uppercase hexadecimal percent-encoding for any newly encoded bytes

Dot-segment normalization or path rewriting shall not be applied during canonicalization.

### FRS-3.8.8 Query String Normalization
The canonical query string shall:

- exclude the leading `?`
- represent each query parameter as a separate key-value pair, including duplicates
- represent parameters with no explicit value as `name=`
- sort pairs first by parameter name using ordinal comparison and then by parameter value using ordinal comparison
- percent-encode parameter names and values using UTF-8 with uppercase hexadecimal percent-encoding
- join normalized pairs using `&`

If the request contains no query parameters, the canonical query-string line shall be an empty string.

### FRS-3.8.9 Body Hash
The body-hash line shall be the lowercase hexadecimal SHA-256 hash of the raw request-body bytes.

For requests with no body or a zero-length body, the body hash shall be the SHA-256 hash of zero bytes.

### FRS-3.8.10 Timestamp Format
The `X-Timestamp` header shall use UTC in the format `yyyy-MM-ddTHH:mm:ssZ` with no fractional seconds.

The server shall validate the timestamp against a configurable skew window.

### FRS-3.8.11 Nonce Handling
The `X-Nonce` header shall be included in the canonical string.

If a nonce value is not supplied, the nonce line in the canonical string shall be an empty string.

The initial release shall validate nonce presence and format only if configured to require a nonce. Replay-detection persistence remains out of scope for the initial release.

### FRS-3.8.12 Signature Algorithm and Encoding
The signature shall be computed using `HMACSHA256` over the UTF-8 bytes of the canonical string.

The `X-Signature` header shall contain the resulting signature encoded as lowercase hexadecimal.

### FRS-3.8.13 Canonicalization Failure Behavior
If the server cannot reconstruct the canonical request using the defined rules, or if required HMAC headers are missing or invalid, the request shall fail authentication securely.

---

## 3.9 Scope and Authorization

### FRS-3.9.1 Scope Assignment
The system shall allow scopes or permissions to be assigned to credentials.

### FRS-3.9.2 HMAC Scope Support
The system shall support assigning scopes or permissions to HMAC credentials in the initial release.

### FRS-3.9.3 Operation-Level Permissions
The system shall support operation-level permissions such as `read`, `write`, `delete`, or equivalent business-defined permissions.

### FRS-3.9.4 Post-Authentication Authorization
The system shall enforce authorization after successful authentication and shall reject requests that do not have the required scope or permission.

### FRS-3.9.5 Provider-Specific Extensibility
The system shall support future provider-specific authorization extensions.

---

## 3.10 Audit and Governance

### FRS-3.10.1 Administrative Audit Logging
The system shall log administrative actions, including create, update, rotate, revoke, disable, and expiry changes.

### FRS-3.10.2 Security Event Logging
The system shall log security-relevant events such as invalid signatures, unknown KeyIds, expired credentials, revoked credential usage attempts, and decryption failures.

### FRS-3.10.3 Traceability
Audit records shall support traceability by actor, action, target, timestamp, and reason.

### FRS-3.10.4 Sensitive Data Protection in Logs
The system shall not log plaintext secrets or decrypted sensitive values.

### FRS-3.10.5 Administrative Role and Grace-Period Audit
For credential issuance, rotation, revocation, disablement, and extended grace-period operations, audit records shall capture the acting administrative role and the requested grace-period reason when applicable.

---

## 3.11 Web Administration Portal

### FRS-3.11.1 Admin Portal
The system shall provide an internal web-based administration portal.

### FRS-3.11.2 UI Framework
The administration portal shall use AdminLTE.

### FRS-3.11.3 No External Resource Dependency
The administration portal shall not call or depend on external/public internet resources at runtime.

### FRS-3.11.4 Local Asset Hosting
All required UI assets shall be hosted locally by the application or approved internal infrastructure.

### FRS-3.11.5 CSP Compatibility
The administration portal shall be compatible with a restrictive Content Security Policy based primarily on `self`.

### FRS-3.11.6 Authenticated Administrative Access
The administration portal and management API shall require authenticated internal administrative users.

### FRS-3.11.7 Administrative Role Model
The initial release shall support the following administrative roles:

- `AccessViewer`
- `AccessOperator`
- `AccessAdministrator`

### FRS-3.11.8 AccessViewer Permissions
`AccessViewer` users shall be allowed to view service/client access listings and credential metadata listings only.

`AccessViewer` users shall not be allowed to issue, rotate, revoke, disable, or modify credentials and shall not be allowed to view audit data.

### FRS-3.11.9 AccessOperator Permissions
`AccessOperator` users shall be allowed to:

- view service/client access listings and credential metadata
- issue credentials
- rotate credentials
- revoke credentials
- disable credentials
- issue encrypted credential packages and encrypted client credential packages
- configure a rotation grace period from 7 days through 14 days inclusive

`AccessOperator` users shall not be allowed to configure a rotation grace period longer than 14 days and shall not be allowed to view audit data in the initial release.

### FRS-3.11.10 AccessAdministrator Permissions
`AccessAdministrator` users shall be allowed to perform all `AccessOperator` actions.

`AccessAdministrator` users shall additionally be allowed to:

- configure extended rotation grace periods longer than 14 days up to the platform maximum of 30 days
- view audit data

### FRS-3.11.11 Extended Grace-Period Approval Rule
In the initial release, a requested rotation grace period longer than 14 days shall require `AccessAdministrator` authorization and an explicit operational reason.

Because maker-checker workflow is out of scope for the initial release, the `AccessAdministrator` authorization check shall act as the approval for extended grace periods rather than a separate approval workflow.

---

## 3.12 Environment Segregation

### FRS-3.12.1 Environment Support
The system shall support separate environments including DEV, TEST, UAT, and PROD.

### FRS-3.12.2 Environment Isolation
Credentials, secrets, keys, and policies shall be segregated by environment.

---

## 3.13 Persistence Portability

### FRS-3.13.1 Supported Databases
The system shall support Microsoft SQL Server and PostgreSQL.

### FRS-3.13.1.1 Demo Persistence Mode
The system may additionally provide a non-persistent in-memory persistence mode for demonstrations.

The demo persistence mode shall:

- store data in process memory only
- be cleared on application restart or process recycle
- not be used as a production persistence target
- follow the same logical repository contracts and business rules as the supported persistent providers where practical

### FRS-3.13.2 Database-Agnostic Core Logic
The system’s core business logic and cryptographic logic shall not depend on database engine specifics.

### FRS-3.13.3 Provider-Based Persistence
The system shall support separate persistence implementations for MSSQL, PostgreSQL, and an optional in-memory demo provider.

### FRS-3.13.4 Functional Parity
The system shall maintain equivalent functional behavior across both supported database platforms.

The in-memory demo provider should preserve equivalent functional behavior for demonstrations, while excluding restart durability and database-engine-specific behavior.

---

## 4.0 Out of Scope for Initial Release

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

---

## 5.0 Summary

The platform is a generic internal authentication credential management platform with an initial release focused on HMAC. It includes HMAC secret issuance, HMAC request authentication, MiniKMS-backed HMAC secret protection, cache-first runtime authentication, AdminLTE-based internal administration, no external/public resource dependency, and database portability across Microsoft SQL Server and PostgreSQL.
