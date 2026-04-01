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

---

## 3.7 HMAC Runtime Secret Caching

### FRS-3.7.1 No Per-Request MiniKMS Decryption
The system shall not require MiniKMS decryption on every HMAC authentication request.

### FRS-3.7.2 In-Memory Cache
The system shall support in-memory caching of decrypted HMAC secrets.

### FRS-3.7.3 Cache Key
The system shall key cache entries using `KeyId` and `KeyVersion`.

### FRS-3.7.4 Configurable TTL
The system shall support configurable cache time-to-live settings.

### FRS-3.7.5 Cache Invalidation
The system shall invalidate relevant cache entries on credential revoke, rotate, disable, or update.

### FRS-3.7.6 Memory-Only Secret Cache
The system shall keep decrypted secret cache entries in memory only and shall not persist them to disk.

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

### FRS-3.13.2 Database-Agnostic Core Logic
The system’s core business logic and cryptographic logic shall not depend on database engine specifics.

### FRS-3.13.3 Provider-Based Persistence
The system shall support separate persistence implementations for MSSQL and PostgreSQL.

### FRS-3.13.4 Functional Parity
The system shall maintain equivalent functional behavior across both supported database platforms.

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
