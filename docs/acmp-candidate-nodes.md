# ACMP Candidate CALM Nodes

Based only on the current requirements baseline, FRS, and technical specification, these are reasonable candidate CALM nodes for the Authentication Credential Management Platform design.

| Node | CALM Type | Short Description |
|---|---|---|
| Authentication Credential Management Platform | `system` | Central internal platform for service/client registration, credential lifecycle management, HMAC issuance, authorization metadata, and audit/governance. |
| AccessViewer | `actor` | Read-only internal user who can view service/client access listings and credential metadata. |
| AccessOperator | `actor` | Internal operator who can issue, rotate, revoke, disable, and package credentials with standard grace periods. |
| AccessAdministrator | `actor` | Elevated internal administrator who can perform operator actions, configure extended grace periods, and view audit data. |
| Admin Web Portal | `webclient` | Internal AdminLTE-based web portal used to administer services, credentials, and platform configuration. |
| Credential Management API | `service` | Management API that supports client registration, credential issuance, rotation, revocation, package issuance, and audit-related operations. |
| Protected Recipient Service | `service` | Internal protected service or business API that validates inbound HMAC requests and enforces credential scope/permission checks. |
| Client Service | `service` | Internal client service that signs outbound HMAC requests when calling protected services. |
| MiniKMS | `service` | Internal cryptographic component used for HMAC secret generation, envelope encryption, decryption, and key versioning. |
| Credential Persistence Store | `database` | SQL Server or PostgreSQL data store holding service/client records, credential metadata, HMAC detail records, and audit data. |
| Encrypted Credential Package | `data-asset` | Versioned encrypted JSON package artifact issued per `KeyId` for recipient-side HMAC validation in `EncryptedFile` mode and bound to an approved X.509 protection context. |
| Encrypted Client Credential Package | `data-asset` | Versioned encrypted JSON package artifact issued per `KeyId` for client-side outbound HMAC signing and bound to an approved X.509 protection context. |

## Candidate CALM Relationships

These relationships are also based only on the current requirements baseline, FRS, and technical specification.

| Relationship | CALM Type | Short Description |
|---|---|---|
| AccessViewer -> Admin Web Portal | `interacts` | AccessViewer users use the internal admin portal for read-only access listings and credential metadata views. |
| AccessOperator -> Admin Web Portal | `interacts` | AccessOperator users use the internal admin portal for standard credential lifecycle and package issuance operations. |
| AccessAdministrator -> Admin Web Portal | `interacts` | AccessAdministrator users use the internal admin portal for elevated administrative operations and audit access. |
| Admin Web Portal -> Credential Management API | `connects` | The admin portal uses the management API for client registration, credential lifecycle actions, package issuance, and audit-related operations. |
| Credential Management API -> Credential Persistence Store | `connects` | The management API persists and reads service/client records, credential metadata, HMAC details, and audit data from the platform data store. |
| Credential Management API -> MiniKMS | `connects` | The management API uses MiniKMS for HMAC secret generation, encryption, decryption, and related key-management operations. |
| Credential Management API -> Encrypted Credential Package | `connects` | The management API issues versioned recipient-side encrypted package envelopes for service-side validation scenarios. |
| Credential Management API -> Encrypted Client Credential Package | `connects` | The management API issues versioned client-side encrypted package envelopes for outbound signing scenarios. |
| Client Service -> Protected Recipient Service | `connects` | Client services send HMAC-signed outbound requests to protected recipient services. |
| Protected Recipient Service -> Encrypted Credential Package | `connects` | In `EncryptedFile` mode, recipient-side validation loads, decrypts, and validates a bound encrypted package envelope from an accessible service directory. |
| Client Service -> Encrypted Client Credential Package | `connects` | The client-side signing library loads, decrypts, and validates a bound encrypted package envelope to sign outbound requests. |
| Authentication Credential Management Platform -> Admin Web Portal, Credential Management API | `composed-of` | At the shared platform level, the platform includes the admin portal and credential management API. |
| Authentication Credential Management Platform -> HMAC Provider Components | `composed-of` | At the HMAC provider level, the platform includes HMAC issuance, package issuance, signing, validation, and supporting runtime components. |

## Candidate CALM Flows

These flows represent business actions described by the current requirements baseline, FRS, and technical specification.

| Flow | Short Description |
|---|---|
| Register Client Service | AccessAdministrator creates a new internal client/service record through the admin portal and credential management API. |
| Update Client Service | AccessAdministrator updates client/service metadata such as owner, environment, or descriptive details. |
| Disable Client Service | AccessAdministrator disables a client/service so it can no longer use managed credentials. |
| Issue HMAC Credential | AccessOperator or AccessAdministrator issues a new HMAC credential, including secret generation, protection, persistence, and one-time secret reveal. |
| Rotate HMAC Credential (Standard) | AccessOperator or AccessAdministrator rotates an existing credential with immediate cutover or a grace period up to 14 days. |
| Rotate HMAC Credential (Extended Grace) | AccessAdministrator rotates an existing credential with a grace period longer than 14 days up to 30 days, with explicit reason and audit traceability. |
| Revoke HMAC Credential | AccessOperator or AccessAdministrator revokes a credential so future authentication attempts are rejected. |
| Issue Encrypted Credential Package | AccessOperator or AccessAdministrator uses the admin portal and credential management API to issue a versioned recipient-side encrypted package envelope bound to the target protection context. |
| Issue Encrypted Client Credential Package | AccessOperator or AccessAdministrator uses the admin portal and credential management API to issue a versioned client-side encrypted package envelope bound to the target protection context. |
| Validate Inbound HMAC Request (KmsBacked) | Protected recipient service validates an inbound HMAC request using cached state and platform or MiniKMS-backed resolution on cache miss. |
| Validate Inbound HMAC Request (EncryptedFile) | Protected recipient service validates an inbound HMAC request using an encrypted credential package file in `EncryptedFile` mode. |
| Sign Outbound HMAC Request | Client service uses the client signing DLL and encrypted client package to construct the canonical string and generate outbound HMAC headers. |
| Authorize Authenticated Request | Protected recipient service evaluates assigned scopes or permissions after successful HMAC authentication. |
| Reload Recipient Credential Package | Recipient-side DLL detects atomic replacement or refresh of a recipient-side package file, validates it, and reloads it securely. |
| Reload Client Credential Package | Client-side DLL detects atomic replacement or refresh of a client-side package file, validates it, and reloads it securely. |
| List Credential Metadata | AccessViewer, AccessOperator, or AccessAdministrator lists credential metadata without exposing plaintext secrets. |
| View Audit Log | AccessAdministrator views audit data through the admin portal and credential management API. |

### Flow Transition Candidates

#### Register Client Service
1. AccessAdministrator -> Admin Web Portal
2. Admin Web Portal -> Credential Management API
3. Credential Management API -> Credential Persistence Store

#### Update Client Service
1. AccessAdministrator -> Admin Web Portal
2. Admin Web Portal -> Credential Management API
3. Credential Management API -> Credential Persistence Store

#### Disable Client Service
1. AccessAdministrator -> Admin Web Portal
2. Admin Web Portal -> Credential Management API
3. Credential Management API -> Credential Persistence Store

#### Issue HMAC Credential
1. AccessOperator -> Admin Web Portal
2. Admin Web Portal -> Credential Management API
3. Credential Management API -> MiniKMS
4. Credential Management API -> Credential Persistence Store

#### Rotate HMAC Credential (Standard)
1. AccessOperator -> Admin Web Portal
2. Admin Web Portal -> Credential Management API
3. Credential Management API -> MiniKMS
4. Credential Management API -> Credential Persistence Store

#### Rotate HMAC Credential (Extended Grace)
1. AccessAdministrator -> Admin Web Portal
2. Admin Web Portal -> Credential Management API
3. Credential Management API -> MiniKMS
4. Credential Management API -> Credential Persistence Store

#### Revoke HMAC Credential
1. AccessOperator -> Admin Web Portal
2. Admin Web Portal -> Credential Management API
3. Credential Management API -> Credential Persistence Store

#### Issue Encrypted Credential Package
1. AccessOperator -> Admin Web Portal
2. Admin Web Portal -> Credential Management API
3. Credential Management API -> Encrypted Credential Package

#### Issue Encrypted Client Credential Package
1. AccessOperator -> Admin Web Portal
2. Admin Web Portal -> Credential Management API
3. Credential Management API -> Encrypted Client Credential Package

#### Validate Inbound HMAC Request (KmsBacked)
1. Client Service -> Protected Recipient Service
2. Protected Recipient Service -> platform or KMS-backed credential resolution path
3. Platform credential resolution path -> Credential Persistence Store
4. Platform credential resolution path -> MiniKMS
5. Protected Recipient Service -> authorization decision

#### Validate Inbound HMAC Request (EncryptedFile)
1. Client Service -> Protected Recipient Service
2. Protected Recipient Service -> Encrypted Credential Package
3. Protected Recipient Service -> authorization decision

#### Sign Outbound HMAC Request
1. Client Service -> Encrypted Client Credential Package
2. Client Service -> Protected Recipient Service

#### Authorize Authenticated Request
1. Client Service -> Protected Recipient Service
2. Protected Recipient Service -> scope or permission evaluation using resolved credential state

#### Reload Recipient Credential Package
1. Protected Recipient Service -> Encrypted Credential Package
2. Protected Recipient Service -> validate schema, binding, and encrypted payload
3. Protected Recipient Service -> in-memory credential state refresh

#### Reload Client Credential Package
1. Client Service -> Encrypted Client Credential Package
2. Client Service -> validate schema, binding, and encrypted payload
3. Client Service -> in-memory signing state refresh

#### List Credential Metadata
1. AccessViewer -> Admin Web Portal
2. Admin Web Portal -> Credential Management API
3. Credential Management API -> Credential Persistence Store

#### View Audit Log
1. AccessAdministrator -> Admin Web Portal
2. Admin Web Portal -> Credential Management API
3. Credential Management API -> Credential Persistence Store
