# ACMP Candidate CALM Nodes

Based only on the current requirements baseline, FRS, and technical specification, these are reasonable candidate CALM nodes for the Authentication Credential Management Platform design.

| Node | CALM Type | Short Description |
|---|---|---|
| Authentication Credential Management Platform | `system` | Central internal platform for service/client registration, administrative identity and role management, credential lifecycle management, HMAC issuance, authorization metadata, and audit/governance. |
| AccessViewer | `actor` | Read-only internal user who can view service/client access listings and credential metadata. |
| AccessOperator | `actor` | Internal operator who can issue, rotate, revoke, disable, and package credentials with standard grace periods. |
| AccessAdministrator | `actor` | Elevated internal administrator who can perform operator actions, configure extended grace periods, and view audit data. |
| Admin Web Portal | `webclient` | Internal AdminLTE-based web portal used to administer services, credentials, and platform configuration. |
| Credential Management API | `service` | Management API that supports administrative user management, client registration, credential issuance, rotation, revocation, package issuance, and audit-related operations. |
| Embedded Identity Provider | `service` | Application-local identity component that authenticates administrative users from persisted records and issues bearer tokens for the management API. |
| Protected Recipient Service | `service` | Internal protected service or business API that validates inbound HMAC requests and enforces credential scope/permission checks. |
| Client Service | `service` | Internal client service that signs outbound HMAC requests when calling protected services. |
| MiniKMS | `service` | Internal cryptographic service used for HMAC secret generation, envelope encryption, decryption, persisted key lifecycle management, and MiniKMS audit capture. |
| MiniKMS State Persistence Store | `database` | MiniKMS persistence layer that may run in file-backed, SQL Server, PostgreSQL, or demo in-memory mode depending on deployment configuration. |
| MiniKMS Key Store | `data-asset` | Logical data store for MiniKMS master-key versions, active-key tracking, and retired-key lifecycle state. |
| MiniKMS Audit Store | `data-asset` | Logical data store for MiniKMS operational audit events such as key creation, activation, retirement, and secret-operation activity. |
| Credential Persistence Store | `database` | SQL Server, PostgreSQL, or demo in-memory persistence layer that contains the platform's logical data stores. |
| Credential Record Store | `data-asset` | Logical data store for service/client records, credential metadata, scopes, and HMAC detail records. |
| Recipient Protection Binding Store | `data-asset` | Logical data store for recipient protection bindings such as X.509 references and registered external RSA public-key bindings used for package issuance. |
| Administrative Identity Store | `data-asset` | Logical data store for persisted admin users, password material, login metadata, and admin role assignments. |
| Audit Event Store | `data-asset` | Logical data store for administrative and security audit events. |
| Encrypted Credential Package | `data-asset` | Versioned encrypted JSON package artifact issued per `KeyId` for recipient-side HMAC validation in `EncryptedFile` mode and bound to an approved protection context such as X.509 or a registered external RSA public-key binding. |
| Encrypted Client Credential Package | `data-asset` | Versioned encrypted JSON package artifact issued per `KeyId` for client-side outbound HMAC signing and bound to an approved protection context such as X.509 or a registered external RSA public-key binding. |

## Candidate CALM Relationships

These relationships are also based only on the current requirements baseline, FRS, and technical specification.

| Relationship | CALM Type | Short Description |
|---|---|---|
| AccessViewer -> Admin Web Portal | `interacts` | AccessViewer users use the internal admin portal for read-only access listings and credential metadata views. |
| AccessOperator -> Admin Web Portal | `interacts` | AccessOperator users use the internal admin portal for standard credential lifecycle and package issuance operations. |
| AccessAdministrator -> Admin Web Portal | `interacts` | AccessAdministrator users use the internal admin portal for elevated administrative operations and audit access. |
| Admin Web Portal -> Credential Management API | `connects` | The admin portal uses the management API for administrative user management, client registration, credential lifecycle actions, package issuance, and audit-related operations. |
| Admin Web Portal -> Embedded Identity Provider | `connects` | The admin portal submits embedded sign-in requests to the local identity component and receives bearer tokens for later management API calls. |
| Embedded Identity Provider -> Administrative Identity Store | `connects` | The embedded identity component reads persisted admin users, password hashes, and role assignments from the admin identity store and updates login metadata. |
| Credential Management API -> Credential Record Store | `connects` | The management API persists and reads service/client records, credential metadata, scopes, and HMAC details from the credential record store. |
| Credential Management API -> Recipient Protection Binding Store | `connects` | The management API persists and reads recipient protection bindings, including X.509 metadata and externally provisioned public-key bindings, from the recipient protection binding store. |
| Credential Management API -> Administrative Identity Store | `connects` | The management API persists and reads administrative users, password material, and admin role assignments from the administrative identity store. |
| Credential Management API -> Audit Event Store | `connects` | The management API persists and reads audit events from the audit event store. |
| Credential Management API -> MiniKMS | `connects` | The management API uses the remote MiniKMS service for HMAC secret generation, encryption, decryption, and related key-management operations. |
| AccessAdministrator -> MiniKMS | `connects` | AccessAdministrator may perform internal MiniKMS key lifecycle and audit operations directly against MiniKMS. |
| MiniKMS -> MiniKMS Key Store | `connects` | MiniKMS persists and reads key-version records, active-key tracking, and retired-key lifecycle state. |
| MiniKMS -> MiniKMS Audit Store | `connects` | MiniKMS persists and reads operational audit events for key and secret operations. |
| Credential Management API -> Encrypted Credential Package | `connects` | The management API issues versioned recipient-side encrypted package envelopes using the selected recipient protection binding for service-side validation scenarios. |
| Credential Management API -> Encrypted Client Credential Package | `connects` | The management API issues versioned client-side encrypted package envelopes using the selected recipient protection binding for outbound signing scenarios. |
| Client Service -> Protected Recipient Service | `connects` | Client services send HMAC-signed outbound requests to protected recipient services. |
| Protected Recipient Service -> Credential Record Store | `connects` | In `KmsBacked` mode, recipient-side validation resolves credential metadata and HMAC detail records from the credential record store on cache miss or refresh. |
| Protected Recipient Service -> Encrypted Credential Package | `connects` | In `EncryptedFile` mode, recipient-side validation loads, decrypts, and validates a bound encrypted package envelope using the local private key or certificate material for the selected protection binding. |
| Client Service -> Encrypted Client Credential Package | `connects` | The client-side signing library loads, decrypts, and validates a bound encrypted package envelope using the local private key or certificate material for the selected protection binding. |
| Authentication Credential Management Platform -> Admin Web Portal, Credential Management API, Embedded Identity Provider | `composed-of` | At the shared platform level, the platform includes the admin portal, management API, and embedded identity component. |
| Credential Persistence Store -> Credential Record Store, Recipient Protection Binding Store, Administrative Identity Store, Audit Event Store | `composed-of` | The physical persistence layer contains separate logical stores for credential data, recipient protection binding data, administrative identity data, and audit events. |
| MiniKMS State Persistence Store -> MiniKMS Key Store, MiniKMS Audit Store | `composed-of` | The MiniKMS persistence layer contains separate logical stores for key lifecycle state and MiniKMS audit events. |
| Authentication Credential Management Platform -> HMAC Provider Components | `composed-of` | At the HMAC provider level, the platform includes MiniKMS, MiniKMS state persistence, HMAC issuance, package issuance, signing, validation, and supporting runtime components. |

## Candidate CALM Flows

These flows represent business actions described by the current requirements baseline, FRS, and technical specification.

| Flow | Short Description |
|---|---|
| Authenticate Administrative User | An access user signs in through the admin portal, the embedded identity provider validates stored credentials and roles, and a bearer token is issued for management API access. |
| Manage Administrative Users | AccessAdministrator creates, updates, disables, or resets persisted admin-user records and role assignments through the admin portal and management API. |
| Reset Administrative User Password | AccessAdministrator resets a persisted admin user's password through the admin portal and management API, with audit capture. |
| Assign Administrative User Role | AccessAdministrator assigns or changes persisted admin-user role memberships through the admin portal and management API, with audit capture. |
| Register Client Service | AccessAdministrator creates a new internal client/service record through the admin portal and credential management API. |
| Update Client Service | AccessAdministrator updates client/service metadata such as owner, environment, or descriptive details. |
| Disable Client Service | AccessAdministrator disables a client/service so it can no longer use managed credentials. |
| Issue HMAC Credential | AccessOperator or AccessAdministrator issues a new HMAC credential, including secret generation, protection, persistence, and one-time secret reveal. |
| Rotate HMAC Credential (Standard) | AccessOperator or AccessAdministrator rotates an existing credential with immediate cutover or a grace period up to 14 days. |
| Rotate HMAC Credential (Extended Grace) | AccessAdministrator rotates an existing credential with a grace period longer than 14 days up to 30 days, with explicit reason and audit traceability. |
| Manage Recipient Protection Bindings | AccessOperator or AccessAdministrator registers, activates, retires, or reviews recipient protection bindings such as X.509 references and externally provisioned RSA public keys. |
| Rotate Recipient Protection Binding | AccessOperator or AccessAdministrator rolls a recipient protection binding to a new public key or X.509 reference and then re-issues packages against the new binding. |
| Manage MiniKMS Key Versions | AccessAdministrator creates, activates, or retires MiniKMS key versions through the internal MiniKMS service, with persisted key-state and audit capture. |
| View MiniKMS Audit Log | AccessAdministrator reads MiniKMS operational audit records for cryptographic governance and troubleshooting. |
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

#### Authenticate Administrative User
1. Access user -> Admin Web Portal
2. Admin Web Portal -> Embedded Identity Provider
3. Embedded Identity Provider -> Administrative Identity Store
4. Embedded Identity Provider -> Admin Web Portal with bearer token

#### Manage Administrative Users
1. AccessAdministrator -> Admin Web Portal
2. Admin Web Portal -> Credential Management API
3. Credential Management API -> Administrative Identity Store
4. Credential Management API -> Audit Event Store

#### Reset Administrative User Password
1. AccessAdministrator -> Admin Web Portal
2. Admin Web Portal -> Credential Management API
3. Credential Management API -> Administrative Identity Store
4. Credential Management API -> Audit Event Store

#### Assign Administrative User Role
1. AccessAdministrator -> Admin Web Portal
2. Admin Web Portal -> Credential Management API
3. Credential Management API -> Administrative Identity Store
4. Credential Management API -> Audit Event Store

#### Register Client Service
1. AccessAdministrator -> Admin Web Portal
2. Admin Web Portal -> Credential Management API
3. Credential Management API -> Credential Record Store

#### Update Client Service
1. AccessAdministrator -> Admin Web Portal
2. Admin Web Portal -> Credential Management API
3. Credential Management API -> Credential Record Store

#### Disable Client Service
1. AccessAdministrator -> Admin Web Portal
2. Admin Web Portal -> Credential Management API
3. Credential Management API -> Credential Record Store

#### Issue HMAC Credential
1. AccessOperator -> Admin Web Portal
2. Admin Web Portal -> Credential Management API
3. Credential Management API -> MiniKMS
4. MiniKMS -> MiniKMS Audit Store
5. Credential Management API -> Credential Record Store
6. Credential Management API -> Audit Event Store

#### Rotate HMAC Credential (Standard)
1. AccessOperator -> Admin Web Portal
2. Admin Web Portal -> Credential Management API
3. Credential Management API -> MiniKMS
4. MiniKMS -> MiniKMS Audit Store
5. Credential Management API -> Credential Record Store
6. Credential Management API -> Audit Event Store

#### Rotate HMAC Credential (Extended Grace)
1. AccessAdministrator -> Admin Web Portal
2. Admin Web Portal -> Credential Management API
3. Credential Management API -> MiniKMS
4. MiniKMS -> MiniKMS Audit Store
5. Credential Management API -> Credential Record Store
6. Credential Management API -> Audit Event Store

#### Manage Recipient Protection Bindings
1. AccessOperator -> Admin Web Portal
2. Admin Web Portal -> Credential Management API
3. Credential Management API -> Recipient Protection Binding Store
4. Credential Management API -> Audit Event Store

#### Rotate Recipient Protection Binding
1. AccessOperator -> Admin Web Portal
2. Admin Web Portal -> Credential Management API
3. Credential Management API -> Recipient Protection Binding Store
4. Credential Management API -> Encrypted Credential Package or Encrypted Client Credential Package
5. Credential Management API -> Audit Event Store

#### Manage MiniKMS Key Versions
1. AccessAdministrator -> MiniKMS
2. MiniKMS -> MiniKMS Key Store
3. MiniKMS -> MiniKMS Audit Store

#### View MiniKMS Audit Log
1. AccessAdministrator -> MiniKMS
2. MiniKMS -> MiniKMS Audit Store

#### Revoke HMAC Credential
1. AccessOperator -> Admin Web Portal
2. Admin Web Portal -> Credential Management API
3. Credential Management API -> Credential Record Store
4. Credential Management API -> Audit Event Store

#### Issue Encrypted Credential Package
1. AccessOperator -> Admin Web Portal
2. Admin Web Portal -> Credential Management API
3. Credential Management API -> Recipient Protection Binding Store
4. Credential Management API -> Encrypted Credential Package

#### Issue Encrypted Client Credential Package
1. AccessOperator -> Admin Web Portal
2. Admin Web Portal -> Credential Management API
3. Credential Management API -> Recipient Protection Binding Store
4. Credential Management API -> Encrypted Client Credential Package

#### Validate Inbound HMAC Request (KmsBacked)
1. Client Service -> Protected Recipient Service
2. Protected Recipient Service -> platform or KMS-backed credential resolution path
3. Platform credential resolution path -> Credential Record Store
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
2. Protected Recipient Service -> validate schema, package identity, binding metadata, and encrypted payload
3. Protected Recipient Service -> in-memory credential state refresh

#### Reload Client Credential Package
1. Client Service -> Encrypted Client Credential Package
2. Client Service -> validate schema, package identity, binding metadata, and encrypted payload
3. Client Service -> in-memory signing state refresh

#### List Credential Metadata
1. AccessViewer -> Admin Web Portal
2. Admin Web Portal -> Credential Management API
3. Credential Management API -> Credential Record Store

#### View Audit Log
1. AccessAdministrator -> Admin Web Portal
2. Admin Web Portal -> Credential Management API
3. Credential Management API -> Audit Event Store
