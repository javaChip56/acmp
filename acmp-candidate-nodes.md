# ACMP Candidate CALM Nodes

Based only on the current requirements baseline, FRS, and technical specification, these are reasonable candidate CALM nodes for the Authentication Credential Management Platform design.

| Node | CALM Type | Short Description |
|---|---|---|
| Authentication Credential Management Platform | `system` | Central internal platform for service/client registration, credential lifecycle management, HMAC issuance, authorization metadata, and audit/governance. |
| Authorized Administrator | `actor` | Authorized internal administrator who manages clients, credentials, scopes, revocation, rotation, and related platform actions. |
| Admin Web Portal | `webclient` | Internal AdminLTE-based web portal used to administer services, credentials, and platform configuration. |
| Credential Management API | `service` | Management API that supports client registration, credential issuance, rotation, revocation, package issuance, and audit-related operations. |
| Protected Recipient Service | `service` | Internal protected service or business API that validates inbound HMAC requests and enforces credential scope/permission checks. |
| Client Service | `service` | Internal client service that signs outbound HMAC requests when calling protected services. |
| MiniKMS | `service` | Internal cryptographic component used for HMAC secret generation, envelope encryption, decryption, and key versioning. |
| Credential Persistence Store | `database` | SQL Server or PostgreSQL data store holding service/client records, credential metadata, HMAC detail records, and audit data. |
| Encrypted Credential Package | `data-asset` | Encrypted file artifact issued per `KeyId` for recipient-side HMAC validation in `EncryptedFile` mode. |
| Encrypted Client Credential Package | `data-asset` | Encrypted file artifact issued per `KeyId` for client-side outbound HMAC signing. |

## Candidate CALM Relationships

These relationships are also based only on the current requirements baseline, FRS, and technical specification.

| Relationship | CALM Type | Short Description |
|---|---|---|
| Authorized Administrator -> Admin Web Portal | `interacts` | Authorized administrators use the internal admin portal to manage clients, credentials, scopes, and platform operations. |
| Admin Web Portal -> Credential Management API | `connects` | The admin portal uses the management API for client registration, credential lifecycle actions, package issuance, and audit-related operations. |
| Credential Management API -> Credential Persistence Store | `connects` | The management API persists and reads service/client records, credential metadata, HMAC details, and audit data from the platform data store. |
| Credential Management API -> MiniKMS | `connects` | The management API uses MiniKMS for HMAC secret generation, encryption, decryption, and related key-management operations. |
| Client Service -> Protected Recipient Service | `connects` | Client services send HMAC-signed outbound requests to protected recipient services. |
| Protected Recipient Service -> Encrypted Credential Package | `connects` | In `EncryptedFile` mode, recipient-side validation reads an encrypted credential package from an accessible service directory. |
| Client Service -> Encrypted Client Credential Package | `connects` | The client-side signing library loads an encrypted client credential package to sign outbound requests. |
| Authentication Credential Management Platform -> Admin Web Portal, Credential Management API | `composed-of` | At the shared platform level, the platform includes the admin portal and credential management API. |
| Authentication Credential Management Platform -> HMAC Provider Components | `composed-of` | At the HMAC provider level, the platform includes HMAC issuance, package issuance, signing, validation, and supporting runtime components. |
