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
