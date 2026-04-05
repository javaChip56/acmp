# External Recipient Wrapping Key Design

## Status

This document is a design draft for a future ACMP extension.

It is not the same as the currently implemented `X509StoreThumbprint` and `X509File` package binding modes. It proposes a more general, cross-platform-friendly recipient protection model that does not require the recipient to use an X.509 certificate store.

## Purpose

The current package model can encrypt a package to an X.509 certificate bound to the recipient environment.

That works well for Windows-centric deployments, but it creates friction when:

- the recipient service is running on Linux
- the service does not already have an app-specific certificate
- certificate renewal changes the key pair and requires package re-issuance
- the team wants a simpler recipient-owned key model

The proposed model introduces an externally provisioned recipient wrapping key.

In the recommended first version, the recipient service generates its own RSA key pair locally, keeps the private key, and registers only the public key with ACMP.

## Recommended First Variant

### `ExternalRsaPublicKey`

This should be the first non-certificate recipient binding supported by ACMP.

The model is:

1. The recipient service generates an RSA key pair locally.
2. The private key stays on the recipient host.
3. The public key is registered with ACMP.
4. ACMP uses that public key to protect the package.
5. The recipient service uses its local private key to decrypt the package.

This keeps ACMP out of the private-key bootstrap path while still allowing offline package delivery.

## Why This Variant Makes Sense

- It is cross-platform.
- ACMP never needs the recipient private key.
- It avoids certificate store coupling.
- It avoids certificate renewal concerns when the team does not want an X.509 lifecycle.
- It is operationally simpler than a shared symmetric wrapping key.

## High-Level Flow

### Recipient Side

1. Generate an RSA key pair locally.
2. Keep the private key in a secure local path or secure local key store.
3. Export the public key in PEM format.
4. Provide the public key PEM and key metadata to ACMP.

### ACMP Side

1. Store the recipient binding metadata and public key.
2. When issuing a package, generate a random content-encryption key.
3. Encrypt the package payload using `AES-256-GCM`.
4. Wrap the content-encryption key using the recipient RSA public key with `RSA-OAEP-256`.
5. Publish a package envelope containing:
   - encrypted payload
   - wrapped content-encryption key
   - binding metadata
   - package metadata

### Recipient Runtime

1. Load the local private key.
2. Unwrap the content-encryption key.
3. Decrypt the package payload.
4. Validate package metadata and package identity.
5. Use the contained HMAC credential material.

## Proposed Binding Types

The recipient protection binding model should be generalized to support:

- `X509StoreThumbprint`
- `X509File`
- `ExternalRsaPublicKey`
- future `ExternalSymmetricWrappingKeyRef`
- future `LocalProtectedKey`

`ExternalRsaPublicKey` should be the first additional binding implemented.

## Proposed ACMP Data Model

Add a logical entity such as `RecipientProtectionBinding`.

Suggested fields:

- `Id`
- `ClientId`
- `BindingName`
- `BindingType`
- `Status`
- `Algorithm`
- `PublicKeyPem`
- `PublicKeyFingerprint`
- `KeyId`
- `KeyVersion`
- `IssuedBy`
- `CreatedAtUtc`
- `ActivatedAtUtc`
- `RetiredAtUtc`
- `RetirementReason`
- `Notes`

Suggested status values:

- `Active`
- `Retired`
- `Revoked`

Notes:

- `PublicKeyPem` is only for public material.
- ACMP must never store the recipient private key.
- `PublicKeyFingerprint` should be stored for operator verification and audit readability.

## Proposed API Shape

These are suggested additions, not current endpoints.

### Create Recipient Binding

`POST /api/clients/{clientId}/recipient-bindings`

Example request:

```json
{
  "bindingName": "orders-api-prod-rsa-2026q2",
  "bindingType": "ExternalRsaPublicKey",
  "algorithm": "RSA-3072",
  "publicKeyPem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
  "notes": "Primary package decryption key for Orders API production"
}
```

### List Recipient Bindings

`GET /api/clients/{clientId}/recipient-bindings`

### Activate Recipient Binding

`POST /api/recipient-bindings/{bindingId}/activate`

### Retire Recipient Binding

`POST /api/recipient-bindings/{bindingId}/retire`

### Issue Package Using a Recipient Binding

`POST /api/credentials/{credentialId}/packages`

Example request:

```json
{
  "bindingType": "ExternalRsaPublicKey",
  "recipientBindingId": "binding-123",
  "reason": "Initial package issue for Orders API production"
}
```

## Proposed Package Envelope Additions

The package envelope should carry enough metadata for validation and troubleshooting.

Suggested binding section:

```json
{
  "bindingType": "ExternalRsaPublicKey",
  "bindingId": "binding-123",
  "keyId": "orders-api-prod-rsa",
  "keyVersion": "2026q2",
  "algorithm": "RSA-OAEP-256",
  "publicKeyFingerprint": "SHA256:..."
}
```

The package should not include the private key.

## Rotation and Rollover Model

When the recipient service rotates its wrapping key:

1. Generate a new local key pair.
2. Register the new public key in ACMP.
3. Mark the new binding active.
4. Re-issue the package against the new binding.
5. Deploy the new package.
6. Keep the old private key temporarily if old packages may still exist.
7. Retire the old binding after successful cutover.

This makes wrapping-key rollover similar to certificate rollover, but without requiring certificate lifecycle management.

## Security Requirements

- The private key must remain on the recipient side only.
- ACMP must never require upload of the private key.
- RSA key size should be at least `3072` bits.
- Key wrapping should use `RSA-OAEP-256`.
- The package payload should continue to use `AES-256-GCM`.
- Public keys should be fingerprinted and auditable.
- Binding creation, activation, retirement, and package issuance must be audited.
- Operators should verify the fingerprint with the recipient team before activation.

## Step-by-Step Runbook For Recipient Service Managers

This section is written so it can be shared directly with recipient service owners.

### What You Are Creating

You are creating a local package decryption key pair for your service:

- the **private key** stays on your server
- the **public key** is sent to ACMP

ACMP uses the public key to encrypt the package.
Your service uses the private key to decrypt it.

### What You Will Send To ACMP

Send these items to the ACMP operator or administrator:

- service name
- environment
- intended binding name
- public key PEM file contents
- key algorithm, such as `RSA-3072`
- an optional comment, such as `Orders API production package decryption key`

Do not send the private key.

## Recommended Generation Method

Use RSA `3072` bits and export the public key in PEM format.

### Linux Steps Using OpenSSL

1. Create a secure local folder for the key material.

```bash
mkdir -p /opt/orders-api/keys
chmod 700 /opt/orders-api/keys
cd /opt/orders-api/keys
```

2. Generate the private key.

```bash
openssl genpkey -algorithm RSA -out recipient-private-key.pem -pkeyopt rsa_keygen_bits:3072
chmod 600 recipient-private-key.pem
```

3. Export the public key.

```bash
openssl rsa -pubout -in recipient-private-key.pem -out recipient-public-key.pem
chmod 644 recipient-public-key.pem
```

4. Display the public key fingerprint for verification.

```bash
openssl pkey -pubin -in recipient-public-key.pem -outform DER | openssl dgst -sha256 -binary | openssl base64
```

5. Send the contents of `recipient-public-key.pem` to the ACMP operator.

6. Keep `recipient-private-key.pem` on the service host only.

### Windows Steps Using OpenSSL

If OpenSSL is available on Windows, use the same commands from PowerShell in a secured folder such as `C:\ProgramData\OrdersApi\Keys`.

```powershell
New-Item -ItemType Directory -Force C:\ProgramData\OrdersApi\Keys | Out-Null
cd C:\ProgramData\OrdersApi\Keys
openssl genpkey -algorithm RSA -out recipient-private-key.pem -pkeyopt rsa_keygen_bits:3072
openssl rsa -pubout -in recipient-private-key.pem -out recipient-public-key.pem
```

After generation:

- restrict access to `recipient-private-key.pem`
- send only `recipient-public-key.pem` to ACMP

### Windows Steps Using PowerShell 7

If OpenSSL is not available, PowerShell 7 can generate the key pair.

1. Open PowerShell 7.

2. Run:

```powershell
New-Item -ItemType Directory -Force C:\ProgramData\OrdersApi\Keys | Out-Null
$rsa = [System.Security.Cryptography.RSA]::Create(3072)
$privatePem = $rsa.ExportPkcs8PrivateKeyPem()
$publicPem = $rsa.ExportSubjectPublicKeyInfoPem()
Set-Content -Path C:\ProgramData\OrdersApi\Keys\recipient-private-key.pem -Value $privatePem -NoNewline
Set-Content -Path C:\ProgramData\OrdersApi\Keys\recipient-public-key.pem -Value $publicPem -NoNewline
```

3. Restrict permissions on the private key file so only the service identity and administrators can read it.

4. Send `recipient-public-key.pem` to the ACMP operator.

### Verification Checklist

Before sending the public key to ACMP:

- confirm the private key file exists
- confirm the public key file exists
- confirm the public key file begins with `-----BEGIN PUBLIC KEY-----`
- confirm the private key is stored only on the recipient host
- confirm file permissions are restricted for the private key

## How ACMP Will Use The Public Key

Once ACMP receives the public key:

1. The operator registers it as a recipient protection binding.
2. ACMP stores the public key and metadata.
3. When a package is issued, ACMP uses the public key to wrap the package encryption key.
4. The resulting package can be delivered to the recipient service.
5. The recipient service uses its private key to load the package.

## Operational Guidance

- One binding per service and environment is usually a good starting point.
- Use clear names such as `orders-api-prod-rsa-2026q2`.
- Rotate keys on a planned schedule or after suspected exposure.
- Re-issue packages after rotating the recipient wrapping key.
- Keep old private keys only for as long as needed to finish package cutover.
- Treat the private key like any other production secret.

## Suggested Future ACMP Enhancements

- admin UI support for recipient binding registration
- binding fingerprint display and verification workflow
- package issuance by binding selection instead of raw thumbprint/path input
- binding rotation and retirement screens
- public-key upload validation
- runtime loader support for private-key file paths or local secure-key references

