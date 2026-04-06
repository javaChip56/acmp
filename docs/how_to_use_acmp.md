# How To Use ACMP

This guide is the practical “day one” walkthrough for using ACMP.

It is intended for:

- platform operators who manage clients, credentials, and packages
- recipient service owners who need to load service packages
- client service owners who need to load client-signing packages

If you need deeper setup details, this guide links to the more focused docs as you go.

## 1. Choose How You Want To Run It

### Fastest Local Start

Use demo mode when you want to explore the system quickly:

```powershell
dotnet run --project .\src\MyCompany.AuthPlatform.Api
```

Then open:

- `/admin/login.html`
- `/swagger`

See [demo_mode.md](d:/Research/acmp/docs/demo_mode.md#L1).

### Full Local Stack

Use the Docker Compose stack when you want the API, MiniKMS, and PostgreSQL together:

```powershell
Copy-Item .\deploy\.env.example .\deploy\.env
docker compose --env-file .\deploy\.env -f .\deploy\docker-compose.yml up --build -d
```

See [local_deployment.md](d:/Research/acmp/docs/local_deployment.md#L1).

### Offline / Air-Gapped Use

Use the offline bundle from a tagged release when the target host should not need internet access.

See [offline_deployment.md](d:/Research/acmp/docs/offline_deployment.md#L1).

## 2. Sign In To The Admin Portal

Open:

- `http://localhost:8080/admin/login.html`
- or the local URL printed by the API host

Default development/demo users:

- `viewer.demo / ViewerPass!123`
- `operator.demo / OperatorPass!123`
- `administrator.demo / AdministratorPass!123`

Role summary:

- `AccessViewer`
  Can view clients, credentials, and basic access metadata.

- `AccessOperator`
  Can create clients, issue credentials, manage recipient bindings, and issue/revoke/rotate credentials within normal policy limits.

- `AccessAdministrator`
  Can do operator actions plus admin-user management, audit access, and extended-grace operations.

## 3. Typical Operator Workflow

This is the most common end-to-end ACMP flow.

### Step 1: Create A Service Client

In the admin portal:

1. Go to `Clients & Credentials`
2. Choose `Create Client`
3. Enter:
   - client code
   - client name
   - owner
   - environment
   - description/metadata if needed

This creates the logical system or workload that will own the credential.

### Step 2: Issue An HMAC Credential

Still in `Clients & Credentials`:

1. Open the target client
2. Choose the HMAC credential issuance action
3. Set:
   - environment
   - expiry
   - notes
   - scopes if needed

Important:

- `Expires At` is the validity limit of the HMAC credential itself
- once the credential expires, client signing and recipient validation should no longer accept it

### Step 3: Create A Recipient Protection Binding

Before package issuance, ACMP needs to know how the recipient will decrypt the package.

Go to `Recipient Bindings` and create one of these:

- `X509StoreThumbprint`
  Windows certificate store binding

- `X509File`
  file-based X.509 binding

- `ExternalRsaPublicKey`
  recipient-owned public key binding, typically the most cross-platform-friendly option

For `ExternalRsaPublicKey`, you will usually enter:

- binding name
- algorithm
- recipient public key PEM
- recipient key id
- recipient key version
- notes

See [external_recipient_wrapping_key_design.md](d:/Research/acmp/docs/external_recipient_wrapping_key_design.md#L1).

### Step 4: Issue Packages

ACMP supports two package types for the same HMAC credential:

- `Service Pkg`
  Used by the recipient/protected API to validate inbound signed requests

- `Client Pkg`
  Used by the calling client service to sign outbound requests

Typical flow:

1. In `Clients & Credentials`, find the active credential
2. Choose `Service Pkg` to issue a validation package
3. Choose `Client Pkg` to issue a signing package
4. Prefer selecting an existing `recipientBindingId`
5. Use inline X.509 fields only as a fallback if you are not using a stored binding

### Step 5: Deliver The Packages

Place the issued package files where the runtime hosts can read them.

Typical pattern:

- recipient service gets the `Service Pkg`
- calling client gets the `Client Pkg`

## 4. Recipient Service Workflow

The recipient service uses `MyCompany.AuthPlatform.Hmac`.

It needs:

- the service package file
- the package directory path
- the expected credential `keyId`
- the decryption material for the chosen binding

For `ExternalRsaPublicKey`, that usually means:

- local PEM private key file
- expected binding metadata from ACMP

See:

- [recipient_runtime_setup.md](d:/Research/acmp/docs/recipient_runtime_setup.md#L1)
- [hmac_service_library.md](d:/Research/acmp/docs/hmac_service_library.md#L1)
- [samples/MyCompany.AuthPlatform.RecipientSample/README.md](d:/Research/acmp/samples/MyCompany.AuthPlatform.RecipientSample/README.md#L1)

## 5. Client Service Workflow

The client service uses `MyCompany.AuthPlatform.Hmac.Client`.

It needs:

- the client package file
- the package directory path
- the credential `keyId`
- the decryption material for the chosen binding

See:

- [recipient_runtime_setup.md](d:/Research/acmp/docs/recipient_runtime_setup.md#L1)
- [hmac_client_library.md](d:/Research/acmp/docs/hmac_client_library.md#L1)
- [samples/MyCompany.AuthPlatform.ClientSample/README.md](d:/Research/acmp/samples/MyCompany.AuthPlatform.ClientSample/README.md#L1)

## 6. Rotation And Renewal

When a credential needs to change:

1. rotate the credential in ACMP
2. if needed, configure a grace-period overlap
3. issue replacement packages
4. deploy the new packages to the recipient and client
5. allow the old credential to age out or end the grace period

If the recipient binding changes too, such as:

- renewed certificate
- new RSA key pair
- new binding version

then issue new packages for the new binding and deploy those together with the new local key material.

## 7. Admin User Management

Administrators can also manage admin users through the portal/API:

- list users
- create users
- disable users
- reset passwords
- assign roles

See [identity_provider_setup.md](d:/Research/acmp/docs/identity_provider_setup.md#L1).

## 8. Where To Look When Something Fails

### Package Won’t Decrypt

Check:

- the recipient has the correct private key or certificate
- the package binding metadata matches the runtime config
- the correct package type was deployed

### Docker Offline Host Still Tries The Registry

Check:

- the required images were imported
- the expected tags exist locally:
  - `acmp-api:offline`
  - `acmp-minikms:offline`
  - `postgres:16`

See [offline_deployment.md](d:/Research/acmp/docs/offline_deployment.md#L1).

### API Starts But Fails Early

Check:

- database connection string
- MiniKMS connection/configuration
- readiness endpoints:
  - `/ready`
  - MiniKMS `/ready`

### A Fix Was Merged But Deployment Still Shows The Old Bug

Regenerate the release artifact or offline bundle and redeploy it. Older bundles do not magically pick up newer source fixes.

## 9. Best Companion Docs

- [demo_mode.md](d:/Research/acmp/docs/demo_mode.md#L1)
- [local_deployment.md](d:/Research/acmp/docs/local_deployment.md#L1)
- [offline_deployment.md](d:/Research/acmp/docs/offline_deployment.md#L1)
- [release_checklist.md](d:/Research/acmp/docs/release_checklist.md#L1)
- [recipient_runtime_setup.md](d:/Research/acmp/docs/recipient_runtime_setup.md#L1)
- [hmac_service_library.md](d:/Research/acmp/docs/hmac_service_library.md#L1)
- [hmac_client_library.md](d:/Research/acmp/docs/hmac_client_library.md#L1)
