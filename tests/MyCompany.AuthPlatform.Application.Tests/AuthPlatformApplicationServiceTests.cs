using MyCompany.AuthPlatform.Application;
using MyCompany.AuthPlatform.Packaging;
using MyCompany.AuthPlatform.Persistence.InMemory;
using MyCompany.Shared.Contracts.Domain;
using Xunit;
using System.Security.Cryptography;

namespace MyCompany.AuthPlatform.Application.Tests;

public sealed class AuthPlatformApplicationServiceTests
{
    [Fact]
    public async Task CreateAdminUserAsync_PersistsUserAndRoles()
    {
        var service = CreateService(out var unitOfWork);
        var access = AdministratorContext();

        var created = await service.CreateAdminUserAsync(
            new CreateAdminUserRequest(
                Username: "auditor.demo",
                DisplayName: "Demo Auditor",
                Password: "AuditorPass!123",
                Roles: ["AccessViewer", "AccessOperator"]),
            access);

        var storedUser = await unitOfWork.AdminUsers.GetByIdAsync(created.UserId);
        var storedRoles = await unitOfWork.AdminUserRoles.ListByUserIdAsync(created.UserId);

        Assert.NotNull(storedUser);
        Assert.Equal("auditor.demo", created.Username);
        Assert.Equal(AdminUserStatus.Active, created.Status);
        Assert.Equal(["AccessOperator", "AccessViewer"], created.Roles);
        Assert.Equal("Demo Auditor", storedUser!.DisplayName);
        Assert.Equal(["AccessOperator", "AccessViewer"], storedRoles.Select(role => role.RoleName).OrderBy(role => role).ToArray());
    }

    [Fact]
    public async Task RotateHmacCredentialAsync_RejectsExtendedGracePeriodForOperator()
    {
        var service = CreateService(out _);
        var operatorAccess = OperatorContext();

        var client = await service.CreateServiceClientAsync(
            new CreateServiceClientRequest(
                ClientCode: "orders-api",
                ClientName: "Orders API",
                Owner: "Integration Team",
                Environment: DeploymentEnvironment.Uat,
                Description: "Smoke test client",
                MetadataJson: null),
            operatorAccess);

        var credential = await service.IssueHmacCredentialAsync(
            client.ClientId,
            new IssueHmacCredentialRequest(
                ExpiresAt: DateTimeOffset.UtcNow.AddDays(30),
                Scopes: ["orders.read"],
                Notes: "Initial credential",
                KeyId: "orders-api-hmac-1",
                KeyVersion: "kms-v1"),
            operatorAccess);

        var exception = await Assert.ThrowsAsync<ApplicationServiceException>(() =>
            service.RotateHmacCredentialAsync(
                credential.CredentialId,
                new RotateHmacCredentialRequest(
                    ExpiresAt: DateTimeOffset.UtcNow.AddDays(60),
                    GracePeriodEndsAt: DateTimeOffset.UtcNow.AddDays(20),
                    Scopes: ["orders.read"],
                    Notes: "Extended overlap",
                    NewKeyId: "orders-api-hmac-2",
                    NewKeyVersion: "kms-v1",
                    Reason: "Needs a longer rollout"),
                operatorAccess));

        Assert.Equal(403, exception.StatusCode);
        Assert.Equal("extended_grace_period_denied", exception.ErrorCode);
    }

    [Fact]
    public void AdminUserPasswordHasher_HashesAndVerifiesPasswords()
    {
        var passwordMaterial = AdminUserPasswordHasher.HashPassword("AdministratorPass!123");

        var valid = AdminUserPasswordHasher.VerifyPassword(
            "AdministratorPass!123",
            passwordMaterial.Hash,
            passwordMaterial.Salt,
            passwordMaterial.Iterations,
            AdminUserPasswordHasher.Algorithm);

        var invalid = AdminUserPasswordHasher.VerifyPassword(
            "WrongPassword!123",
            passwordMaterial.Hash,
            passwordMaterial.Salt,
            passwordMaterial.Iterations,
            AdminUserPasswordHasher.Algorithm);

        Assert.True(valid);
        Assert.False(invalid);
    }

    [Fact]
    public async Task IssueServiceValidationPackageAsync_ReturnsPackageAndWritesAuditEntry()
    {
        var protector = new FakePackageProtector();
        var service = CreateService(out _, protector);
        var operatorAccess = OperatorContext();
        var adminAccess = AdministratorContext();

        var client = await service.CreateServiceClientAsync(
            new CreateServiceClientRequest(
                ClientCode: "inventory-api",
                ClientName: "Inventory API",
                Owner: "Supply Chain Team",
                Environment: DeploymentEnvironment.Uat,
                Description: null,
                MetadataJson: null),
            operatorAccess);

        var credential = await service.IssueHmacCredentialAsync(
            client.ClientId,
            new IssueHmacCredentialRequest(
                ExpiresAt: DateTimeOffset.UtcNow.AddDays(30),
                Scopes: ["inventory.read"],
                Notes: "Demo-issued credential",
                KeyId: "inventory-key-01",
                KeyVersion: "kms-v1"),
            operatorAccess);

        var package = await service.IssueServiceValidationPackageAsync(
            credential.CredentialId,
            new IssueCredentialPackageRequest(
                RecipientBindingId: null,
                BindingType: RecipientProtectionBindingTypes.X509StoreThumbprint,
                CertificateThumbprint: "ABCD1234EF567890ABCD1234EF567890ABCD1234",
                StoreLocation: "CurrentUser",
                StoreName: "My",
                CertificatePath: null,
                PrivateKeyPath: null,
                CertificatePem: null,
                PublicKeyPem: null,
                PublicKeyFingerprint: null,
                KeyId: null,
                KeyVersion: null,
                Reason: "Issue package for service validation"),
            operatorAccess);

        var auditEntries = await service.ListAuditLogAsync(adminAccess);

        Assert.Equal("ServiceValidation", package.PackageType);
        Assert.Equal("inventory-key-01.service.acmppkg.json", package.FileName);
        Assert.Equal("application/vnd.acmp.hmac-service-package+json", package.ContentType);
        Assert.Equal(credential.CredentialId, package.CredentialId);
        Assert.Contains(auditEntries, entry => entry.Action == "ServiceValidationPackageIssued");
        Assert.NotNull(protector.LastDefinition);
        Assert.Equal("inventory-key-01", protector.LastDefinition!.KeyId);
        Assert.Equal(CredentialPackageType.ServiceValidation, protector.LastDefinition.PackageType);
    }

    [Fact]
    public async Task IssueServiceValidationPackageAsync_UsesDecryptedSecretMaterial()
    {
        var protector = new FakePackageProtector();
        var secretProtector = CreateSecretProtector(Enumerable.Range(50, 32).Select(index => (byte)index).ToArray());
        var unitOfWork = new InMemoryAuthPlatformUnitOfWork();
        var service = new AuthPlatformApplicationService(unitOfWork, protector, secretProtector);
        var operatorAccess = OperatorContext();

        var client = await service.CreateServiceClientAsync(
            new CreateServiceClientRequest(
                ClientCode: "pricing-api",
                ClientName: "Pricing API",
                Owner: "Commercial Systems",
                Environment: DeploymentEnvironment.Uat,
                Description: null,
                MetadataJson: null),
            operatorAccess);

        var credential = await service.IssueHmacCredentialAsync(
            client.ClientId,
            new IssueHmacCredentialRequest(
                ExpiresAt: DateTimeOffset.UtcNow.AddDays(30),
                Scopes: ["pricing.read"],
                Notes: null,
                KeyId: "pricing-key-01",
                KeyVersion: "kms-v1"),
            operatorAccess);

        await service.IssueServiceValidationPackageAsync(
            credential.CredentialId,
            new IssueCredentialPackageRequest(
                RecipientBindingId: null,
                BindingType: RecipientProtectionBindingTypes.X509StoreThumbprint,
                CertificateThumbprint: "ABCD1234EF567890ABCD1234EF567890ABCD1234",
                StoreLocation: "CurrentUser",
                StoreName: "My",
                CertificatePath: null,
                PrivateKeyPath: null,
                CertificatePem: null,
                PublicKeyPem: null,
                PublicKeyFingerprint: null,
                KeyId: null,
                KeyVersion: null,
                Reason: null),
            operatorAccess);

        var storedDetail = await unitOfWork.HmacCredentialDetails.GetByCredentialIdAsync(credential.CredentialId);

        Assert.NotNull(storedDetail);
        Assert.NotNull(protector.LastDefinition);
        Assert.Equal(
            Convert.ToBase64String(secretProtector.Unprotect(storedDetail!)),
            Convert.ToBase64String(protector.LastDefinition!.Secret));
        Assert.NotEqual(
            Convert.ToBase64String(storedDetail!.EncryptedSecret),
            Convert.ToBase64String(protector.LastDefinition!.Secret));
    }

    [Fact]
    public async Task CreateRecipientProtectionBindingAndIssuePackageAsync_UsesStoredBinding()
    {
        var protector = new FakePackageProtector();
        var service = CreateService(out _, protector);
        var operatorAccess = OperatorContext();
        using var rsa = RSA.Create(3072);
        var publicKeyPem = rsa.ExportSubjectPublicKeyInfoPem();

        var client = await service.CreateServiceClientAsync(
            new CreateServiceClientRequest(
                ClientCode: "orders-api",
                ClientName: "Orders API",
                Owner: "Integration Team",
                Environment: DeploymentEnvironment.Uat,
                Description: null,
                MetadataJson: null),
            operatorAccess);

        var binding = await service.CreateRecipientProtectionBindingAsync(
            client.ClientId,
            new CreateRecipientProtectionBindingRequest(
                BindingName: "orders-api-prod-rsa-2026q2",
                BindingType: RecipientProtectionBindingTypes.ExternalRsaPublicKey,
                Algorithm: "RSA-3072",
                PublicKeyPem: publicKeyPem,
                CertificateThumbprint: null,
                StoreLocation: null,
                StoreName: null,
                CertificatePath: null,
                PrivateKeyPathHint: null,
                KeyId: "orders-api-prod-rsa",
                KeyVersion: "2026q2",
                Notes: "Primary package decryption key"),
            operatorAccess);

        var credential = await service.IssueHmacCredentialAsync(
            client.ClientId,
            new IssueHmacCredentialRequest(
                ExpiresAt: DateTimeOffset.UtcNow.AddDays(30),
                Scopes: ["orders.read"],
                Notes: "Initial credential",
                KeyId: "orders-api-hmac-1",
                KeyVersion: "kms-v1"),
            operatorAccess);

        await service.IssueServiceValidationPackageAsync(
            credential.CredentialId,
            new IssueCredentialPackageRequest(
                RecipientBindingId: binding.BindingId,
                BindingType: RecipientProtectionBindingTypes.ExternalRsaPublicKey,
                CertificateThumbprint: null,
                StoreLocation: null,
                StoreName: null,
                CertificatePath: null,
                PrivateKeyPath: null,
                CertificatePem: null,
                PublicKeyPem: null,
                PublicKeyFingerprint: null,
                KeyId: null,
                KeyVersion: null,
                Reason: "Issue package via stored binding"),
            operatorAccess);

        Assert.NotNull(protector.LastDefinition);
        Assert.Equal(binding.BindingId, protector.LastDefinition!.ProtectionBinding.BindingId);
        Assert.Equal(RecipientProtectionBindingTypes.ExternalRsaPublicKey, protector.LastDefinition.ProtectionBinding.BindingType);
        Assert.Equal("orders-api-prod-rsa", protector.LastDefinition.ProtectionBinding.KeyId);
        Assert.Equal("2026q2", protector.LastDefinition.ProtectionBinding.KeyVersion);
        Assert.NotNull(protector.LastDefinition.ProtectionBinding.PublicKeyFingerprint);
    }

    [Fact]
    public void LocalMiniKms_EncryptsAndDecryptsSecretRoundTrip()
    {
        var masterKey = Enumerable.Range(100, 32).Select(index => (byte)index).ToArray();
        var miniKms = new LocalMiniKms(new ConfiguredMasterKeyProvider(
            new Dictionary<string, byte[]> { ["kms-v1"] = masterKey },
            "kms-v1"));
        var secret = miniKms.GenerateRandomSecret();

        var encrypted = miniKms.Encrypt(secret);
        var decrypted = miniKms.Decrypt(encrypted);

        Assert.Equal("kms-v1", encrypted.KeyVersion);
        Assert.Equal("MINIKMS-LOCAL-AES256GCM", encrypted.EncryptionAlgorithm);
        Assert.Equal(Convert.ToBase64String(secret), Convert.ToBase64String(decrypted));
    }

    private static AuthPlatformApplicationService CreateService(
        out InMemoryAuthPlatformUnitOfWork unitOfWork,
        IHmacCredentialPackageProtector? packageProtector = null)
    {
        unitOfWork = new InMemoryAuthPlatformUnitOfWork();
        return new AuthPlatformApplicationService(
            unitOfWork,
            packageProtector,
            CreateSecretProtector(Enumerable.Range(1, 32).Select(index => (byte)index).ToArray()));
    }

    private static IHmacSecretProtector CreateSecretProtector(byte[] masterKey) =>
        new MiniKmsHmacSecretProtector(new LocalMiniKms(new ConfiguredMasterKeyProvider(
            new Dictionary<string, byte[]> { ["kms-v1"] = masterKey },
            "kms-v1")));

    private static AdminAccessContext AdministratorContext() =>
        new("administrator.demo", AdminAccessRole.AccessAdministrator, Guid.NewGuid().ToString("N"));

    private static AdminAccessContext OperatorContext() =>
        new("operator.demo", AdminAccessRole.AccessOperator, Guid.NewGuid().ToString("N"));

    private sealed class FakePackageProtector : IHmacCredentialPackageProtector
    {
        public HmacCredentialPackageDefinition? LastDefinition { get; private set; }

        public Task<IssuedCredentialPackage> ProtectAsync(
            HmacCredentialPackageDefinition definition,
            CancellationToken cancellationToken = default)
        {
            LastDefinition = definition;
            return Task.FromResult(new IssuedCredentialPackage(
                definition.CredentialId,
                definition.KeyId,
                definition.PackageType.ToString(),
                $"{definition.KeyId}.service.acmppkg.json",
                "application/vnd.acmp.hmac-service-package+json",
                definition.IssuedAt,
                definition.KeyVersion,
                definition.PackageId,
                [0x01, 0x02, 0x03]));
        }
    }
}
