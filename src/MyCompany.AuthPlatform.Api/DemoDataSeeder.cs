using Microsoft.Extensions.Options;
using MyCompany.AuthPlatform.Application;
using MyCompany.AuthPlatform.Persistence.Abstractions;
using MyCompany.Shared.Contracts.Domain;

namespace MyCompany.AuthPlatform.Api;

internal sealed class DemoDataSeeder
{
    private readonly IAuthPlatformUnitOfWork _unitOfWork;
    private readonly DemoModeOptions _options;
    private readonly AuthProviderOptions _authProviderOptions;
    private readonly IHmacSecretProtector _secretProtector;

    public DemoDataSeeder(
        IAuthPlatformUnitOfWork unitOfWork,
        IOptions<DemoModeOptions> options,
        IOptions<AuthProviderOptions> authProviderOptions,
        IHmacSecretProtector secretProtector)
    {
        _unitOfWork = unitOfWork;
        _options = options.Value;
        _authProviderOptions = authProviderOptions.Value;
        _secretProtector = secretProtector;
    }

    public async Task SeedAsync(CancellationToken cancellationToken = default)
    {
        if (!_options.SeedOnStartup)
        {
            return;
        }

        await SeedAdminUsersAsync(cancellationToken);

        var existingClients = await _unitOfWork.ServiceClients.ListAsync(
            new ListServiceClientsRequest { Take = 1 },
            cancellationToken);

        if (existingClients.TotalCount > 0)
        {
            return;
        }

        var now = DateTimeOffset.UtcNow;

        var ordersClientId = Guid.Parse("1f4a8ec5-31f6-4df8-8b7d-6c22f4f9d0a1");
        var billingClientId = Guid.Parse("6df1d8fd-1ce5-4c50-a59b-0a8e6f540ab3");

        var rotatedCredentialId = Guid.Parse("b9a6bd4f-30a6-413d-8d11-50612f5cf11b");
        var activeCredentialId = Guid.Parse("bd0dd9fc-90d2-4dc8-a99e-5f5d65d8b041");
        var revokedCredentialId = Guid.Parse("1f8e89ef-80cf-4e56-bf58-0f8684ea7d0e");

        await _unitOfWork.ServiceClients.AddAsync(
            new ServiceClient
            {
                ClientId = ordersClientId,
                ClientCode = "orders-api",
                ClientName = "Orders API",
                Owner = "Integration Platform Team",
                Environment = DeploymentEnvironment.Uat,
                Status = ServiceClientStatus.Active,
                Description = "Demo protected API for internal order-processing flows.",
                MetadataJson = """{"businessUnit":"Operations","contactEmail":"integration-platform@example.internal"}""",
                CreatedAt = now.AddDays(-60),
                CreatedBy = "seed.demo",
                UpdatedAt = now.AddDays(-2),
                UpdatedBy = "seed.demo",
            },
            cancellationToken);

        await _unitOfWork.ServiceClients.AddAsync(
            new ServiceClient
            {
                ClientId = billingClientId,
                ClientCode = "billing-worker",
                ClientName = "Billing Worker",
                Owner = "Payments Team",
                Environment = DeploymentEnvironment.Uat,
                Status = ServiceClientStatus.Active,
                Description = "Demo client for recurring billing synchronization.",
                MetadataJson = """{"businessUnit":"Finance","contactEmail":"payments@example.internal"}""",
                CreatedAt = now.AddDays(-45),
                CreatedBy = "seed.demo",
                UpdatedAt = now.AddDays(-1),
                UpdatedBy = "seed.demo",
            },
            cancellationToken);

        await _unitOfWork.Credentials.AddAsync(
            new Credential
            {
                CredentialId = rotatedCredentialId,
                ClientId = ordersClientId,
                AuthenticationMode = AuthenticationMode.Hmac,
                Status = CredentialStatus.Active,
                Environment = DeploymentEnvironment.Uat,
                ExpiresAt = now.AddMonths(6),
                ReplacedByCredentialId = activeCredentialId,
                RotationGraceEndsAt = now.AddDays(7),
                Notes = "Superseded credential retained during demo grace period.",
                CreatedAt = now.AddDays(-30),
                CreatedBy = "access.operator.demo",
                UpdatedAt = now.AddDays(-1),
                UpdatedBy = "access.administrator.demo",
            },
            cancellationToken);

        await _unitOfWork.Credentials.AddAsync(
            new Credential
            {
                CredentialId = activeCredentialId,
                ClientId = ordersClientId,
                AuthenticationMode = AuthenticationMode.Hmac,
                Status = CredentialStatus.Active,
                Environment = DeploymentEnvironment.Uat,
                ExpiresAt = now.AddMonths(12),
                Notes = "Current active credential for Orders API.",
                CreatedAt = now.AddDays(-1),
                CreatedBy = "access.operator.demo",
                UpdatedAt = now.AddHours(-12),
                UpdatedBy = "access.operator.demo",
            },
            cancellationToken);

        await _unitOfWork.Credentials.AddAsync(
            new Credential
            {
                CredentialId = revokedCredentialId,
                ClientId = billingClientId,
                AuthenticationMode = AuthenticationMode.Hmac,
                Status = CredentialStatus.Revoked,
                Environment = DeploymentEnvironment.Uat,
                ExpiresAt = now.AddMonths(3),
                RevokedAt = now.AddDays(-3),
                Notes = "Revoked after suspected exposure during a demo scenario.",
                CreatedAt = now.AddDays(-20),
                CreatedBy = "access.operator.demo",
                UpdatedAt = now.AddDays(-3),
                UpdatedBy = "access.administrator.demo",
            },
            cancellationToken);

        await _unitOfWork.CredentialScopes.ReplaceForCredentialAsync(
            rotatedCredentialId,
            [
                new CredentialScope
                {
                    CredentialId = rotatedCredentialId,
                    ScopeName = "orders.read",
                    CreatedAt = now.AddDays(-30),
                    CreatedBy = "seed.demo",
                },
                new CredentialScope
                {
                    CredentialId = rotatedCredentialId,
                    ScopeName = "orders.write",
                    CreatedAt = now.AddDays(-30),
                    CreatedBy = "seed.demo",
                }
            ],
            cancellationToken);

        await _unitOfWork.CredentialScopes.ReplaceForCredentialAsync(
            activeCredentialId,
            [
                new CredentialScope
                {
                    CredentialId = activeCredentialId,
                    ScopeName = "orders.read",
                    CreatedAt = now.AddDays(-1),
                    CreatedBy = "seed.demo",
                },
                new CredentialScope
                {
                    CredentialId = activeCredentialId,
                    ScopeName = "orders.write",
                    CreatedAt = now.AddDays(-1),
                    CreatedBy = "seed.demo",
                }
            ],
            cancellationToken);

        await _unitOfWork.CredentialScopes.ReplaceForCredentialAsync(
            revokedCredentialId,
            [
                new CredentialScope
                {
                    CredentialId = revokedCredentialId,
                    ScopeName = "billing.sync",
                    CreatedAt = now.AddDays(-20),
                    CreatedBy = "seed.demo",
                }
            ],
            cancellationToken);

        await _unitOfWork.HmacCredentialDetails.AddAsync(
            CreateHmacDetail(rotatedCredentialId, "key-uat-orders-0001", "kms-v1", _secretProtector),
            cancellationToken);
        await _unitOfWork.HmacCredentialDetails.AddAsync(
            CreateHmacDetail(activeCredentialId, "key-uat-orders-0002", "kms-v1", _secretProtector),
            cancellationToken);
        await _unitOfWork.HmacCredentialDetails.AddAsync(
            CreateHmacDetail(revokedCredentialId, "key-uat-billing-0001", "kms-v1", _secretProtector),
            cancellationToken);

        await _unitOfWork.AuditLogs.AddAsync(
            new AuditLogEntry
            {
                AuditId = Guid.Parse("0c67a837-f3b3-41c3-a31b-fc57fb45ef29"),
                Timestamp = now.AddDays(-30),
                Actor = "access.operator.demo",
                Action = "CredentialIssued",
                TargetType = "Credential",
                TargetId = rotatedCredentialId.ToString(),
                Environment = DeploymentEnvironment.Uat,
                Reason = "Initial seeded demo credential.",
                Outcome = AuditOutcome.Succeeded,
                CorrelationId = "demo-seed-001",
                MetadataJson = """{"role":"AccessOperator","gracePeriodDays":0}""",
            },
            cancellationToken);

        await _unitOfWork.AuditLogs.AddAsync(
            new AuditLogEntry
            {
                AuditId = Guid.Parse("2b0dff7f-f7ef-4d14-b10b-1d70b4f88bc9"),
                Timestamp = now.AddDays(-1),
                Actor = "access.administrator.demo",
                Action = "CredentialRotated",
                TargetType = "Credential",
                TargetId = rotatedCredentialId.ToString(),
                Environment = DeploymentEnvironment.Uat,
                Reason = "Demo rotation with bounded grace period.",
                Outcome = AuditOutcome.Succeeded,
                CorrelationId = "demo-seed-002",
                MetadataJson = """{"role":"AccessAdministrator","replacementCredentialId":"bd0dd9fc-90d2-4dc8-a99e-5f5d65d8b041","gracePeriodDays":7}""",
            },
            cancellationToken);

        await _unitOfWork.AuditLogs.AddAsync(
            new AuditLogEntry
            {
                AuditId = Guid.Parse("d8e6ba24-4058-44b7-8fe6-f4836de371a8"),
                Timestamp = now.AddDays(-3),
                Actor = "access.administrator.demo",
                Action = "CredentialRevoked",
                TargetType = "Credential",
                TargetId = revokedCredentialId.ToString(),
                Environment = DeploymentEnvironment.Uat,
                Reason = "Simulated credential exposure during demo setup.",
                Outcome = AuditOutcome.Succeeded,
                CorrelationId = "demo-seed-003",
                MetadataJson = """{"role":"AccessAdministrator"}""",
            },
            cancellationToken);

        await _unitOfWork.SaveChangesAsync(cancellationToken);
    }

    private async Task SeedAdminUsersAsync(CancellationToken cancellationToken)
    {
        foreach (var configuredUser in _authProviderOptions.EmbeddedIdentity.Users)
        {
            if (string.IsNullOrWhiteSpace(configuredUser.Username) || string.IsNullOrWhiteSpace(configuredUser.Password))
            {
                continue;
            }

            var existing = await _unitOfWork.AdminUsers.GetByUsernameAsync(configuredUser.Username.Trim(), cancellationToken);
            if (existing is not null)
            {
                continue;
            }

            var now = DateTimeOffset.UtcNow;
            var passwordMaterial = AdminUserPasswordHasher.HashPassword(configuredUser.Password);
            var user = new AdminUser
            {
                UserId = Guid.NewGuid(),
                Username = configuredUser.Username.Trim(),
                DisplayName = string.IsNullOrWhiteSpace(configuredUser.DisplayName)
                    ? configuredUser.Username.Trim()
                    : configuredUser.DisplayName.Trim(),
                Status = AdminUserStatus.Active,
                PasswordHash = passwordMaterial.Hash,
                PasswordSalt = passwordMaterial.Salt,
                PasswordHashAlgorithm = AdminUserPasswordHasher.Algorithm,
                PasswordIterations = passwordMaterial.Iterations,
                CreatedAt = now,
                CreatedBy = "seed.demo",
                UpdatedAt = now,
                UpdatedBy = "seed.demo",
                ConcurrencyToken = Guid.NewGuid().ToString("N"),
            };

            await _unitOfWork.AdminUsers.AddAsync(user, cancellationToken);
            await _unitOfWork.AdminUserRoles.ReplaceForUserAsync(
                user.UserId,
                configuredUser.Roles
                    .Where(role => !string.IsNullOrWhiteSpace(role))
                    .Select(role => new AdminUserRoleAssignment
                    {
                        UserId = user.UserId,
                        RoleName = role.Trim(),
                        CreatedAt = now,
                        CreatedBy = "seed.demo",
                    })
                    .ToArray(),
                cancellationToken);
        }
    }

    private static HmacCredentialDetail CreateHmacDetail(
        Guid credentialId,
        string keyId,
        string keyVersion,
        IHmacSecretProtector secretProtector)
    {
        var secret = secretProtector.GenerateSecret();
        var protectionResult = secretProtector.Protect(secret, keyVersion);

        return new HmacCredentialDetail
        {
            CredentialId = credentialId,
            KeyId = keyId,
            KeyVersion = keyVersion,
            HmacAlgorithm = HmacAlgorithm.HmacSha256,
            EncryptionAlgorithm = protectionResult.EncryptionAlgorithm,
            EncryptedSecret = protectionResult.EncryptedSecret,
            EncryptedDataKey = protectionResult.EncryptedDataKey,
            Iv = protectionResult.Iv,
            Tag = protectionResult.Tag,
        };
    }
}
