using MyCompany.AuthPlatform.Application;
using MyCompany.AuthPlatform.Persistence.InMemory;
using MyCompany.Shared.Contracts.Domain;
using Xunit;

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

    private static AuthPlatformApplicationService CreateService(out InMemoryAuthPlatformUnitOfWork unitOfWork)
    {
        unitOfWork = new InMemoryAuthPlatformUnitOfWork();
        return new AuthPlatformApplicationService(unitOfWork);
    }

    private static AdminAccessContext AdministratorContext() =>
        new("administrator.demo", AdminAccessRole.AccessAdministrator, Guid.NewGuid().ToString("N"));

    private static AdminAccessContext OperatorContext() =>
        new("operator.demo", AdminAccessRole.AccessOperator, Guid.NewGuid().ToString("N"));
}
