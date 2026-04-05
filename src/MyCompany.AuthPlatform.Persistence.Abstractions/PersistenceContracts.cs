using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using MyCompany.Shared.Contracts.Domain;

namespace MyCompany.AuthPlatform.Persistence.Abstractions;

public sealed class ListServiceClientsRequest
{
    public DeploymentEnvironment? Environment { get; init; }
    public ServiceClientStatus? Status { get; init; }
    public string? Owner { get; init; }
    public int Skip { get; init; }
    public int Take { get; init; } = 50;
}

public sealed class ListCredentialsRequest
{
    public Guid? ClientId { get; init; }
    public DeploymentEnvironment? Environment { get; init; }
    public CredentialStatus? Status { get; init; }
    public AuthenticationMode? AuthenticationMode { get; init; }
    public int Skip { get; init; }
    public int Take { get; init; } = 50;
}

public sealed class ListAuditLogEntriesRequest
{
    public string? Actor { get; init; }
    public string? Action { get; init; }
    public string? TargetType { get; init; }
    public string? TargetId { get; init; }
    public DateTimeOffset? FromUtc { get; init; }
    public DateTimeOffset? ToUtc { get; init; }
    public int Skip { get; init; }
    public int Take { get; init; } = 100;
}

public sealed class ListAdminUsersRequest
{
    public AdminUserStatus? Status { get; init; }
    public string? Username { get; init; }
    public int Skip { get; init; }
    public int Take { get; init; } = 50;
}

public sealed class ListRecipientProtectionBindingsRequest
{
    public Guid? ClientId { get; init; }
    public RecipientProtectionBindingStatus? Status { get; init; }
    public string? BindingType { get; init; }
    public int Skip { get; init; }
    public int Take { get; init; } = 50;
}

public interface IServiceClientRepository
{
    Task<ServiceClient?> GetByIdAsync(Guid clientId, CancellationToken cancellationToken = default);
    Task<ServiceClient?> GetByCodeAsync(
        DeploymentEnvironment environment,
        string clientCode,
        CancellationToken cancellationToken = default);
    Task<PagedResult<ServiceClient>> ListAsync(
        ListServiceClientsRequest request,
        CancellationToken cancellationToken = default);
    Task AddAsync(ServiceClient client, CancellationToken cancellationToken = default);
    Task UpdateAsync(ServiceClient client, CancellationToken cancellationToken = default);
}

public interface ICredentialRepository
{
    Task<Credential?> GetByIdAsync(Guid credentialId, CancellationToken cancellationToken = default);
    Task<PagedResult<Credential>> ListAsync(
        ListCredentialsRequest request,
        CancellationToken cancellationToken = default);
    Task AddAsync(Credential credential, CancellationToken cancellationToken = default);
    Task UpdateAsync(Credential credential, CancellationToken cancellationToken = default);
}

public interface ICredentialScopeRepository
{
    Task<IReadOnlyList<CredentialScope>> ListByCredentialIdAsync(
        Guid credentialId,
        CancellationToken cancellationToken = default);
    Task ReplaceForCredentialAsync(
        Guid credentialId,
        IReadOnlyCollection<CredentialScope> scopes,
        CancellationToken cancellationToken = default);
}

public interface IHmacCredentialDetailRepository
{
    Task<HmacCredentialDetail?> GetByCredentialIdAsync(
        Guid credentialId,
        CancellationToken cancellationToken = default);
    Task<HmacCredentialDetail?> GetByKeyIdAsync(
        string keyId,
        CancellationToken cancellationToken = default);
    Task AddAsync(HmacCredentialDetail detail, CancellationToken cancellationToken = default);
    Task UpdateAsync(HmacCredentialDetail detail, CancellationToken cancellationToken = default);
}

public interface IRecipientProtectionBindingRepository
{
    Task<RecipientProtectionBinding?> GetByIdAsync(Guid bindingId, CancellationToken cancellationToken = default);
    Task<RecipientProtectionBinding?> GetByNameAsync(
        Guid clientId,
        string bindingName,
        CancellationToken cancellationToken = default);
    Task<PagedResult<RecipientProtectionBinding>> ListAsync(
        ListRecipientProtectionBindingsRequest request,
        CancellationToken cancellationToken = default);
    Task AddAsync(RecipientProtectionBinding binding, CancellationToken cancellationToken = default);
    Task UpdateAsync(RecipientProtectionBinding binding, CancellationToken cancellationToken = default);
}

public interface IAuditLogRepository
{
    Task AddAsync(AuditLogEntry entry, CancellationToken cancellationToken = default);
    Task<PagedResult<AuditLogEntry>> ListAsync(
        ListAuditLogEntriesRequest request,
        CancellationToken cancellationToken = default);
}

public interface IAdminUserRepository
{
    Task<AdminUser?> GetByIdAsync(Guid userId, CancellationToken cancellationToken = default);
    Task<AdminUser?> GetByUsernameAsync(string username, CancellationToken cancellationToken = default);
    Task<PagedResult<AdminUser>> ListAsync(
        ListAdminUsersRequest request,
        CancellationToken cancellationToken = default);
    Task AddAsync(AdminUser user, CancellationToken cancellationToken = default);
    Task UpdateAsync(AdminUser user, CancellationToken cancellationToken = default);
}

public interface IAdminUserRoleRepository
{
    Task<IReadOnlyList<AdminUserRoleAssignment>> ListByUserIdAsync(
        Guid userId,
        CancellationToken cancellationToken = default);
    Task ReplaceForUserAsync(
        Guid userId,
        IReadOnlyCollection<AdminUserRoleAssignment> roles,
        CancellationToken cancellationToken = default);
}

public interface IAuthPlatformUnitOfWork
{
    IServiceClientRepository ServiceClients { get; }
    ICredentialRepository Credentials { get; }
    ICredentialScopeRepository CredentialScopes { get; }
    IHmacCredentialDetailRepository HmacCredentialDetails { get; }
    IRecipientProtectionBindingRepository RecipientProtectionBindings { get; }
    IAuditLogRepository AuditLogs { get; }
    IAdminUserRepository AdminUsers { get; }
    IAdminUserRoleRepository AdminUserRoles { get; }

    Task SaveChangesAsync(CancellationToken cancellationToken = default);
}
