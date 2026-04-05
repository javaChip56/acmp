using Microsoft.EntityFrameworkCore;
using MyCompany.AuthPlatform.Persistence.Abstractions;
using MyCompany.Shared.Contracts.Domain;

namespace MyCompany.AuthPlatform.Persistence.SqlServer;

public sealed class SqlServerAuthPlatformUnitOfWork : IAuthPlatformUnitOfWork
{
    private readonly AuthPlatformSqlServerDbContext _dbContext;

    public SqlServerAuthPlatformUnitOfWork(AuthPlatformSqlServerDbContext dbContext)
    {
        _dbContext = dbContext;
        ServiceClients = new SqlServerServiceClientRepository(dbContext);
        Credentials = new SqlServerCredentialRepository(dbContext);
        CredentialScopes = new SqlServerCredentialScopeRepository(dbContext);
        HmacCredentialDetails = new SqlServerHmacCredentialDetailRepository(dbContext);
        RecipientProtectionBindings = new SqlServerRecipientProtectionBindingRepository(dbContext);
        AuditLogs = new SqlServerAuditLogRepository(dbContext);
        AdminUsers = new SqlServerAdminUserRepository(dbContext);
        AdminUserRoles = new SqlServerAdminUserRoleRepository(dbContext);
    }

    public IServiceClientRepository ServiceClients { get; }

    public ICredentialRepository Credentials { get; }

    public ICredentialScopeRepository CredentialScopes { get; }

    public IHmacCredentialDetailRepository HmacCredentialDetails { get; }

    public IRecipientProtectionBindingRepository RecipientProtectionBindings { get; }

    public IAuditLogRepository AuditLogs { get; }

    public IAdminUserRepository AdminUsers { get; }

    public IAdminUserRoleRepository AdminUserRoles { get; }

    public Task SaveChangesAsync(CancellationToken cancellationToken = default) =>
        _dbContext.SaveChangesAsync(cancellationToken);
}

internal sealed class SqlServerServiceClientRepository : IServiceClientRepository
{
    private readonly AuthPlatformSqlServerDbContext _dbContext;

    public SqlServerServiceClientRepository(AuthPlatformSqlServerDbContext dbContext) => _dbContext = dbContext;

    public Task<ServiceClient?> GetByIdAsync(Guid clientId, CancellationToken cancellationToken = default) =>
        _dbContext.ServiceClients.SingleOrDefaultAsync(item => item.ClientId == clientId, cancellationToken);

    public Task<ServiceClient?> GetByCodeAsync(
        DeploymentEnvironment environment,
        string clientCode,
        CancellationToken cancellationToken = default) =>
        _dbContext.ServiceClients.SingleOrDefaultAsync(
            item => item.Environment == environment && item.ClientCode == clientCode,
            cancellationToken);

    public async Task<PagedResult<ServiceClient>> ListAsync(
        ListServiceClientsRequest request,
        CancellationToken cancellationToken = default)
    {
        var query = _dbContext.ServiceClients.AsQueryable();

        if (request.Environment.HasValue)
        {
            query = query.Where(item => item.Environment == request.Environment.Value);
        }

        if (request.Status.HasValue)
        {
            query = query.Where(item => item.Status == request.Status.Value);
        }

        if (!string.IsNullOrWhiteSpace(request.Owner))
        {
            query = query.Where(item => item.Owner == request.Owner);
        }

        query = query.OrderBy(item => item.Environment).ThenBy(item => item.ClientCode);
        return await PaginationQuery.ToPagedResultAsync(query, request.Skip, request.Take, cancellationToken);
    }

    public Task AddAsync(ServiceClient client, CancellationToken cancellationToken = default) =>
        _dbContext.ServiceClients.AddAsync(client, cancellationToken).AsTask();

    public Task UpdateAsync(ServiceClient client, CancellationToken cancellationToken = default)
    {
        _dbContext.ServiceClients.Update(client);
        return Task.CompletedTask;
    }
}

internal sealed class SqlServerCredentialRepository : ICredentialRepository
{
    private readonly AuthPlatformSqlServerDbContext _dbContext;

    public SqlServerCredentialRepository(AuthPlatformSqlServerDbContext dbContext) => _dbContext = dbContext;

    public Task<Credential?> GetByIdAsync(Guid credentialId, CancellationToken cancellationToken = default) =>
        _dbContext.Credentials.SingleOrDefaultAsync(item => item.CredentialId == credentialId, cancellationToken);

    public async Task<PagedResult<Credential>> ListAsync(
        ListCredentialsRequest request,
        CancellationToken cancellationToken = default)
    {
        var query = _dbContext.Credentials.AsQueryable();

        if (request.ClientId.HasValue)
        {
            query = query.Where(item => item.ClientId == request.ClientId.Value);
        }

        if (request.Environment.HasValue)
        {
            query = query.Where(item => item.Environment == request.Environment.Value);
        }

        if (request.Status.HasValue)
        {
            query = query.Where(item => item.Status == request.Status.Value);
        }

        if (request.AuthenticationMode.HasValue)
        {
            query = query.Where(item => item.AuthenticationMode == request.AuthenticationMode.Value);
        }

        query = query.OrderBy(item => item.ClientId).ThenByDescending(item => item.CreatedAt);
        return await PaginationQuery.ToPagedResultAsync(query, request.Skip, request.Take, cancellationToken);
    }

    public Task AddAsync(Credential credential, CancellationToken cancellationToken = default) =>
        _dbContext.Credentials.AddAsync(credential, cancellationToken).AsTask();

    public Task UpdateAsync(Credential credential, CancellationToken cancellationToken = default)
    {
        _dbContext.Credentials.Update(credential);
        return Task.CompletedTask;
    }
}

internal sealed class SqlServerCredentialScopeRepository : ICredentialScopeRepository
{
    private readonly AuthPlatformSqlServerDbContext _dbContext;

    public SqlServerCredentialScopeRepository(AuthPlatformSqlServerDbContext dbContext) => _dbContext = dbContext;

    public async Task<IReadOnlyList<CredentialScope>> ListByCredentialIdAsync(
        Guid credentialId,
        CancellationToken cancellationToken = default) =>
        await _dbContext.CredentialScopes
            .Where(item => item.CredentialId == credentialId)
            .OrderBy(item => item.ScopeName)
            .ToArrayAsync(cancellationToken);

    public async Task ReplaceForCredentialAsync(
        Guid credentialId,
        IReadOnlyCollection<CredentialScope> scopes,
        CancellationToken cancellationToken = default)
    {
        var existing = await _dbContext.CredentialScopes
            .Where(item => item.CredentialId == credentialId)
            .ToListAsync(cancellationToken);

        _dbContext.CredentialScopes.RemoveRange(existing);
        await _dbContext.CredentialScopes.AddRangeAsync(scopes, cancellationToken);
    }
}

internal sealed class SqlServerHmacCredentialDetailRepository : IHmacCredentialDetailRepository
{
    private readonly AuthPlatformSqlServerDbContext _dbContext;

    public SqlServerHmacCredentialDetailRepository(AuthPlatformSqlServerDbContext dbContext) => _dbContext = dbContext;

    public Task<HmacCredentialDetail?> GetByCredentialIdAsync(
        Guid credentialId,
        CancellationToken cancellationToken = default) =>
        _dbContext.HmacCredentialDetails.SingleOrDefaultAsync(item => item.CredentialId == credentialId, cancellationToken);

    public Task<HmacCredentialDetail?> GetByKeyIdAsync(
        string keyId,
        CancellationToken cancellationToken = default) =>
        _dbContext.HmacCredentialDetails.SingleOrDefaultAsync(item => item.KeyId == keyId, cancellationToken);

    public Task AddAsync(HmacCredentialDetail detail, CancellationToken cancellationToken = default) =>
        _dbContext.HmacCredentialDetails.AddAsync(detail, cancellationToken).AsTask();

    public Task UpdateAsync(HmacCredentialDetail detail, CancellationToken cancellationToken = default)
    {
        _dbContext.HmacCredentialDetails.Update(detail);
        return Task.CompletedTask;
    }
}

internal sealed class SqlServerAuditLogRepository : IAuditLogRepository
{
    private readonly AuthPlatformSqlServerDbContext _dbContext;

    public SqlServerAuditLogRepository(AuthPlatformSqlServerDbContext dbContext) => _dbContext = dbContext;

    public Task AddAsync(AuditLogEntry entry, CancellationToken cancellationToken = default) =>
        _dbContext.AuditLogs.AddAsync(entry, cancellationToken).AsTask();

    public async Task<PagedResult<AuditLogEntry>> ListAsync(
        ListAuditLogEntriesRequest request,
        CancellationToken cancellationToken = default)
    {
        var query = _dbContext.AuditLogs.AsQueryable();

        if (!string.IsNullOrWhiteSpace(request.Actor))
        {
            query = query.Where(item => item.Actor == request.Actor);
        }

        if (!string.IsNullOrWhiteSpace(request.Action))
        {
            query = query.Where(item => item.Action == request.Action);
        }

        if (!string.IsNullOrWhiteSpace(request.TargetType))
        {
            query = query.Where(item => item.TargetType == request.TargetType);
        }

        if (!string.IsNullOrWhiteSpace(request.TargetId))
        {
            query = query.Where(item => item.TargetId == request.TargetId);
        }

        if (request.FromUtc.HasValue)
        {
            query = query.Where(item => item.Timestamp >= request.FromUtc.Value);
        }

        if (request.ToUtc.HasValue)
        {
            query = query.Where(item => item.Timestamp <= request.ToUtc.Value);
        }

        query = query.OrderByDescending(item => item.Timestamp);
        return await PaginationQuery.ToPagedResultAsync(query, request.Skip, request.Take, cancellationToken);
    }
}

internal sealed class SqlServerRecipientProtectionBindingRepository : IRecipientProtectionBindingRepository
{
    private readonly AuthPlatformSqlServerDbContext _dbContext;

    public SqlServerRecipientProtectionBindingRepository(AuthPlatformSqlServerDbContext dbContext) => _dbContext = dbContext;

    public Task<RecipientProtectionBinding?> GetByIdAsync(Guid bindingId, CancellationToken cancellationToken = default) =>
        _dbContext.RecipientProtectionBindings.SingleOrDefaultAsync(item => item.BindingId == bindingId, cancellationToken);

    public Task<RecipientProtectionBinding?> GetByNameAsync(
        Guid clientId,
        string bindingName,
        CancellationToken cancellationToken = default) =>
        _dbContext.RecipientProtectionBindings.SingleOrDefaultAsync(
            item => item.ClientId == clientId && item.BindingName == bindingName,
            cancellationToken);

    public async Task<PagedResult<RecipientProtectionBinding>> ListAsync(
        ListRecipientProtectionBindingsRequest request,
        CancellationToken cancellationToken = default)
    {
        var query = _dbContext.RecipientProtectionBindings.AsQueryable();

        if (request.ClientId.HasValue)
        {
            query = query.Where(item => item.ClientId == request.ClientId.Value);
        }

        if (request.Status.HasValue)
        {
            query = query.Where(item => item.Status == request.Status.Value);
        }

        if (!string.IsNullOrWhiteSpace(request.BindingType))
        {
            query = query.Where(item => item.BindingType == request.BindingType);
        }

        query = query.OrderBy(item => item.ClientId).ThenBy(item => item.BindingName);
        return await PaginationQuery.ToPagedResultAsync(query, request.Skip, request.Take, cancellationToken);
    }

    public Task AddAsync(RecipientProtectionBinding binding, CancellationToken cancellationToken = default) =>
        _dbContext.RecipientProtectionBindings.AddAsync(binding, cancellationToken).AsTask();

    public Task UpdateAsync(RecipientProtectionBinding binding, CancellationToken cancellationToken = default)
    {
        _dbContext.RecipientProtectionBindings.Update(binding);
        return Task.CompletedTask;
    }
}

internal sealed class SqlServerAdminUserRepository : IAdminUserRepository
{
    private readonly AuthPlatformSqlServerDbContext _dbContext;

    public SqlServerAdminUserRepository(AuthPlatformSqlServerDbContext dbContext) => _dbContext = dbContext;

    public Task<AdminUser?> GetByIdAsync(Guid userId, CancellationToken cancellationToken = default) =>
        _dbContext.AdminUsers.SingleOrDefaultAsync(item => item.UserId == userId, cancellationToken);

    public Task<AdminUser?> GetByUsernameAsync(string username, CancellationToken cancellationToken = default) =>
        _dbContext.AdminUsers.SingleOrDefaultAsync(item => item.Username == username, cancellationToken);

    public async Task<PagedResult<AdminUser>> ListAsync(
        ListAdminUsersRequest request,
        CancellationToken cancellationToken = default)
    {
        var query = _dbContext.AdminUsers.AsQueryable();

        if (request.Status.HasValue)
        {
            query = query.Where(item => item.Status == request.Status.Value);
        }

        if (!string.IsNullOrWhiteSpace(request.Username))
        {
            query = query.Where(item => item.Username == request.Username);
        }

        query = query.OrderBy(item => item.Username);
        return await PaginationQuery.ToPagedResultAsync(query, request.Skip, request.Take, cancellationToken);
    }

    public Task AddAsync(AdminUser user, CancellationToken cancellationToken = default) =>
        _dbContext.AdminUsers.AddAsync(user, cancellationToken).AsTask();

    public Task UpdateAsync(AdminUser user, CancellationToken cancellationToken = default)
    {
        _dbContext.AdminUsers.Update(user);
        return Task.CompletedTask;
    }
}

internal sealed class SqlServerAdminUserRoleRepository : IAdminUserRoleRepository
{
    private readonly AuthPlatformSqlServerDbContext _dbContext;

    public SqlServerAdminUserRoleRepository(AuthPlatformSqlServerDbContext dbContext) => _dbContext = dbContext;

    public async Task<IReadOnlyList<AdminUserRoleAssignment>> ListByUserIdAsync(
        Guid userId,
        CancellationToken cancellationToken = default) =>
        await _dbContext.AdminUserRoles
            .Where(item => item.UserId == userId)
            .OrderBy(item => item.RoleName)
            .ToArrayAsync(cancellationToken);

    public async Task ReplaceForUserAsync(
        Guid userId,
        IReadOnlyCollection<AdminUserRoleAssignment> roles,
        CancellationToken cancellationToken = default)
    {
        var existing = await _dbContext.AdminUserRoles
            .Where(item => item.UserId == userId)
            .ToListAsync(cancellationToken);

        _dbContext.AdminUserRoles.RemoveRange(existing);
        await _dbContext.AdminUserRoles.AddRangeAsync(roles, cancellationToken);
    }
}

internal static class PaginationQuery
{
    public static async Task<PagedResult<T>> ToPagedResultAsync<T>(
        IQueryable<T> query,
        int skip,
        int take,
        CancellationToken cancellationToken)
    {
        var safeSkip = Math.Max(skip, 0);
        var safeTake = take <= 0 ? 50 : take;
        var totalCount = await query.CountAsync(cancellationToken);
        var items = await query.Skip(safeSkip).Take(safeTake).ToArrayAsync(cancellationToken);

        return new PagedResult<T>
        {
            Items = items,
            Skip = safeSkip,
            Take = safeTake,
            TotalCount = totalCount,
        };
    }
}
