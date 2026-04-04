using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using MyCompany.AuthPlatform.Persistence.Abstractions;
using MyCompany.Shared.Contracts.Domain;

namespace MyCompany.AuthPlatform.Persistence.InMemory;

public sealed class InMemoryAuthPlatformUnitOfWork : IAuthPlatformUnitOfWork
{
    private readonly InMemoryPersistenceState _state;

    public InMemoryAuthPlatformUnitOfWork()
        : this(new InMemoryPersistenceState())
    {
    }

    public InMemoryAuthPlatformUnitOfWork(InMemoryPersistenceState state)
    {
        _state = state;
        ServiceClients = new InMemoryServiceClientRepository(_state);
        Credentials = new InMemoryCredentialRepository(_state);
        CredentialScopes = new InMemoryCredentialScopeRepository(_state);
        HmacCredentialDetails = new InMemoryHmacCredentialDetailRepository(_state);
        AuditLogs = new InMemoryAuditLogRepository(_state);
    }

    public IServiceClientRepository ServiceClients { get; }

    public ICredentialRepository Credentials { get; }

    public ICredentialScopeRepository CredentialScopes { get; }

    public IHmacCredentialDetailRepository HmacCredentialDetails { get; }

    public IAuditLogRepository AuditLogs { get; }

    public Task SaveChangesAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
}

public sealed class InMemoryPersistenceState
{
    internal object SyncRoot { get; } = new();
    internal Dictionary<Guid, ServiceClient> ServiceClients { get; } = new();
    internal Dictionary<Guid, Credential> Credentials { get; } = new();
    internal Dictionary<(Guid CredentialId, string ScopeName), CredentialScope> CredentialScopes { get; } = new();
    internal Dictionary<Guid, HmacCredentialDetail> HmacCredentialDetails { get; } = new();
    internal Dictionary<string, Guid> KeyIds { get; } = new(StringComparer.Ordinal);
    internal Dictionary<Guid, AuditLogEntry> AuditLogs { get; } = new();
}

internal sealed class InMemoryServiceClientRepository : IServiceClientRepository
{
    private readonly InMemoryPersistenceState _state;

    public InMemoryServiceClientRepository(InMemoryPersistenceState state) => _state = state;

    public Task<ServiceClient?> GetByIdAsync(Guid clientId, CancellationToken cancellationToken = default)
    {
        lock (_state.SyncRoot)
        {
            return Task.FromResult(
                _state.ServiceClients.TryGetValue(clientId, out var client) ? Clone(client) : null);
        }
    }

    public Task<ServiceClient?> GetByCodeAsync(
        DeploymentEnvironment environment,
        string clientCode,
        CancellationToken cancellationToken = default)
    {
        lock (_state.SyncRoot)
        {
            var client = _state.ServiceClients.Values.FirstOrDefault(
                item => item.Environment == environment && string.Equals(item.ClientCode, clientCode, StringComparison.Ordinal));
            return Task.FromResult(client is null ? null : Clone(client));
        }
    }

    public Task<PagedResult<ServiceClient>> ListAsync(
        ListServiceClientsRequest request,
        CancellationToken cancellationToken = default)
    {
        lock (_state.SyncRoot)
        {
            var query = _state.ServiceClients.Values.AsEnumerable();

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
                query = query.Where(item => string.Equals(item.Owner, request.Owner, StringComparison.Ordinal));
            }

            var ordered = query
                .OrderBy(item => item.Environment)
                .ThenBy(item => item.ClientCode, StringComparer.Ordinal)
                .Select(Clone)
                .ToList();

            return Task.FromResult(Pagination.Paginate(ordered, request.Skip, request.Take));
        }
    }

    public Task AddAsync(ServiceClient client, CancellationToken cancellationToken = default)
    {
        lock (_state.SyncRoot)
        {
            if (_state.ServiceClients.ContainsKey(client.ClientId))
            {
                throw new InvalidOperationException($"Service client '{client.ClientId}' already exists.");
            }

            var duplicateCode = _state.ServiceClients.Values.Any(item =>
                item.Environment == client.Environment &&
                string.Equals(item.ClientCode, client.ClientCode, StringComparison.Ordinal));

            if (duplicateCode)
            {
                throw new InvalidOperationException(
                    $"Client code '{client.ClientCode}' already exists in environment '{client.Environment}'.");
            }

            _state.ServiceClients[client.ClientId] = Clone(client);
            return Task.CompletedTask;
        }
    }

    public Task UpdateAsync(ServiceClient client, CancellationToken cancellationToken = default)
    {
        lock (_state.SyncRoot)
        {
            if (!_state.ServiceClients.ContainsKey(client.ClientId))
            {
                throw new KeyNotFoundException($"Service client '{client.ClientId}' was not found.");
            }

            var duplicateCode = _state.ServiceClients.Values.Any(item =>
                item.ClientId != client.ClientId &&
                item.Environment == client.Environment &&
                string.Equals(item.ClientCode, client.ClientCode, StringComparison.Ordinal));

            if (duplicateCode)
            {
                throw new InvalidOperationException(
                    $"Client code '{client.ClientCode}' already exists in environment '{client.Environment}'.");
            }

            _state.ServiceClients[client.ClientId] = Clone(client);
            return Task.CompletedTask;
        }
    }

    private static ServiceClient Clone(ServiceClient client) =>
        new()
        {
            ClientId = client.ClientId,
            ClientCode = client.ClientCode,
            ClientName = client.ClientName,
            Owner = client.Owner,
            Environment = client.Environment,
            Status = client.Status,
            Description = client.Description,
            MetadataJson = client.MetadataJson,
            DisabledAt = client.DisabledAt,
            CreatedAt = client.CreatedAt,
            CreatedBy = client.CreatedBy,
            UpdatedAt = client.UpdatedAt,
            UpdatedBy = client.UpdatedBy,
            ConcurrencyToken = client.ConcurrencyToken,
        };
}

internal sealed class InMemoryCredentialRepository : ICredentialRepository
{
    private readonly InMemoryPersistenceState _state;

    public InMemoryCredentialRepository(InMemoryPersistenceState state) => _state = state;

    public Task<Credential?> GetByIdAsync(Guid credentialId, CancellationToken cancellationToken = default)
    {
        lock (_state.SyncRoot)
        {
            return Task.FromResult(
                _state.Credentials.TryGetValue(credentialId, out var credential) ? Clone(credential) : null);
        }
    }

    public Task<PagedResult<Credential>> ListAsync(
        ListCredentialsRequest request,
        CancellationToken cancellationToken = default)
    {
        lock (_state.SyncRoot)
        {
            var query = _state.Credentials.Values.AsEnumerable();

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

            var ordered = query
                .OrderBy(item => item.ClientId)
                .ThenByDescending(item => item.CreatedAt)
                .Select(Clone)
                .ToList();

            return Task.FromResult(Pagination.Paginate(ordered, request.Skip, request.Take));
        }
    }

    public Task AddAsync(Credential credential, CancellationToken cancellationToken = default)
    {
        lock (_state.SyncRoot)
        {
            if (_state.Credentials.ContainsKey(credential.CredentialId))
            {
                throw new InvalidOperationException($"Credential '{credential.CredentialId}' already exists.");
            }

            if (!_state.ServiceClients.ContainsKey(credential.ClientId))
            {
                throw new InvalidOperationException(
                    $"Credential '{credential.CredentialId}' references unknown client '{credential.ClientId}'.");
            }

            _state.Credentials[credential.CredentialId] = Clone(credential);
            return Task.CompletedTask;
        }
    }

    public Task UpdateAsync(Credential credential, CancellationToken cancellationToken = default)
    {
        lock (_state.SyncRoot)
        {
            if (!_state.Credentials.ContainsKey(credential.CredentialId))
            {
                throw new KeyNotFoundException($"Credential '{credential.CredentialId}' was not found.");
            }

            _state.Credentials[credential.CredentialId] = Clone(credential);
            return Task.CompletedTask;
        }
    }

    private static Credential Clone(Credential credential) =>
        new()
        {
            CredentialId = credential.CredentialId,
            ClientId = credential.ClientId,
            AuthenticationMode = credential.AuthenticationMode,
            Status = credential.Status,
            Environment = credential.Environment,
            ExpiresAt = credential.ExpiresAt,
            DisabledAt = credential.DisabledAt,
            RevokedAt = credential.RevokedAt,
            ReplacedByCredentialId = credential.ReplacedByCredentialId,
            RotationGraceEndsAt = credential.RotationGraceEndsAt,
            Notes = credential.Notes,
            CreatedAt = credential.CreatedAt,
            CreatedBy = credential.CreatedBy,
            UpdatedAt = credential.UpdatedAt,
            UpdatedBy = credential.UpdatedBy,
            ConcurrencyToken = credential.ConcurrencyToken,
        };
}

internal sealed class InMemoryCredentialScopeRepository : ICredentialScopeRepository
{
    private readonly InMemoryPersistenceState _state;

    public InMemoryCredentialScopeRepository(InMemoryPersistenceState state) => _state = state;

    public Task<IReadOnlyList<CredentialScope>> ListByCredentialIdAsync(
        Guid credentialId,
        CancellationToken cancellationToken = default)
    {
        lock (_state.SyncRoot)
        {
            var scopes = _state.CredentialScopes.Values
                .Where(item => item.CredentialId == credentialId)
                .OrderBy(item => item.ScopeName, StringComparer.Ordinal)
                .Select(Clone)
                .ToList();

            return Task.FromResult<IReadOnlyList<CredentialScope>>(scopes);
        }
    }

    public Task ReplaceForCredentialAsync(
        Guid credentialId,
        IReadOnlyCollection<CredentialScope> scopes,
        CancellationToken cancellationToken = default)
    {
        lock (_state.SyncRoot)
        {
            if (!_state.Credentials.ContainsKey(credentialId))
            {
                throw new KeyNotFoundException($"Credential '{credentialId}' was not found.");
            }

            foreach (var key in _state.CredentialScopes.Keys.Where(key => key.CredentialId == credentialId).ToList())
            {
                _state.CredentialScopes.Remove(key);
            }

            foreach (var scope in scopes)
            {
                var key = (credentialId, scope.ScopeName);
                if (_state.CredentialScopes.ContainsKey(key))
                {
                    throw new InvalidOperationException(
                        $"Scope '{scope.ScopeName}' is duplicated for credential '{credentialId}'.");
                }

                _state.CredentialScopes[key] = Clone(scope);
            }

            return Task.CompletedTask;
        }
    }

    private static CredentialScope Clone(CredentialScope scope) =>
        new()
        {
            CredentialId = scope.CredentialId,
            ScopeName = scope.ScopeName,
            CreatedAt = scope.CreatedAt,
            CreatedBy = scope.CreatedBy,
        };
}

internal sealed class InMemoryHmacCredentialDetailRepository : IHmacCredentialDetailRepository
{
    private readonly InMemoryPersistenceState _state;

    public InMemoryHmacCredentialDetailRepository(InMemoryPersistenceState state) => _state = state;

    public Task<HmacCredentialDetail?> GetByCredentialIdAsync(
        Guid credentialId,
        CancellationToken cancellationToken = default)
    {
        lock (_state.SyncRoot)
        {
            return Task.FromResult(
                _state.HmacCredentialDetails.TryGetValue(credentialId, out var detail) ? Clone(detail) : null);
        }
    }

    public Task<HmacCredentialDetail?> GetByKeyIdAsync(
        string keyId,
        CancellationToken cancellationToken = default)
    {
        lock (_state.SyncRoot)
        {
            if (!_state.KeyIds.TryGetValue(keyId, out var credentialId))
            {
                return Task.FromResult<HmacCredentialDetail?>(null);
            }

            return Task.FromResult(
                _state.HmacCredentialDetails.TryGetValue(credentialId, out var detail) ? Clone(detail) : null);
        }
    }

    public Task AddAsync(HmacCredentialDetail detail, CancellationToken cancellationToken = default)
    {
        lock (_state.SyncRoot)
        {
            if (_state.HmacCredentialDetails.ContainsKey(detail.CredentialId))
            {
                throw new InvalidOperationException(
                    $"HMAC detail for credential '{detail.CredentialId}' already exists.");
            }

            if (_state.KeyIds.ContainsKey(detail.KeyId))
            {
                throw new InvalidOperationException($"KeyId '{detail.KeyId}' already exists.");
            }

            if (!_state.Credentials.ContainsKey(detail.CredentialId))
            {
                throw new InvalidOperationException(
                    $"HMAC detail references unknown credential '{detail.CredentialId}'.");
            }

            _state.HmacCredentialDetails[detail.CredentialId] = Clone(detail);
            _state.KeyIds[detail.KeyId] = detail.CredentialId;
            return Task.CompletedTask;
        }
    }

    public Task UpdateAsync(HmacCredentialDetail detail, CancellationToken cancellationToken = default)
    {
        lock (_state.SyncRoot)
        {
            if (!_state.HmacCredentialDetails.TryGetValue(detail.CredentialId, out var existing))
            {
                throw new KeyNotFoundException(
                    $"HMAC detail for credential '{detail.CredentialId}' was not found.");
            }

            if (!string.Equals(existing.KeyId, detail.KeyId, StringComparison.Ordinal) &&
                _state.KeyIds.ContainsKey(detail.KeyId))
            {
                throw new InvalidOperationException($"KeyId '{detail.KeyId}' already exists.");
            }

            _state.KeyIds.Remove(existing.KeyId);
            _state.HmacCredentialDetails[detail.CredentialId] = Clone(detail);
            _state.KeyIds[detail.KeyId] = detail.CredentialId;
            return Task.CompletedTask;
        }
    }

    private static HmacCredentialDetail Clone(HmacCredentialDetail detail) =>
        new()
        {
            CredentialId = detail.CredentialId,
            KeyId = detail.KeyId,
            EncryptedSecret = detail.EncryptedSecret.ToArray(),
            EncryptedDataKey = detail.EncryptedDataKey.ToArray(),
            KeyVersion = detail.KeyVersion,
            HmacAlgorithm = detail.HmacAlgorithm,
            EncryptionAlgorithm = detail.EncryptionAlgorithm,
            Iv = detail.Iv?.ToArray(),
            Tag = detail.Tag?.ToArray(),
            LastUsedAt = detail.LastUsedAt,
        };
}

internal sealed class InMemoryAuditLogRepository : IAuditLogRepository
{
    private readonly InMemoryPersistenceState _state;

    public InMemoryAuditLogRepository(InMemoryPersistenceState state) => _state = state;

    public Task AddAsync(AuditLogEntry entry, CancellationToken cancellationToken = default)
    {
        lock (_state.SyncRoot)
        {
            if (_state.AuditLogs.ContainsKey(entry.AuditId))
            {
                throw new InvalidOperationException($"Audit log entry '{entry.AuditId}' already exists.");
            }

            _state.AuditLogs[entry.AuditId] = Clone(entry);
            return Task.CompletedTask;
        }
    }

    public Task<PagedResult<AuditLogEntry>> ListAsync(
        ListAuditLogEntriesRequest request,
        CancellationToken cancellationToken = default)
    {
        lock (_state.SyncRoot)
        {
            var query = _state.AuditLogs.Values.AsEnumerable();

            if (!string.IsNullOrWhiteSpace(request.Actor))
            {
                query = query.Where(item => string.Equals(item.Actor, request.Actor, StringComparison.Ordinal));
            }

            if (!string.IsNullOrWhiteSpace(request.Action))
            {
                query = query.Where(item => string.Equals(item.Action, request.Action, StringComparison.Ordinal));
            }

            if (!string.IsNullOrWhiteSpace(request.TargetType))
            {
                query = query.Where(item => string.Equals(item.TargetType, request.TargetType, StringComparison.Ordinal));
            }

            if (!string.IsNullOrWhiteSpace(request.TargetId))
            {
                query = query.Where(item => string.Equals(item.TargetId, request.TargetId, StringComparison.Ordinal));
            }

            if (request.FromUtc.HasValue)
            {
                query = query.Where(item => item.Timestamp >= request.FromUtc.Value);
            }

            if (request.ToUtc.HasValue)
            {
                query = query.Where(item => item.Timestamp <= request.ToUtc.Value);
            }

            var ordered = query
                .OrderByDescending(item => item.Timestamp)
                .ThenBy(item => item.AuditId)
                .Select(Clone)
                .ToList();

            return Task.FromResult(Pagination.Paginate(ordered, request.Skip, request.Take));
        }
    }

    private static AuditLogEntry Clone(AuditLogEntry entry) =>
        new()
        {
            AuditId = entry.AuditId,
            Timestamp = entry.Timestamp,
            Actor = entry.Actor,
            Action = entry.Action,
            TargetType = entry.TargetType,
            TargetId = entry.TargetId,
            Environment = entry.Environment,
            Reason = entry.Reason,
            Outcome = entry.Outcome,
            CorrelationId = entry.CorrelationId,
            MetadataJson = entry.MetadataJson,
        };
}

internal static class Pagination
{
    public static PagedResult<T> Paginate<T>(IReadOnlyList<T> items, int skip, int take)
    {
        var normalizedSkip = Math.Max(skip, 0);
        var normalizedTake = take <= 0 ? 50 : take;
        var page = items.Skip(normalizedSkip).Take(normalizedTake).ToList();

        return new PagedResult<T>
        {
            Items = page,
            Skip = normalizedSkip,
            Take = normalizedTake,
            TotalCount = items.Count,
        };
    }
}
