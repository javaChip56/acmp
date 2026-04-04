using System.Text.Json;
using MyCompany.AuthPlatform.Persistence.Abstractions;
using MyCompany.Shared.Contracts.Domain;

namespace MyCompany.AuthPlatform.Application;

public sealed class AuthPlatformApplicationService
{
    private const int DefaultPageSize = 100;
    private const int DefaultAuditPageSize = 200;
    private const int RoutineGracePeriodLimitDays = 14;
    private const int ExtendedGracePeriodLimitDays = 30;
    private const int MinimumOperatorGracePeriodDays = 7;
    private const string DefaultKeyVersion = "kms-v1";

    private readonly IAuthPlatformUnitOfWork _unitOfWork;

    public AuthPlatformApplicationService(IAuthPlatformUnitOfWork unitOfWork)
    {
        _unitOfWork = unitOfWork;
    }

    public async Task<IReadOnlyList<ServiceClientSummary>> ListClientsAsync(
        AdminAccessContext accessContext,
        CancellationToken cancellationToken = default)
    {
        EnsureMinimumRole(accessContext, AdminAccessRole.AccessViewer);

        var clients = await _unitOfWork.ServiceClients.ListAsync(
            new ListServiceClientsRequest { Take = DefaultPageSize },
            cancellationToken);

        return clients.Items.Select(MapServiceClient).ToArray();
    }

    public async Task<ServiceClientSummary> GetClientAsync(
        Guid clientId,
        AdminAccessContext accessContext,
        CancellationToken cancellationToken = default)
    {
        EnsureMinimumRole(accessContext, AdminAccessRole.AccessViewer);

        var client = await _unitOfWork.ServiceClients.GetByIdAsync(clientId, cancellationToken)
            ?? throw new ApplicationServiceException(404, "client_not_found", "The specified client could not be found.");

        return MapServiceClient(client);
    }

    public async Task<ClientCredentialList> ListClientCredentialsAsync(
        Guid clientId,
        AdminAccessContext accessContext,
        CancellationToken cancellationToken = default)
    {
        EnsureMinimumRole(accessContext, AdminAccessRole.AccessViewer);

        var client = await _unitOfWork.ServiceClients.GetByIdAsync(clientId, cancellationToken)
            ?? throw new ApplicationServiceException(404, "client_not_found", "The specified client could not be found.");

        var credentials = await _unitOfWork.Credentials.ListAsync(
            new ListCredentialsRequest { ClientId = clientId, Take = DefaultPageSize },
            cancellationToken);

        var items = new List<CredentialSummary>(credentials.Items.Count);
        foreach (var credential in credentials.Items)
        {
            items.Add(await BuildCredentialSummaryAsync(credential, cancellationToken));
        }

        return new ClientCredentialList(
            client.ClientId,
            client.ClientCode,
            client.ClientName,
            items);
    }

    public async Task<CredentialSummary> GetCredentialAsync(
        Guid credentialId,
        AdminAccessContext accessContext,
        CancellationToken cancellationToken = default)
    {
        EnsureMinimumRole(accessContext, AdminAccessRole.AccessViewer);

        var credential = await _unitOfWork.Credentials.GetByIdAsync(credentialId, cancellationToken)
            ?? throw new ApplicationServiceException(404, "credential_not_found", "The specified credential could not be found.");

        return await BuildCredentialSummaryAsync(credential, cancellationToken);
    }

    public async Task<IReadOnlyList<AuditLogSummary>> ListAuditLogAsync(
        AdminAccessContext accessContext,
        CancellationToken cancellationToken = default)
    {
        EnsureMinimumRole(accessContext, AdminAccessRole.AccessAdministrator, "audit_access_denied");

        var auditEntries = await _unitOfWork.AuditLogs.ListAsync(
            new ListAuditLogEntriesRequest { Take = DefaultAuditPageSize },
            cancellationToken);

        return auditEntries.Items
            .Select(entry => new AuditLogSummary(
                entry.AuditId,
                entry.Timestamp,
                entry.Actor,
                entry.Action,
                entry.TargetType,
                entry.TargetId,
                entry.Environment,
                entry.Reason,
                entry.Outcome,
                entry.CorrelationId,
                entry.MetadataJson))
            .ToArray();
    }

    public async Task<ServiceClientSummary> CreateServiceClientAsync(
        CreateServiceClientRequest request,
        AdminAccessContext accessContext,
        CancellationToken cancellationToken = default)
    {
        EnsureMinimumRole(accessContext, AdminAccessRole.AccessOperator);

        var clientCode = RequireText(request.ClientCode, "clientCode");
        var clientName = RequireText(request.ClientName, "clientName");
        var owner = RequireText(request.Owner, "owner");

        var existing = await _unitOfWork.ServiceClients.GetByCodeAsync(request.Environment, clientCode, cancellationToken);
        if (existing is not null)
        {
            throw new ApplicationServiceException(409, "client_code_conflict", "A client with the same code already exists in the target environment.");
        }

        var now = DateTimeOffset.UtcNow;
        var client = new ServiceClient
        {
            ClientId = Guid.NewGuid(),
            ClientCode = clientCode,
            ClientName = clientName,
            Owner = owner,
            Environment = request.Environment,
            Status = ServiceClientStatus.Active,
            Description = NormalizeOptionalText(request.Description),
            MetadataJson = NormalizeOptionalText(request.MetadataJson),
            CreatedAt = now,
            CreatedBy = accessContext.Actor,
            UpdatedAt = now,
            UpdatedBy = accessContext.Actor,
            ConcurrencyToken = Guid.NewGuid().ToString("N"),
        };

        await _unitOfWork.ServiceClients.AddAsync(client, cancellationToken);
        await AppendAuditLogAsync(
            accessContext,
            "ClientCreated",
            "ServiceClient",
            client.ClientId.ToString(),
            client.Environment,
            "Demo client created through the API host.",
            AuditOutcome.Succeeded,
            new
            {
                role = accessContext.Role.ToString(),
                clientCode = client.ClientCode,
            },
            cancellationToken);

        await _unitOfWork.SaveChangesAsync(cancellationToken);
        return MapServiceClient(client);
    }

    public async Task<CredentialSummary> IssueHmacCredentialAsync(
        Guid clientId,
        IssueHmacCredentialRequest request,
        AdminAccessContext accessContext,
        CancellationToken cancellationToken = default)
    {
        EnsureMinimumRole(accessContext, AdminAccessRole.AccessOperator);

        var client = await _unitOfWork.ServiceClients.GetByIdAsync(clientId, cancellationToken)
            ?? throw new ApplicationServiceException(404, "client_not_found", "The specified client could not be found.");

        if (client.Status != ServiceClientStatus.Active)
        {
            throw new ApplicationServiceException(409, "client_inactive", "Credentials can only be issued to active clients.");
        }

        var expiresAt = ValidateFutureTimestamp(request.ExpiresAt, "expiresAt");
        var scopes = NormalizeScopes(request.Scopes, required: true);
        var keyId = await ResolveUniqueKeyIdAsync(request.KeyId, client, cancellationToken);
        var keyVersion = NormalizeOptionalText(request.KeyVersion) ?? DefaultKeyVersion;

        var now = DateTimeOffset.UtcNow;
        var credential = new Credential
        {
            CredentialId = Guid.NewGuid(),
            ClientId = client.ClientId,
            AuthenticationMode = AuthenticationMode.Hmac,
            Status = CredentialStatus.Active,
            Environment = client.Environment,
            ExpiresAt = expiresAt,
            Notes = NormalizeOptionalText(request.Notes),
            CreatedAt = now,
            CreatedBy = accessContext.Actor,
            UpdatedAt = now,
            UpdatedBy = accessContext.Actor,
            ConcurrencyToken = Guid.NewGuid().ToString("N"),
        };

        await _unitOfWork.Credentials.AddAsync(credential, cancellationToken);
        await _unitOfWork.CredentialScopes.ReplaceForCredentialAsync(
            credential.CredentialId,
            scopes.Select(scope => new CredentialScope
            {
                CredentialId = credential.CredentialId,
                ScopeName = scope,
                CreatedAt = now,
                CreatedBy = accessContext.Actor,
            }).ToArray(),
            cancellationToken);
        await _unitOfWork.HmacCredentialDetails.AddAsync(
            CreateHmacDetail(credential.CredentialId, keyId, keyVersion),
            cancellationToken);
        await AppendAuditLogAsync(
            accessContext,
            "CredentialIssued",
            "Credential",
            credential.CredentialId.ToString(),
            client.Environment,
            credential.Notes ?? "HMAC credential issued.",
            AuditOutcome.Succeeded,
            new
            {
                role = accessContext.Role.ToString(),
                keyId,
                scopeCount = scopes.Count,
            },
            cancellationToken);

        await _unitOfWork.SaveChangesAsync(cancellationToken);
        return await BuildCredentialSummaryAsync(credential, cancellationToken);
    }

    public async Task<CredentialSummary> RotateHmacCredentialAsync(
        Guid credentialId,
        RotateHmacCredentialRequest request,
        AdminAccessContext accessContext,
        CancellationToken cancellationToken = default)
    {
        EnsureMinimumRole(accessContext, AdminAccessRole.AccessOperator);

        var currentCredential = await _unitOfWork.Credentials.GetByIdAsync(credentialId, cancellationToken)
            ?? throw new ApplicationServiceException(404, "credential_not_found", "The specified credential could not be found.");

        if (currentCredential.AuthenticationMode != AuthenticationMode.Hmac)
        {
            throw new ApplicationServiceException(409, "unsupported_authentication_mode", "Only HMAC credential rotation is implemented in the demo host.");
        }

        if (currentCredential.Status != CredentialStatus.Active)
        {
            throw new ApplicationServiceException(409, "credential_not_active", "Only active credentials can be rotated.");
        }

        if (currentCredential.DisabledAt.HasValue)
        {
            throw new ApplicationServiceException(409, "credential_disabled", "Disabled credentials cannot be rotated.");
        }

        if (currentCredential.RevokedAt.HasValue)
        {
            throw new ApplicationServiceException(409, "credential_revoked", "Revoked credentials cannot be rotated.");
        }

        var client = await _unitOfWork.ServiceClients.GetByIdAsync(currentCredential.ClientId, cancellationToken)
            ?? throw new ApplicationServiceException(409, "client_not_found", "The client associated with the credential could not be found.");

        var expiresAt = ValidateFutureTimestamp(request.ExpiresAt, "expiresAt");
        var existingScopes = await _unitOfWork.CredentialScopes.ListByCredentialIdAsync(currentCredential.CredentialId, cancellationToken);
        var scopes = request.Scopes is null
            ? NormalizeScopes(existingScopes.Select(scope => scope.ScopeName).ToArray(), required: true)
            : NormalizeScopes(request.Scopes, required: true);

        var gracePeriodEndsAt = ValidateGracePeriod(request.GracePeriodEndsAt, accessContext);
        var keyId = await ResolveUniqueKeyIdAsync(request.NewKeyId, client, cancellationToken);
        var keyVersion = NormalizeOptionalText(request.NewKeyVersion) ?? DefaultKeyVersion;
        var reason = NormalizeOptionalText(request.Reason) ??
            (gracePeriodEndsAt.HasValue
                ? "Credential rotated with overlap during package transition."
                : "Credential rotated with immediate cutover.");

        var now = DateTimeOffset.UtcNow;
        var replacementCredential = new Credential
        {
            CredentialId = Guid.NewGuid(),
            ClientId = currentCredential.ClientId,
            AuthenticationMode = currentCredential.AuthenticationMode,
            Status = CredentialStatus.Active,
            Environment = currentCredential.Environment,
            ExpiresAt = expiresAt,
            Notes = NormalizeOptionalText(request.Notes),
            CreatedAt = now,
            CreatedBy = accessContext.Actor,
            UpdatedAt = now,
            UpdatedBy = accessContext.Actor,
            ConcurrencyToken = Guid.NewGuid().ToString("N"),
        };

        currentCredential.ReplacedByCredentialId = replacementCredential.CredentialId;
        currentCredential.RotationGraceEndsAt = gracePeriodEndsAt;
        currentCredential.UpdatedAt = now;
        currentCredential.UpdatedBy = accessContext.Actor;

        if (gracePeriodEndsAt.HasValue)
        {
            currentCredential.Status = CredentialStatus.Active;
            currentCredential.RevokedAt = null;
        }
        else
        {
            currentCredential.Status = CredentialStatus.Revoked;
            currentCredential.RevokedAt = now;
        }

        await _unitOfWork.Credentials.UpdateAsync(currentCredential, cancellationToken);
        await _unitOfWork.Credentials.AddAsync(replacementCredential, cancellationToken);
        await _unitOfWork.CredentialScopes.ReplaceForCredentialAsync(
            replacementCredential.CredentialId,
            scopes.Select(scope => new CredentialScope
            {
                CredentialId = replacementCredential.CredentialId,
                ScopeName = scope,
                CreatedAt = now,
                CreatedBy = accessContext.Actor,
            }).ToArray(),
            cancellationToken);
        await _unitOfWork.HmacCredentialDetails.AddAsync(
            CreateHmacDetail(replacementCredential.CredentialId, keyId, keyVersion),
            cancellationToken);
        await AppendAuditLogAsync(
            accessContext,
            "CredentialRotated",
            "Credential",
            currentCredential.CredentialId.ToString(),
            currentCredential.Environment,
            reason,
            AuditOutcome.Succeeded,
            new
            {
                role = accessContext.Role.ToString(),
                replacementCredentialId = replacementCredential.CredentialId,
                keyId,
                gracePeriodEndsAt,
            },
            cancellationToken);

        await _unitOfWork.SaveChangesAsync(cancellationToken);
        return await BuildCredentialSummaryAsync(replacementCredential, cancellationToken);
    }

    public async Task<CredentialSummary> RevokeCredentialAsync(
        Guid credentialId,
        RevokeCredentialRequest request,
        AdminAccessContext accessContext,
        CancellationToken cancellationToken = default)
    {
        EnsureMinimumRole(accessContext, AdminAccessRole.AccessOperator);

        var credential = await _unitOfWork.Credentials.GetByIdAsync(credentialId, cancellationToken)
            ?? throw new ApplicationServiceException(404, "credential_not_found", "The specified credential could not be found.");

        if (credential.Status == CredentialStatus.Revoked)
        {
            throw new ApplicationServiceException(409, "credential_already_revoked", "The specified credential has already been revoked.");
        }

        var reason = RequireText(request.Reason, "reason");
        var now = DateTimeOffset.UtcNow;
        credential.Status = CredentialStatus.Revoked;
        credential.RevokedAt = now;
        credential.RotationGraceEndsAt = null;
        credential.UpdatedAt = now;
        credential.UpdatedBy = accessContext.Actor;

        await _unitOfWork.Credentials.UpdateAsync(credential, cancellationToken);
        await AppendAuditLogAsync(
            accessContext,
            "CredentialRevoked",
            "Credential",
            credential.CredentialId.ToString(),
            credential.Environment,
            reason,
            AuditOutcome.Succeeded,
            new
            {
                role = accessContext.Role.ToString(),
            },
            cancellationToken);

        await _unitOfWork.SaveChangesAsync(cancellationToken);
        return await BuildCredentialSummaryAsync(credential, cancellationToken);
    }

    private static void EnsureMinimumRole(
        AdminAccessContext accessContext,
        AdminAccessRole requiredRole,
        string errorCode = "forbidden")
    {
        if (accessContext.Role < requiredRole)
        {
            throw new ApplicationServiceException(403, errorCode, "The current role is not permitted to perform this action.");
        }
    }

    private async Task<string> ResolveUniqueKeyIdAsync(
        string? requestedKeyId,
        ServiceClient client,
        CancellationToken cancellationToken)
    {
        var candidate = NormalizeOptionalText(requestedKeyId) ?? GenerateKeyId(client);
        var existing = await _unitOfWork.HmacCredentialDetails.GetByKeyIdAsync(candidate, cancellationToken);
        if (existing is not null)
        {
            throw new ApplicationServiceException(409, "key_id_conflict", "The supplied key identifier is already in use.");
        }

        return candidate;
    }

    private static DateTimeOffset ValidateFutureTimestamp(DateTimeOffset timestamp, string fieldName)
    {
        if (timestamp <= DateTimeOffset.UtcNow)
        {
            throw new ApplicationServiceException(400, "validation_error", $"'{fieldName}' must be a future timestamp.");
        }

        return timestamp;
    }

    private static DateTimeOffset? ValidateGracePeriod(DateTimeOffset? gracePeriodEndsAt, AdminAccessContext accessContext)
    {
        if (!gracePeriodEndsAt.HasValue)
        {
            return null;
        }

        var now = DateTimeOffset.UtcNow;
        if (gracePeriodEndsAt.Value <= now)
        {
            throw new ApplicationServiceException(400, "rotation_grace_period_invalid", "'gracePeriodEndsAt' must be later than the current time.");
        }

        var duration = gracePeriodEndsAt.Value - now;
        if (duration > TimeSpan.FromDays(ExtendedGracePeriodLimitDays))
        {
            throw new ApplicationServiceException(400, "rotation_grace_period_invalid", $"Grace periods may not exceed {ExtendedGracePeriodLimitDays} days.");
        }

        if (duration > TimeSpan.FromDays(RoutineGracePeriodLimitDays) && accessContext.Role != AdminAccessRole.AccessAdministrator)
        {
            throw new ApplicationServiceException(403, "extended_grace_period_denied", "Only AccessAdministrator may approve grace periods longer than 14 days.");
        }

        if (accessContext.Role == AdminAccessRole.AccessOperator && duration < TimeSpan.FromDays(MinimumOperatorGracePeriodDays))
        {
            throw new ApplicationServiceException(403, "rotation_grace_period_invalid", "AccessOperator may only request grace periods from 7 to 14 days. Omit the field for immediate cutover.");
        }

        return gracePeriodEndsAt;
    }

    private static string RequireText(string? value, string fieldName)
    {
        var normalized = NormalizeOptionalText(value);
        if (normalized is null)
        {
            throw new ApplicationServiceException(400, "validation_error", $"'{fieldName}' is required.");
        }

        return normalized;
    }

    private static string? NormalizeOptionalText(string? value)
    {
        return string.IsNullOrWhiteSpace(value) ? null : value.Trim();
    }

    private static IReadOnlyList<string> NormalizeScopes(IEnumerable<string>? scopes, bool required)
    {
        var normalized = (scopes ?? Array.Empty<string>())
            .Select(scope => scope?.Trim())
            .Where(scope => !string.IsNullOrWhiteSpace(scope))
            .Distinct(StringComparer.Ordinal)
            .OrderBy(scope => scope, StringComparer.Ordinal)
            .Cast<string>()
            .ToArray();

        if (required && normalized.Length == 0)
        {
            throw new ApplicationServiceException(400, "validation_error", "At least one scope is required.");
        }

        return normalized;
    }

    private async Task<CredentialSummary> BuildCredentialSummaryAsync(
        Credential credential,
        CancellationToken cancellationToken)
    {
        var scopes = await _unitOfWork.CredentialScopes.ListByCredentialIdAsync(credential.CredentialId, cancellationToken);
        var hmacDetail = await _unitOfWork.HmacCredentialDetails.GetByCredentialIdAsync(credential.CredentialId, cancellationToken);

        return new CredentialSummary(
            credential.CredentialId,
            credential.ClientId,
            credential.AuthenticationMode,
            credential.Status,
            credential.Environment,
            credential.ExpiresAt,
            credential.DisabledAt,
            credential.RevokedAt,
            credential.ReplacedByCredentialId,
            credential.RotationGraceEndsAt,
            credential.Notes,
            hmacDetail?.KeyId,
            hmacDetail?.KeyVersion,
            scopes.Select(scope => scope.ScopeName).OrderBy(scope => scope, StringComparer.Ordinal).ToArray(),
            credential.CreatedAt,
            credential.UpdatedAt);
    }

    private static ServiceClientSummary MapServiceClient(ServiceClient client)
    {
        return new ServiceClientSummary(
            client.ClientId,
            client.ClientCode,
            client.ClientName,
            client.Owner,
            client.Environment,
            client.Status,
            client.Description,
            client.CreatedAt,
            client.UpdatedAt);
    }

    private async Task AppendAuditLogAsync(
        AdminAccessContext accessContext,
        string action,
        string targetType,
        string? targetId,
        DeploymentEnvironment? environment,
        string reason,
        AuditOutcome outcome,
        object metadata,
        CancellationToken cancellationToken)
    {
        await _unitOfWork.AuditLogs.AddAsync(
            new AuditLogEntry
            {
                AuditId = Guid.NewGuid(),
                Timestamp = DateTimeOffset.UtcNow,
                Actor = accessContext.Actor,
                Action = action,
                TargetType = targetType,
                TargetId = targetId,
                Environment = environment,
                Reason = reason,
                Outcome = outcome,
                CorrelationId = accessContext.CorrelationId,
                MetadataJson = JsonSerializer.Serialize(metadata),
            },
            cancellationToken);
    }

    private static string GenerateKeyId(ServiceClient client)
    {
        var environment = client.Environment.ToString().ToLowerInvariant();
        var code = client.ClientCode.ToLowerInvariant();
        var suffix = Guid.NewGuid().ToString("N")[..12];
        return $"key-{environment}-{code}-{suffix}";
    }

    private static HmacCredentialDetail CreateHmacDetail(Guid credentialId, string keyId, string keyVersion)
    {
        var bytes = credentialId.ToByteArray();
        var reversed = bytes.Reverse().ToArray();

        return new HmacCredentialDetail
        {
            CredentialId = credentialId,
            KeyId = keyId,
            KeyVersion = keyVersion,
            HmacAlgorithm = HmacAlgorithm.HmacSha256,
            EncryptionAlgorithm = "A256GCM",
            EncryptedSecret = bytes.Concat(bytes).ToArray(),
            EncryptedDataKey = reversed.Concat(reversed).ToArray(),
            Iv = bytes.Take(12).ToArray(),
            Tag = bytes.Skip(4).Take(12).ToArray(),
        };
    }
}
