using System.Text.Json;
using MyCompany.AuthPlatform.Persistence.Abstractions;
using MyCompany.Shared.Contracts.Domain;

namespace MyCompany.AuthPlatform.Application;

public sealed class AuthPlatformApplicationService
{
    private const int DefaultPageSize = 100;
    private const int DefaultAuditPageSize = 200;
    private const int DefaultAdminUserPageSize = 100;
    private const int RoutineGracePeriodLimitDays = 14;
    private const int ExtendedGracePeriodLimitDays = 30;
    private const int MinimumOperatorGracePeriodDays = 7;
    private const int MinimumPasswordLength = 12;
    private const string DefaultKeyVersion = "kms-v1";
    private const string DefaultCanonicalSigningProfileId = "acmp-hmac-v1";

    private readonly IAuthPlatformUnitOfWork _unitOfWork;
    private readonly IHmacCredentialPackageProtector _packageProtector;
    private readonly IHmacSecretProtector _secretProtector;

    public AuthPlatformApplicationService(
        IAuthPlatformUnitOfWork unitOfWork,
        IHmacCredentialPackageProtector? packageProtector = null,
        IHmacSecretProtector? secretProtector = null)
    {
        _unitOfWork = unitOfWork;
        _packageProtector = packageProtector ?? new UnsupportedHmacCredentialPackageProtector();
        _secretProtector = secretProtector ?? throw new ArgumentNullException(nameof(secretProtector));
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

    public async Task<IReadOnlyList<AdminUserSummary>> ListAdminUsersAsync(
        AdminAccessContext accessContext,
        CancellationToken cancellationToken = default)
    {
        EnsureMinimumRole(accessContext, AdminAccessRole.AccessAdministrator, "admin_access_denied");

        var users = await _unitOfWork.AdminUsers.ListAsync(
            new ListAdminUsersRequest { Take = DefaultAdminUserPageSize },
            cancellationToken);

        var items = new List<AdminUserSummary>(users.Items.Count);
        foreach (var user in users.Items)
        {
            items.Add(await BuildAdminUserSummaryAsync(user, cancellationToken));
        }

        return items;
    }

    public async Task<AdminUserSummary> GetAdminUserAsync(
        Guid userId,
        AdminAccessContext accessContext,
        CancellationToken cancellationToken = default)
    {
        EnsureMinimumRole(accessContext, AdminAccessRole.AccessAdministrator, "admin_access_denied");

        var user = await _unitOfWork.AdminUsers.GetByIdAsync(userId, cancellationToken)
            ?? throw new ApplicationServiceException(404, "admin_user_not_found", "The specified administrative user could not be found.");

        return await BuildAdminUserSummaryAsync(user, cancellationToken);
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

    public async Task<AdminUserSummary> CreateAdminUserAsync(
        CreateAdminUserRequest request,
        AdminAccessContext accessContext,
        CancellationToken cancellationToken = default)
    {
        EnsureMinimumRole(accessContext, AdminAccessRole.AccessAdministrator, "admin_access_denied");

        var username = RequireText(request.Username, "username");
        var displayName = RequireText(request.DisplayName, "displayName");
        var password = ValidatePassword(request.Password);
        var roles = NormalizeAdminRoles(request.Roles);

        var existing = await _unitOfWork.AdminUsers.GetByUsernameAsync(username, cancellationToken);
        if (existing is not null)
        {
            throw new ApplicationServiceException(409, "admin_username_conflict", "An administrative user with the same username already exists.");
        }

        var passwordMaterial = AdminUserPasswordHasher.HashPassword(password);
        var now = DateTimeOffset.UtcNow;
        var user = new AdminUser
        {
            UserId = Guid.NewGuid(),
            Username = username,
            DisplayName = displayName,
            Status = AdminUserStatus.Active,
            PasswordHash = passwordMaterial.Hash,
            PasswordSalt = passwordMaterial.Salt,
            PasswordHashAlgorithm = AdminUserPasswordHasher.Algorithm,
            PasswordIterations = passwordMaterial.Iterations,
            CreatedAt = now,
            CreatedBy = accessContext.Actor,
            UpdatedAt = now,
            UpdatedBy = accessContext.Actor,
            ConcurrencyToken = Guid.NewGuid().ToString("N"),
        };

        await _unitOfWork.AdminUsers.AddAsync(user, cancellationToken);
        await ReplaceAdminUserRolesAsync(user.UserId, roles, accessContext, now, cancellationToken);
        await AppendAuditLogAsync(
            accessContext,
            "AdminUserCreated",
            "AdminUser",
            user.UserId.ToString(),
            environment: null,
            reason: "Administrative user created.",
            outcome: AuditOutcome.Succeeded,
            metadata: new
            {
                role = accessContext.Role.ToString(),
                username = user.Username,
                assignedRoles = roles,
            },
            cancellationToken);

        await _unitOfWork.SaveChangesAsync(cancellationToken);
        return await BuildAdminUserSummaryAsync(user, cancellationToken);
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
            CreateHmacDetail(credential.CredentialId, keyId, keyVersion, _secretProtector),
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
            CreateHmacDetail(replacementCredential.CredentialId, keyId, keyVersion, _secretProtector),
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

    public async Task<IssuedCredentialPackage> IssueServiceValidationPackageAsync(
        Guid credentialId,
        IssueCredentialPackageRequest request,
        AdminAccessContext accessContext,
        CancellationToken cancellationToken = default)
    {
        return await IssueCredentialPackageAsync(
            credentialId,
            request,
            CredentialPackageType.ServiceValidation,
            accessContext,
            cancellationToken);
    }

    public async Task<IssuedCredentialPackage> IssueClientSigningPackageAsync(
        Guid credentialId,
        IssueCredentialPackageRequest request,
        AdminAccessContext accessContext,
        CancellationToken cancellationToken = default)
    {
        return await IssueCredentialPackageAsync(
            credentialId,
            request,
            CredentialPackageType.ClientSigning,
            accessContext,
            cancellationToken);
    }

    public async Task<AdminUserSummary> DisableAdminUserAsync(
        Guid userId,
        DisableAdminUserRequest request,
        AdminAccessContext accessContext,
        CancellationToken cancellationToken = default)
    {
        EnsureMinimumRole(accessContext, AdminAccessRole.AccessAdministrator, "admin_access_denied");

        var user = await _unitOfWork.AdminUsers.GetByIdAsync(userId, cancellationToken)
            ?? throw new ApplicationServiceException(404, "admin_user_not_found", "The specified administrative user could not be found.");

        if (user.Status == AdminUserStatus.Disabled)
        {
            throw new ApplicationServiceException(409, "admin_user_already_disabled", "The specified administrative user is already disabled.");
        }

        var reason = NormalizeOptionalText(request.Reason) ?? "Administrative user disabled.";
        var now = DateTimeOffset.UtcNow;
        user.Status = AdminUserStatus.Disabled;
        user.UpdatedAt = now;
        user.UpdatedBy = accessContext.Actor;

        await _unitOfWork.AdminUsers.UpdateAsync(user, cancellationToken);
        await AppendAuditLogAsync(
            accessContext,
            "AdminUserDisabled",
            "AdminUser",
            user.UserId.ToString(),
            environment: null,
            reason,
            outcome: AuditOutcome.Succeeded,
            metadata: new
            {
                role = accessContext.Role.ToString(),
                username = user.Username,
            },
            cancellationToken);

        await _unitOfWork.SaveChangesAsync(cancellationToken);
        return await BuildAdminUserSummaryAsync(user, cancellationToken);
    }

    public async Task<AdminUserSummary> ResetAdminUserPasswordAsync(
        Guid userId,
        ResetAdminUserPasswordRequest request,
        AdminAccessContext accessContext,
        CancellationToken cancellationToken = default)
    {
        EnsureMinimumRole(accessContext, AdminAccessRole.AccessAdministrator, "admin_access_denied");

        var user = await _unitOfWork.AdminUsers.GetByIdAsync(userId, cancellationToken)
            ?? throw new ApplicationServiceException(404, "admin_user_not_found", "The specified administrative user could not be found.");

        var newPassword = ValidatePassword(request.NewPassword);
        var passwordMaterial = AdminUserPasswordHasher.HashPassword(newPassword);
        var reason = NormalizeOptionalText(request.Reason) ?? "Administrative user password reset.";
        var now = DateTimeOffset.UtcNow;

        user.PasswordHash = passwordMaterial.Hash;
        user.PasswordSalt = passwordMaterial.Salt;
        user.PasswordHashAlgorithm = AdminUserPasswordHasher.Algorithm;
        user.PasswordIterations = passwordMaterial.Iterations;
        user.UpdatedAt = now;
        user.UpdatedBy = accessContext.Actor;

        await _unitOfWork.AdminUsers.UpdateAsync(user, cancellationToken);
        await AppendAuditLogAsync(
            accessContext,
            "AdminUserPasswordReset",
            "AdminUser",
            user.UserId.ToString(),
            environment: null,
            reason,
            outcome: AuditOutcome.Succeeded,
            metadata: new
            {
                role = accessContext.Role.ToString(),
                username = user.Username,
            },
            cancellationToken);

        await _unitOfWork.SaveChangesAsync(cancellationToken);
        return await BuildAdminUserSummaryAsync(user, cancellationToken);
    }

    public async Task<AdminUserSummary> AssignAdminUserRolesAsync(
        Guid userId,
        AssignAdminUserRolesRequest request,
        AdminAccessContext accessContext,
        CancellationToken cancellationToken = default)
    {
        EnsureMinimumRole(accessContext, AdminAccessRole.AccessAdministrator, "admin_access_denied");

        var user = await _unitOfWork.AdminUsers.GetByIdAsync(userId, cancellationToken)
            ?? throw new ApplicationServiceException(404, "admin_user_not_found", "The specified administrative user could not be found.");

        var roles = NormalizeAdminRoles(request.Roles);
        var reason = NormalizeOptionalText(request.Reason) ?? "Administrative user roles updated.";
        var now = DateTimeOffset.UtcNow;

        user.UpdatedAt = now;
        user.UpdatedBy = accessContext.Actor;

        await _unitOfWork.AdminUsers.UpdateAsync(user, cancellationToken);
        await ReplaceAdminUserRolesAsync(user.UserId, roles, accessContext, now, cancellationToken);
        await AppendAuditLogAsync(
            accessContext,
            "AdminUserRolesUpdated",
            "AdminUser",
            user.UserId.ToString(),
            environment: null,
            reason,
            outcome: AuditOutcome.Succeeded,
            metadata: new
            {
                role = accessContext.Role.ToString(),
                username = user.Username,
                assignedRoles = roles,
            },
            cancellationToken);

        await _unitOfWork.SaveChangesAsync(cancellationToken);
        return await BuildAdminUserSummaryAsync(user, cancellationToken);
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

    private static string ValidatePassword(string? password)
    {
        var normalized = RequireText(password, "password");
        if (normalized.Length < MinimumPasswordLength)
        {
            throw new ApplicationServiceException(400, "password_policy_invalid", $"Passwords must be at least {MinimumPasswordLength} characters long.");
        }

        return normalized;
    }

    private async Task<IssuedCredentialPackage> IssueCredentialPackageAsync(
        Guid credentialId,
        IssueCredentialPackageRequest request,
        CredentialPackageType packageType,
        AdminAccessContext accessContext,
        CancellationToken cancellationToken)
    {
        EnsureMinimumRole(accessContext, AdminAccessRole.AccessOperator);

        var credential = await _unitOfWork.Credentials.GetByIdAsync(credentialId, cancellationToken)
            ?? throw new ApplicationServiceException(404, "credential_not_found", "The specified credential could not be found.");

        if (credential.AuthenticationMode != AuthenticationMode.Hmac)
        {
            throw new ApplicationServiceException(409, "unsupported_authentication_mode", "Only HMAC credential package issuance is implemented in the current release.");
        }

        if (credential.Status != CredentialStatus.Active || credential.DisabledAt.HasValue || credential.RevokedAt.HasValue)
        {
            throw new ApplicationServiceException(409, "credential_state_conflict", "Packages may only be issued for active credentials.");
        }

        if (!credential.ExpiresAt.HasValue || credential.ExpiresAt.Value <= DateTimeOffset.UtcNow)
        {
            throw new ApplicationServiceException(409, "credential_expiry_invalid", "Packages may only be issued for credentials with a future expiry.");
        }

        var hmacDetail = await _unitOfWork.HmacCredentialDetails.GetByCredentialIdAsync(credential.CredentialId, cancellationToken)
            ?? throw new ApplicationServiceException(409, "package_issuance_failed", "The HMAC credential detail could not be resolved for package issuance.");

        var scopes = await _unitOfWork.CredentialScopes.ListByCredentialIdAsync(credential.CredentialId, cancellationToken);
        var now = DateTimeOffset.UtcNow;
        var protectionBinding = BuildProtectionBinding(request);
        var packageScopes = scopes
            .Select(scope => scope.ScopeName)
            .OrderBy(scope => scope, StringComparer.Ordinal)
            .ToArray();
        var canonicalSigningProfileId = packageType == CredentialPackageType.ClientSigning
            ? DefaultCanonicalSigningProfileId
            : null;

        var definition = new HmacCredentialPackageDefinition(
            packageType,
            PackageId: $"pkg-{Guid.NewGuid():N}",
            CredentialId: credential.CredentialId,
            KeyId: hmacDetail.KeyId,
            KeyVersion: hmacDetail.KeyVersion,
            CredentialStatus: credential.Status,
            Environment: credential.Environment,
            ExpiresAt: credential.ExpiresAt.Value,
            IssuedAt: now,
            ProtectionBinding: protectionBinding,
            HmacAlgorithm: "HMACSHA256",
            Scopes: packageScopes,
            Secret: _secretProtector.Unprotect(hmacDetail),
            CanonicalSigningProfileId: canonicalSigningProfileId);

        IssuedCredentialPackage package;
        try
        {
            package = await _packageProtector.ProtectAsync(definition, cancellationToken);
        }
        catch (ApplicationServiceException)
        {
            throw;
        }
        catch (Exception)
        {
            throw new ApplicationServiceException(500, "package_issuance_failed", "The encrypted package could not be created.");
        }

        var reason = NormalizeOptionalText(request.Reason) ?? $"{package.PackageType} package issued.";
        await AppendAuditLogAsync(
            accessContext,
            packageType == CredentialPackageType.ServiceValidation
                ? "ServiceValidationPackageIssued"
                : "ClientSigningPackageIssued",
            "CredentialPackage",
            credential.CredentialId.ToString(),
            credential.Environment,
            reason,
            AuditOutcome.Succeeded,
            new
            {
                role = accessContext.Role.ToString(),
                packageType = package.PackageType,
                packageId = package.PackageId,
                keyId = package.KeyId,
                keyVersion = package.KeyVersion,
                fileName = package.FileName,
            },
            cancellationToken);

        await _unitOfWork.SaveChangesAsync(cancellationToken);
        return package;
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

    private static HmacCredentialPackageProtectionBinding BuildProtectionBinding(IssueCredentialPackageRequest request)
    {
        var bindingType = RequireText(request.BindingType, "bindingType");
        if (string.Equals(bindingType, RecipientProtectionBindingTypes.X509StoreThumbprint, StringComparison.Ordinal))
        {
            return new HmacCredentialPackageProtectionBinding(
                BindingType: RecipientProtectionBindingTypes.X509StoreThumbprint,
                CertificateThumbprint: RequireText(request.CertificateThumbprint, "certificateThumbprint"),
                StoreLocation: RequireText(request.StoreLocation, "storeLocation"),
                StoreName: RequireText(request.StoreName, "storeName"),
                CertificatePath: null,
                PrivateKeyPath: null,
                CertificatePem: null);
        }

        if (string.Equals(bindingType, RecipientProtectionBindingTypes.X509File, StringComparison.Ordinal))
        {
            var certificatePath = RequireText(request.CertificatePath, "certificatePath");
            var certificatePem = NormalizeOptionalText(request.CertificatePem);

            if (certificatePem is null && certificatePath is null)
            {
                throw new ApplicationServiceException(
                    400,
                    "package_binding_invalid",
                    "For X509File bindings, 'certificatePath' is required and 'certificatePem' may be supplied to provide the public certificate at issuance time.");
            }

            return new HmacCredentialPackageProtectionBinding(
                BindingType: RecipientProtectionBindingTypes.X509File,
                CertificateThumbprint: NormalizeOptionalText(request.CertificateThumbprint),
                StoreLocation: null,
                StoreName: null,
                CertificatePath: certificatePath,
                PrivateKeyPath: NormalizeOptionalText(request.PrivateKeyPath),
                CertificatePem: certificatePem);
        }

        throw new ApplicationServiceException(
            400,
            "package_binding_invalid",
            $"The protection binding type '{bindingType}' is not supported.");
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

    private static IReadOnlyList<string> NormalizeAdminRoles(IEnumerable<string>? roles)
    {
        var normalized = (roles ?? Array.Empty<string>())
            .Select(role => role?.Trim())
            .Where(role => !string.IsNullOrWhiteSpace(role))
            .Distinct(StringComparer.Ordinal)
            .OrderBy(role => role, StringComparer.Ordinal)
            .Cast<string>()
            .ToArray();

        if (normalized.Length == 0)
        {
            throw new ApplicationServiceException(400, "invalid_admin_role_assignment", "At least one administrative role assignment is required.");
        }

        foreach (var role in normalized)
        {
            if (!Enum.TryParse<AdminAccessRole>(role, ignoreCase: false, out _))
            {
                throw new ApplicationServiceException(400, "invalid_admin_role_assignment", $"'{role}' is not a supported administrative role.");
            }
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

    private async Task<AdminUserSummary> BuildAdminUserSummaryAsync(
        AdminUser user,
        CancellationToken cancellationToken)
    {
        var roles = await _unitOfWork.AdminUserRoles.ListByUserIdAsync(user.UserId, cancellationToken);

        return new AdminUserSummary(
            user.UserId,
            user.Username,
            user.DisplayName,
            user.Status,
            user.LastLoginAt,
            roles.Select(role => role.RoleName).OrderBy(role => role, StringComparer.Ordinal).ToArray(),
            user.CreatedAt,
            user.UpdatedAt);
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

    private async Task ReplaceAdminUserRolesAsync(
        Guid userId,
        IReadOnlyList<string> roles,
        AdminAccessContext accessContext,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        await _unitOfWork.AdminUserRoles.ReplaceForUserAsync(
            userId,
            roles.Select(role => new AdminUserRoleAssignment
            {
                UserId = userId,
                RoleName = role,
                CreatedAt = now,
                CreatedBy = accessContext.Actor,
            }).ToArray(),
            cancellationToken);
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

    private static HmacCredentialDetail CreateHmacDetail(
        Guid credentialId,
        string keyId,
        string keyVersion,
        IHmacSecretProtector secretProtector)
    {
        var plaintextSecret = secretProtector.GenerateSecret();
        var protectionResult = secretProtector.Protect(plaintextSecret, keyVersion);

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

    private sealed class UnsupportedHmacCredentialPackageProtector : IHmacCredentialPackageProtector
    {
        public Task<IssuedCredentialPackage> ProtectAsync(
            HmacCredentialPackageDefinition definition,
            CancellationToken cancellationToken = default)
        {
            throw new ApplicationServiceException(500, "package_issuance_failed", "Package protection services are not configured.");
        }
    }
}
