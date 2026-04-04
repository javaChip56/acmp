using Microsoft.EntityFrameworkCore;
using MyCompany.Shared.Contracts.Domain;

namespace MyCompany.AuthPlatform.Persistence.Postgres;

public sealed class AuthPlatformPostgresDbContext : DbContext
{
    public AuthPlatformPostgresDbContext(DbContextOptions<AuthPlatformPostgresDbContext> options)
        : base(options)
    {
    }

    public DbSet<ServiceClient> ServiceClients => Set<ServiceClient>();
    public DbSet<Credential> Credentials => Set<Credential>();
    public DbSet<CredentialScope> CredentialScopes => Set<CredentialScope>();
    public DbSet<HmacCredentialDetail> HmacCredentialDetails => Set<HmacCredentialDetail>();
    public DbSet<AuditLogEntry> AuditLogs => Set<AuditLogEntry>();
    public DbSet<AdminUser> AdminUsers => Set<AdminUser>();
    public DbSet<AdminUserRoleAssignment> AdminUserRoles => Set<AdminUserRoleAssignment>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.Entity<ServiceClient>(entity =>
        {
            entity.ToTable("ServiceClient");
            entity.HasKey(item => item.ClientId);
            entity.Property(item => item.ClientCode).HasMaxLength(200).IsRequired();
            entity.Property(item => item.ClientName).HasMaxLength(200).IsRequired();
            entity.Property(item => item.Owner).HasMaxLength(200).IsRequired();
            entity.Property(item => item.Environment).HasConversion<string>().HasMaxLength(16).IsRequired();
            entity.Property(item => item.Status).HasConversion<string>().HasMaxLength(32).IsRequired();
            entity.Property(item => item.Description).HasMaxLength(2000);
            entity.Property(item => item.MetadataJson).HasColumnType("jsonb");
            entity.Property(item => item.CreatedBy).HasMaxLength(200).IsRequired();
            entity.Property(item => item.UpdatedBy).HasMaxLength(200).IsRequired();
            entity.Property(item => item.ConcurrencyToken).HasMaxLength(64);
            entity.HasIndex(item => new { item.Environment, item.ClientCode }).IsUnique();
            entity.HasIndex(item => new { item.Environment, item.Status });
        });

        modelBuilder.Entity<Credential>(entity =>
        {
            entity.ToTable("Credential");
            entity.HasKey(item => item.CredentialId);
            entity.Property(item => item.AuthenticationMode).HasConversion<string>().HasMaxLength(64).IsRequired();
            entity.Property(item => item.Status).HasConversion<string>().HasMaxLength(32).IsRequired();
            entity.Property(item => item.Environment).HasConversion<string>().HasMaxLength(16).IsRequired();
            entity.Property(item => item.Notes).HasMaxLength(2000);
            entity.Property(item => item.CreatedBy).HasMaxLength(200).IsRequired();
            entity.Property(item => item.UpdatedBy).HasMaxLength(200).IsRequired();
            entity.Property(item => item.ConcurrencyToken).HasMaxLength(64);
            entity.HasOne<ServiceClient>()
                .WithMany()
                .HasForeignKey(item => item.ClientId)
                .OnDelete(DeleteBehavior.Restrict);
            entity.HasIndex(item => new { item.ClientId, item.Status });
            entity.HasIndex(item => new { item.Environment, item.AuthenticationMode, item.Status });
        });

        modelBuilder.Entity<CredentialScope>(entity =>
        {
            entity.ToTable("CredentialScope");
            entity.HasKey(item => new { item.CredentialId, item.ScopeName });
            entity.Property(item => item.ScopeName).HasMaxLength(200).IsRequired();
            entity.Property(item => item.CreatedBy).HasMaxLength(200).IsRequired();
            entity.HasOne<Credential>()
                .WithMany()
                .HasForeignKey(item => item.CredentialId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<HmacCredentialDetail>(entity =>
        {
            entity.ToTable("HmacCredentialDetail");
            entity.HasKey(item => item.CredentialId);
            entity.Property(item => item.KeyId).HasMaxLength(200).IsRequired();
            entity.Property(item => item.KeyVersion).HasMaxLength(64).IsRequired();
            entity.Property(item => item.HmacAlgorithm).HasConversion<string>().HasMaxLength(64).IsRequired();
            entity.Property(item => item.EncryptionAlgorithm).HasMaxLength(64).IsRequired();
            entity.Property(item => item.EncryptedSecret).HasColumnType("bytea").IsRequired();
            entity.Property(item => item.EncryptedDataKey).HasColumnType("bytea").IsRequired();
            entity.Property(item => item.Iv).HasColumnType("bytea");
            entity.Property(item => item.Tag).HasColumnType("bytea");
            entity.HasOne<Credential>()
                .WithOne()
                .HasForeignKey<HmacCredentialDetail>(item => item.CredentialId)
                .OnDelete(DeleteBehavior.Cascade);
            entity.HasIndex(item => item.KeyId).IsUnique();
            entity.HasIndex(item => item.KeyVersion);
        });

        modelBuilder.Entity<AuditLogEntry>(entity =>
        {
            entity.ToTable("AuditLog");
            entity.HasKey(item => item.AuditId);
            entity.Property(item => item.Actor).HasMaxLength(200).IsRequired();
            entity.Property(item => item.Action).HasMaxLength(100).IsRequired();
            entity.Property(item => item.TargetType).HasMaxLength(100).IsRequired();
            entity.Property(item => item.TargetId).HasMaxLength(200);
            entity.Property(item => item.Environment).HasConversion<string>().HasMaxLength(16);
            entity.Property(item => item.Reason).HasMaxLength(2000);
            entity.Property(item => item.Outcome).HasConversion<string>().HasMaxLength(32);
            entity.Property(item => item.CorrelationId).HasMaxLength(200);
            entity.Property(item => item.MetadataJson).HasColumnType("jsonb");
            entity.HasIndex(item => item.Timestamp);
            entity.HasIndex(item => new { item.TargetType, item.TargetId });
            entity.HasIndex(item => new { item.Actor, item.Timestamp });
            entity.HasIndex(item => new { item.Action, item.Timestamp });
        });

        modelBuilder.Entity<AdminUser>(entity =>
        {
            entity.ToTable("AdminUser");
            entity.HasKey(item => item.UserId);
            entity.Property(item => item.Username).HasMaxLength(200).IsRequired();
            entity.Property(item => item.DisplayName).HasMaxLength(200).IsRequired();
            entity.Property(item => item.Status).HasConversion<string>().HasMaxLength(32).IsRequired();
            entity.Property(item => item.PasswordHash).HasColumnType("bytea").IsRequired();
            entity.Property(item => item.PasswordSalt).HasColumnType("bytea").IsRequired();
            entity.Property(item => item.PasswordHashAlgorithm).HasMaxLength(64).IsRequired();
            entity.Property(item => item.CreatedBy).HasMaxLength(200).IsRequired();
            entity.Property(item => item.UpdatedBy).HasMaxLength(200).IsRequired();
            entity.Property(item => item.ConcurrencyToken).HasMaxLength(64);
            entity.HasIndex(item => item.Username).IsUnique();
            entity.HasIndex(item => new { item.Status, item.Username });
        });

        modelBuilder.Entity<AdminUserRoleAssignment>(entity =>
        {
            entity.ToTable("AdminUserRoleAssignment");
            entity.HasKey(item => new { item.UserId, item.RoleName });
            entity.Property(item => item.RoleName).HasMaxLength(64).IsRequired();
            entity.Property(item => item.CreatedBy).HasMaxLength(200).IsRequired();
            entity.HasOne<AdminUser>()
                .WithMany()
                .HasForeignKey(item => item.UserId)
                .OnDelete(DeleteBehavior.Cascade);
            entity.HasIndex(item => item.RoleName);
        });
    }
}
