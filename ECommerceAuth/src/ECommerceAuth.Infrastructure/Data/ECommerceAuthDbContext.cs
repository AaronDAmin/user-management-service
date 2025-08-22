using Microsoft.EntityFrameworkCore;
using ECommerceAuth.Domain.Entities;
using System.Reflection;
using System.Linq.Expressions;

namespace ECommerceAuth.Infrastructure.Data
{
    /// <summary>
    /// Contexte de base de données principal pour l'authentification e-commerce.
    /// </summary>
    /// <remarks>
    /// Ce DbContext gère toutes les entités du système d'authentification :
    /// - Utilisateurs et leurs rôles
    /// - Tokens de rafraîchissement
    /// - Historique des connexions
    /// - Audit et sécurité
    /// 
    /// Fonctionnalités implémentées :
    /// - Soft delete automatique (IsDeleted)
    /// - Audit automatique (CreatedAt, UpdatedAt)
    /// - Configuration via Fluent API
    /// - Optimisations des requêtes avec des index
    /// </remarks>
    public class ECommerceAuthDbContext : DbContext
    {
        public ECommerceAuthDbContext(DbContextOptions<ECommerceAuthDbContext> options) : base(options)
        {
        }

        #region DbSets

        /// <summary>
        /// Utilisateurs du système.
        /// </summary>
        public DbSet<User> Users { get; set; } = null!;

        /// <summary>
        /// Rôles disponibles dans le système.
        /// </summary>
        public DbSet<Role> Roles { get; set; } = null!;

        /// <summary>
        /// Relations utilisateur-rôle (many-to-many).
        /// </summary>
        public DbSet<UserRole> UserRoles { get; set; } = null!;

        /// <summary>
        /// Tokens de rafraîchissement JWT.
        /// </summary>
        public DbSet<RefreshToken> RefreshTokens { get; set; } = null!;

        /// <summary>
        /// Historique des connexions pour audit.
        /// </summary>
        public DbSet<LoginHistory> LoginHistories { get; set; } = null!;

        #endregion

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            // Appliquer toutes les configurations d'entités automatiquement
            modelBuilder.ApplyConfigurationsFromAssembly(Assembly.GetExecutingAssembly());

            // Configuration globale pour le soft delete
            ConfigureSoftDelete(modelBuilder);

            // Configuration des index pour optimiser les performances
            ConfigureIndexes(modelBuilder);

            // Données de seed pour les rôles par défaut
            SeedDefaultRoles(modelBuilder);
        }

        /// <summary>
        /// Configure le soft delete pour toutes les entités héritant de BaseEntity.
        /// </summary>
        private static void ConfigureSoftDelete(ModelBuilder modelBuilder)
        {
            // Filtre global pour exclure les entités supprimées (soft delete)
            foreach (var entityType in modelBuilder.Model.GetEntityTypes())
            {
                if (typeof(BaseEntity).IsAssignableFrom(entityType.ClrType))
                {
                    var parameter = Expression.Parameter(entityType.ClrType, "e");
                    var property = Expression.Property(parameter, nameof(BaseEntity.IsDeleted));
                    var filter = Expression.Lambda(Expression.Equal(property, Expression.Constant(false)), parameter);
                    
                    modelBuilder.Entity(entityType.ClrType).HasQueryFilter(filter);
                }
            }
        }

        /// <summary>
        /// Configure les index pour optimiser les performances des requêtes.
        /// </summary>
        private static void ConfigureIndexes(ModelBuilder modelBuilder)
        {
            // Index sur les colonnes fréquemment utilisées pour les recherches
            modelBuilder.Entity<User>()
                .HasIndex(u => u.Email)
                .IsUnique()
                .HasDatabaseName("IX_Users_Email");

            modelBuilder.Entity<User>()
                .HasIndex(u => u.UserName)
                .IsUnique()
                .HasDatabaseName("IX_Users_UserName");

            modelBuilder.Entity<User>()
                .HasIndex(u => new { u.Email, u.IsDeleted })
                .HasDatabaseName("IX_Users_Email_IsDeleted");

            modelBuilder.Entity<RefreshToken>()
                .HasIndex(rt => rt.Token)
                .IsUnique()
                .HasDatabaseName("IX_RefreshTokens_Token");

            modelBuilder.Entity<RefreshToken>()
                .HasIndex(rt => new { rt.UserId, rt.IsRevoked, rt.ExpiresAt })
                .HasDatabaseName("IX_RefreshTokens_UserId_IsRevoked_ExpiresAt");

            modelBuilder.Entity<LoginHistory>()
                .HasIndex(lh => new { lh.UserId, lh.CreatedAt })
                .HasDatabaseName("IX_LoginHistories_UserId_CreatedAt");

            modelBuilder.Entity<LoginHistory>()
                .HasIndex(lh => lh.IpAddress)
                .HasDatabaseName("IX_LoginHistories_IpAddress");

            modelBuilder.Entity<UserRole>()
                .HasIndex(ur => new { ur.UserId, ur.RoleId })
                .IsUnique()
                .HasDatabaseName("IX_UserRoles_UserId_RoleId");
        }

        /// <summary>
        /// Ajoute les rôles par défaut lors de la création de la base.
        /// </summary>
        private static void SeedDefaultRoles(ModelBuilder modelBuilder)
        {
            var buyerRoleId = Guid.Parse("11111111-1111-1111-1111-111111111111");
            var sellerRoleId = Guid.Parse("22222222-2222-2222-2222-222222222222");
            var adminRoleId = Guid.Parse("33333333-3333-3333-3333-333333333333");

            modelBuilder.Entity<Role>().HasData(
                new Role
                {
                    Id = buyerRoleId,
                    Name = "Buyer",
                    Description = "Utilisateur standard qui peut acheter des produits",
                    CreatedAt = DateTime.UtcNow,
                    IsDeleted = false
                },
                new Role
                {
                    Id = sellerRoleId,
                    Name = "Seller",
                    Description = "Utilisateur qui peut vendre des produits (hérite des droits Buyer)",
                    CreatedAt = DateTime.UtcNow,
                    IsDeleted = false
                },
                new Role
                {
                    Id = adminRoleId,
                    Name = "Admin",
                    Description = "Administrateur avec tous les droits de gestion",
                    CreatedAt = DateTime.UtcNow,
                    IsDeleted = false
                }
            );
        }

        /// <summary>
        /// Override SaveChanges pour gérer automatiquement l'audit.
        /// </summary>
        public override int SaveChanges()
        {
            UpdateAuditFields();
            return base.SaveChanges();
        }

        /// <summary>
        /// Override SaveChangesAsync pour gérer automatiquement l'audit.
        /// </summary>
        public override async Task<int> SaveChangesAsync(CancellationToken cancellationToken = default)
        {
            UpdateAuditFields();
            return await base.SaveChangesAsync(cancellationToken);
        }

        /// <summary>
        /// Met à jour automatiquement les champs d'audit lors des modifications.
        /// </summary>
        private void UpdateAuditFields()
        {
            var entries = ChangeTracker.Entries<BaseEntity>()
                .Where(e => e.State == EntityState.Modified);

            foreach (var entry in entries)
            {
                entry.Entity.UpdatedAt = DateTime.UtcNow;
            }
        }
    }
}