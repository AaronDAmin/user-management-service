using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using ECommerceAuth.Domain.Entities;

namespace ECommerceAuth.Infrastructure.Data.Configurations
{
    /// <summary>
    /// Configuration Entity Framework pour l'entité User.
    /// </summary>
    /// <remarks>
    /// Cette configuration définit :
    /// - Les contraintes de colonnes (longueurs, types, nullabilité)
    /// - Les relations avec les autres entités
    /// - Les index pour optimiser les performances
    /// - Les validations au niveau base de données
    /// 
    /// Bonnes pratiques appliquées :
    /// - Longueurs de champs appropriées pour éviter le gaspillage
    /// - Contraintes NOT NULL pour les champs obligatoires
    /// - Index sur les colonnes de recherche fréquente
    /// - Relations correctement configurées
    /// </remarks>
    public class UserConfiguration : IEntityTypeConfiguration<User>
    {
        public void Configure(EntityTypeBuilder<User> builder)
        {
            // Configuration de la table
            builder.ToTable("Users");
            
            // Configuration de la clé primaire
            builder.HasKey(u => u.Id);
            builder.Property(u => u.Id)
                .ValueGeneratedNever(); // Guid généré dans l'entité

            // Configuration des propriétés string avec contraintes
            builder.Property(u => u.UserName)
                .IsRequired()
                .HasMaxLength(50)
                .HasComment("Nom d'utilisateur unique pour l'affichage public");

            builder.Property(u => u.Email)
                .IsRequired()
                .HasMaxLength(255)
                .HasComment("Adresse email unique utilisée comme identifiant de connexion");

            builder.Property(u => u.PasswordHash)
                .IsRequired()
                .HasMaxLength(255)
                .HasComment("Hash sécurisé du mot de passe (BCrypt/Argon2)");

            builder.Property(u => u.FirstName)
                .HasMaxLength(50)
                .HasComment("Prénom de l'utilisateur");

            builder.Property(u => u.LastName)
                .HasMaxLength(50)
                .HasComment("Nom de famille de l'utilisateur");

            builder.Property(u => u.PhoneNumber)
                .HasMaxLength(20)
                .HasComment("Numéro de téléphone au format international");

            builder.Property(u => u.Bio)
                .HasMaxLength(1000)
                .HasComment("Biographie ou description de l'utilisateur");

            builder.Property(u => u.AvatarUrl)
                .HasMaxLength(500)
                .HasComment("URL de l'avatar de l'utilisateur");

            // Configuration des tokens avec longueurs appropriées
            builder.Property(u => u.EmailConfirmationToken)
                .HasMaxLength(255)
                .HasComment("Token de confirmation d'email");

            builder.Property(u => u.PasswordResetToken)
                .HasMaxLength(255)
                .HasComment("Token de réinitialisation de mot de passe");

            builder.Property(u => u.TwoFactorSecretKey)
                .HasMaxLength(100)
                .HasComment("Clé secrète pour l'authentification 2FA");

            // Configuration des propriétés DateTime
            builder.Property(u => u.CreatedAt)
                .IsRequired()
                .HasComment("Date et heure de création du compte");

            builder.Property(u => u.UpdatedAt)
                .HasComment("Date et heure de dernière modification");

            builder.Property(u => u.LastLoginAt)
                .HasComment("Date et heure de dernière connexion réussie");

            builder.Property(u => u.EmailConfirmationTokenExpiry)
                .HasComment("Date d'expiration du token de confirmation d'email");

            builder.Property(u => u.PasswordResetTokenExpiry)
                .HasComment("Date d'expiration du token de réinitialisation");

            builder.Property(u => u.LockoutEnd)
                .HasComment("Date de fin de verrouillage du compte");

            // Configuration des propriétés booléennes avec valeurs par défaut
            builder.Property(u => u.EmailConfirmed)
                .IsRequired()
                .HasDefaultValue(false)
                .HasComment("Indique si l'email a été confirmé");

            builder.Property(u => u.TwoFactorEnabled)
                .IsRequired()
                .HasDefaultValue(false)
                .HasComment("Indique si l'authentification 2FA est activée");

            builder.Property(u => u.IsActive)
                .IsRequired()
                .HasDefaultValue(true)
                .HasComment("Indique si le compte utilisateur est actif");

            builder.Property(u => u.IsDeleted)
                .IsRequired()
                .HasDefaultValue(false)
                .HasComment("Soft delete - indique si l'utilisateur est supprimé");

            // Configuration des propriétés numériques
            builder.Property(u => u.FailedLoginAttempts)
                .IsRequired()
                .HasDefaultValue(0)
                .HasComment("Nombre de tentatives de connexion échouées consécutives");

            // Configuration des contraintes d'unicité
            builder.HasIndex(u => u.Email)
                .IsUnique()
                .HasDatabaseName("IX_Users_Email_Unique")
                .HasFilter("[IsDeleted] = 0"); // Unicité seulement pour les non-supprimés

            builder.HasIndex(u => u.UserName)
                .IsUnique()
                .HasDatabaseName("IX_Users_UserName_Unique")
                .HasFilter("[IsDeleted] = 0"); // Unicité seulement pour les non-supprimés

            // Configuration des relations
            builder.HasMany(u => u.UserRoles)
                .WithOne(ur => ur.User)
                .HasForeignKey(ur => ur.UserId)
                .OnDelete(DeleteBehavior.Cascade)
                .HasConstraintName("FK_UserRoles_Users");

            builder.HasMany(u => u.RefreshTokens)
                .WithOne(rt => rt.User)
                .HasForeignKey(rt => rt.UserId)
                .OnDelete(DeleteBehavior.Cascade)
                .HasConstraintName("FK_RefreshTokens_Users");

            builder.HasMany(u => u.LoginHistories)
                .WithOne(lh => lh.User)
                .HasForeignKey(lh => lh.UserId)
                .OnDelete(DeleteBehavior.Cascade)
                .HasConstraintName("FK_LoginHistories_Users");

            // Index pour optimiser les requêtes fréquentes
            builder.HasIndex(u => new { u.Email, u.IsDeleted })
                .HasDatabaseName("IX_Users_Email_IsDeleted");

            builder.HasIndex(u => u.EmailConfirmationToken)
                .HasDatabaseName("IX_Users_EmailConfirmationToken")
                .HasFilter("[EmailConfirmationToken] IS NOT NULL");

            builder.HasIndex(u => u.PasswordResetToken)
                .HasDatabaseName("IX_Users_PasswordResetToken")
                .HasFilter("[PasswordResetToken] IS NOT NULL");

            builder.HasIndex(u => u.CreatedAt)
                .HasDatabaseName("IX_Users_CreatedAt");

            builder.HasIndex(u => u.LastLoginAt)
                .HasDatabaseName("IX_Users_LastLoginAt")
                .HasFilter("[LastLoginAt] IS NOT NULL");
        }
    }
}