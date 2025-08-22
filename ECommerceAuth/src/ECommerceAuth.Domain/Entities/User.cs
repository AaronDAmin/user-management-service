using System;
using System.Collections.Generic;

namespace ECommerceAuth.Domain.Entities
{
    /// <summary>
    /// Entité représentant un utilisateur de la plateforme e-commerce.
    /// </summary>
    /// <remarks>
    /// Cette entité contient toutes les informations nécessaires pour :
    /// - L'authentification (email, mot de passe hashé)
    /// - La gestion du profil (nom, téléphone, bio, avatar)
    /// - La sécurité (tentatives de connexion, 2FA, confirmation email)
    /// - L'audit (historique des connexions)
    /// 
    /// Bonnes pratiques implémentées :
    /// - Mot de passe jamais stocké en clair (PasswordHash)
    /// - Email unique comme identifiant de connexion
    /// - Limitation des tentatives de connexion (sécurité anti-brute-force)
    /// - Support 2FA pour sécurité renforcée
    /// - Confirmation d'email obligatoire
    /// </remarks>
    public class User : BaseEntity
    {
        /// <summary>
        /// Nom d'utilisateur unique. Utilisé pour l'affichage public.
        /// </summary>
        public string UserName { get; set; } = string.Empty;

        /// <summary>
        /// Adresse email unique. Utilisée comme identifiant de connexion.
        /// </summary>
        public string Email { get; set; } = string.Empty;

        /// <summary>
        /// Hash du mot de passe. Le mot de passe en clair n'est jamais stocké.
        /// Utilisation d'Argon2 ou BCrypt pour le hashage sécurisé.
        /// </summary>
        public string PasswordHash { get; set; } = string.Empty;

        /// <summary>
        /// Prénom de l'utilisateur.
        /// </summary>
        public string? FirstName { get; set; }

        /// <summary>
        /// Nom de famille de l'utilisateur.
        /// </summary>
        public string? LastName { get; set; }

        /// <summary>
        /// Numéro de téléphone (optionnel).
        /// </summary>
        public string? PhoneNumber { get; set; }

        /// <summary>
        /// Biographie ou description de l'utilisateur (utile pour les vendeurs).
        /// </summary>
        public string? Bio { get; set; }

        /// <summary>
        /// URL de l'avatar de l'utilisateur.
        /// </summary>
        public string? AvatarUrl { get; set; }

        /// <summary>
        /// Indique si l'email a été confirmé.
        /// Requis pour la sécurité et éviter les comptes fantômes.
        /// </summary>
        public bool EmailConfirmed { get; set; }

        /// <summary>
        /// Token de confirmation d'email.
        /// Généré lors de l'inscription et utilisé pour confirmer l'email.
        /// </summary>
        public string? EmailConfirmationToken { get; set; }

        /// <summary>
        /// Date d'expiration du token de confirmation d'email.
        /// </summary>
        public DateTime? EmailConfirmationTokenExpiry { get; set; }

        /// <summary>
        /// Token de réinitialisation de mot de passe.
        /// </summary>
        public string? PasswordResetToken { get; set; }

        /// <summary>
        /// Date d'expiration du token de réinitialisation.
        /// </summary>
        public DateTime? PasswordResetTokenExpiry { get; set; }

        /// <summary>
        /// Indique si l'authentification à deux facteurs (2FA) est activée.
        /// </summary>
        public bool TwoFactorEnabled { get; set; }

        /// <summary>
        /// Clé secrète pour l'authentification à deux facteurs (Google Authenticator).
        /// </summary>
        public string? TwoFactorSecretKey { get; set; }

        /// <summary>
        /// Nombre de tentatives de connexion échouées consécutives.
        /// Utilisé pour la protection anti-brute-force.
        /// </summary>
        public int FailedLoginAttempts { get; set; }

        /// <summary>
        /// Date jusqu'à laquelle le compte est verrouillé après trop de tentatives échouées.
        /// </summary>
        public DateTime? LockoutEnd { get; set; }

        /// <summary>
        /// Indique si le compte utilisateur est actif.
        /// Un admin peut désactiver un compte sans le supprimer.
        /// </summary>
        public bool IsActive { get; set; }

        /// <summary>
        /// Date de la dernière connexion réussie.
        /// </summary>
        public DateTime? LastLoginAt { get; set; }

        /// <summary>
        /// Collection des rôles de l'utilisateur.
        /// Relation many-to-many avec l'entité Role.
        /// </summary>
        public virtual ICollection<UserRole> UserRoles { get; set; } = new List<UserRole>();

        /// <summary>
        /// Collection des tokens de rafraîchissement de l'utilisateur.
        /// </summary>
        public virtual ICollection<RefreshToken> RefreshTokens { get; set; } = new List<RefreshToken>();

        /// <summary>
        /// Historique des connexions de l'utilisateur.
        /// </summary>
        public virtual ICollection<LoginHistory> LoginHistories { get; set; } = new List<LoginHistory>();

        /// <summary>
        /// Constructeur par défaut.
        /// </summary>
        public User() : base()
        {
            IsActive = true;
            EmailConfirmed = false;
            TwoFactorEnabled = false;
            FailedLoginAttempts = 0;
        }

        /// <summary>
        /// Vérifie si le compte est actuellement verrouillé.
        /// </summary>
        public bool IsLockedOut => LockoutEnd.HasValue && LockoutEnd > DateTime.UtcNow;

        /// <summary>
        /// Obtient le nom complet de l'utilisateur.
        /// </summary>
        public string FullName => $"{FirstName} {LastName}".Trim();
    }
}